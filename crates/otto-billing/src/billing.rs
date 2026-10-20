//! Card on file, Stripe subscriptions, webhooks and sync
//! (savvagent/otto-platform#61, epic #55).
//!
//! An org's owner puts a card on file through a Stripe Checkout session in
//! `setup` mode ([`start_setup`]); when Stripe reports it complete
//! ([`handle_event`], `checkout.session.completed`) the card becomes the Stripe
//! customer's default payment method and the org gets a Stripe subscription
//! with one metered item per priced meter, anchored to 00:00 UTC on the first
//! of next month with proration off, so usage is invoiced monthly in arrears.
//! [`sync`] makes Stripe match the price book: a billing meter per platform
//! meter, an immutable Stripe Price per price-book version, and every live
//! subscription's items on the version in effect this month.
//!
//! # Where state lives
//!
//! - `subscriptions` (tenant, one row per org): the Stripe customer and
//!   subscription ids, the subscription's Stripe `status`, and our own
//!   [`PaymentMethodStatus`].
//! - `stripe_subscription_items` (tenant): which meter each item bills and at
//!   which price-book version.
//! - `stripe_customers` (global, no `otto_app` access): customer to org, so a
//!   webhook that names only a customer can be pinned to its org.
//! - `stripe_events` (global, no `otto_app` access): the webhook idempotency
//!   ledger.
//! - `stripe_meters`, `stripe_prices` (global, read-only to `otto_app`): the
//!   Stripe ids of meters and price-book versions.
//!
//! Global tables are written through [`Db::begin_unpinned`], as the connecting
//! role; tenant tables through a transaction pinned to the org.
//!
//! # Exactly once, with an API in the middle
//!
//! A Stripe call cannot join a database transaction, so every change is made
//! safe to repeat instead:
//!
//! - Every POST carries an idempotency key derived from what it is for (the
//!   org, the setup intent, the price-book version, the item), never a random
//!   one when the call can be retried, so a retry after a lost response gets
//!   the first answer back.
//! - The per-org work runs in a transaction pinned to the org that holds the
//!   org's `subscriptions` row `FOR UPDATE` across its Stripe calls. Two
//!   requests for one org (an owner double-clicking, a webhook racing `stripe
//!   sync`) run one after the other, and the second sees what the first did.
//! - Webhook handlers only move a status forward in event time: each status
//!   remembers the `created` of the event that set it, and an older event is
//!   ignored. A redelivered or out-of-order event therefore changes nothing,
//!   and is audited at most once (an event is audited only when it changes
//!   something).
//! - The `stripe_events` ledger is written after an event's effects commit,
//!   so a failure is retried by Stripe and a success is never handled twice.
//!
//! # Not here
//!
//! Shipping metered usage to Stripe meter events is #64; it needs only
//! [`live_subscription`]. Cancelling a deleted org's subscription is not done
//! anywhere yet.

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveTime, TimeZone, Utc};
use otto_tenant::audit::Entry;
use otto_tenant::ids::OrgId;
use otto_tenant::{Db, Tx};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::pricebook::{self, Month, Tiers};
use crate::stripe::{
    meter_event_name, Client, CreateCustomer, CreateMeter, CreateMeteredPrice,
    CreateSetupCheckoutSession, CreateSubscription, EventNameError, IdempotencyKey, PriceProduct,
    PriceTier, SetupPaymentMethods, StripeError, TierUpTo, WebhookEvent, WebhookSecret,
};

/// The one currency billed in. Multi-currency is a non-goal.
pub const CURRENCY: &str = "usd";

/// Stripe's limit on items per subscription.
pub const MAX_SUBSCRIPTION_ITEMS: usize = 20;

/// [`sync`] warns once a subscription holds this many items.
pub const ITEMS_WARN_AT: usize = 16;

/// The most items a subscription is created with. Stripe embeds at most ten
/// items in a subscription object, and an item whose id is not returned could
/// never be moved, so any more are added one by one, each returning its id.
const CREATE_WITH_AT_MOST: usize = 10;

/// The Stripe subscription statuses that are live: the subscription exists,
/// accrues usage, and is invoiced (`unpaid` invoices are created but not
/// collected). Anything else (`canceled`, `incomplete`, `incomplete_expired`,
/// `paused`) is not.
pub const LIVE_STATUSES: [&str; 4] = ["active", "trialing", "past_due", "unpaid"];

/// Audit actions. Dotted and stable: a console filter or a SIEM rule keys on
/// them.
pub mod actions {
    /// An owner started putting a card on file (a Checkout session was made).
    pub const SETUP_STARTED: &str = "billing.setup.started";
    /// Stripe confirmed the card; it is now the default payment method.
    pub const CARD_ADDED: &str = "billing.card.added";
    /// The card on file was removed from the Stripe customer.
    pub const CARD_DETACHED: &str = "billing.card.detached";
    /// Stripe could not collect an invoice with the card on file.
    pub const PAYMENT_FAILED: &str = "billing.payment.failed";
    /// A Stripe subscription was created for the org.
    pub const SUBSCRIPTION_CREATED: &str = "billing.subscription.created";
    /// Stripe reported a new subscription status (including `canceled`).
    pub const SUBSCRIPTION_STATUS_CHANGED: &str = "billing.subscription.status_changed";
    /// `stripe sync` added items to, or re-priced items of, the subscription.
    pub const SUBSCRIPTION_ITEMS_SYNCED: &str = "billing.subscription.items_synced";
}

/// The label audit entries written on Stripe's behalf carry as their actor.
const STRIPE_ACTOR: &str = "stripe";
const SYNC_ACTOR: &str = "stripe sync";

/// Billing's Stripe configuration: an API client and the webhook signing
/// secret. Present only when both `STRIPE_SECRET_KEY` and
/// `STRIPE_WEBHOOK_SECRET` are set. Neither secret is shown by `Debug`.
#[derive(Debug, Clone)]
pub struct Stripe {
    pub client: Client,
    pub webhook_secret: WebhookSecret,
}

/// A billing failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Stripe(#[from] StripeError),
    #[error(transparent)]
    Tenant(#[from] otto_tenant::Error),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    PriceBook(#[from] pricebook::Error),
    /// A meter key that has no Stripe event name. Shorten the meter (or its
    /// service slug) and declare it again.
    #[error("meter {meter} cannot be synced to Stripe: {source}")]
    EventName {
        meter: String,
        source: EventNameError,
    },
    /// Stripe answered with something billing cannot use.
    #[error("unexpected Stripe response: {0}")]
    Unexpected(String),
}

/// A billing result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

fn idem(key: String) -> Result<IdempotencyKey> {
    Ok(IdempotencyKey::new(key)?)
}

// ------------------------------------------------------------------ status

/// Whether the org has a usable card on file. Stored as
/// `subscriptions.payment_method_status`, a CHECKed vocabulary (0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethodStatus {
    /// No card has ever been put on file.
    None,
    /// A card is on file and is the Stripe customer's default.
    Active,
    /// Stripe could not collect an invoice with the card on file.
    Failed,
    /// The card was removed from the Stripe customer.
    Detached,
}

impl PaymentMethodStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Detached => "detached",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "active" => Ok(Self::Active),
            "failed" => Ok(Self::Failed),
            "detached" => Ok(Self::Detached),
            // Unreachable while the CHECK holds.
            other => Err(Error::Unexpected(format!(
                "stored payment_method_status {other:?}"
            ))),
        }
    }
}

/// Whether a Stripe subscription status is one of [`LIVE_STATUSES`].
pub fn is_live_status(status: &str) -> bool {
    LIVE_STATUSES.contains(&status)
}

/// An org's Stripe subscription, as last reported by Stripe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionState {
    pub stripe_subscription_id: String,
    pub status: String,
}

impl SubscriptionState {
    pub fn is_live(&self) -> bool {
        is_live_status(&self.status)
    }
}

/// Where an org's billing stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingStatus {
    pub stripe_customer_id: Option<String>,
    pub payment_method: PaymentMethodStatus,
    pub subscription: Option<SubscriptionState>,
}

/// What metered-usage shipping (#64) needs about an org: its Stripe customer
/// and its live subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSubscription {
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubRow {
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    status: String,
    payment_method_status: String,
    stripe_payment_method_id: Option<String>,
    payment_method_event_at: Option<DateTime<Utc>>,
    subscription_event_at: Option<DateTime<Utc>>,
}

const SUB_COLS: &str = "stripe_customer_id, stripe_subscription_id, status, \
                        payment_method_status, stripe_payment_method_id, \
                        payment_method_event_at, subscription_event_at";

impl SubRow {
    fn card(&self) -> Result<PaymentMethodStatus> {
        PaymentMethodStatus::parse(&self.payment_method_status)
    }

    fn subscription(&self) -> Option<SubscriptionState> {
        self.stripe_subscription_id
            .as_ref()
            .map(|id| SubscriptionState {
                stripe_subscription_id: id.clone(),
                status: self.status.clone(),
            })
    }

    fn live_subscription(&self) -> Option<SubscriptionState> {
        self.subscription().filter(SubscriptionState::is_live)
    }
}

async fn read_row(tx: &mut Tx<'_>) -> Result<Option<SubRow>> {
    let org = tx.org();
    Ok(sqlx::query_as(&format!(
        "SELECT {SUB_COLS} FROM subscriptions WHERE org_id = $1"
    ))
    .bind(org)
    .fetch_optional(tx.conn())
    .await?)
}

/// The org's row, created if absent, locked until `tx` ends.
async fn lock_row(tx: &mut Tx<'_>) -> Result<SubRow> {
    let org = tx.org();
    sqlx::query("INSERT INTO subscriptions (org_id) VALUES ($1) ON CONFLICT (org_id) DO NOTHING")
        .bind(org)
        .execute(tx.conn())
        .await?;
    Ok(sqlx::query_as(&format!(
        "SELECT {SUB_COLS} FROM subscriptions WHERE org_id = $1 FOR UPDATE"
    ))
    .bind(org)
    .fetch_one(tx.conn())
    .await?)
}

/// The org's billing state. An org that never started setup has no customer,
/// no card and no subscription.
pub async fn status(tx: &mut Tx<'_>) -> Result<BillingStatus> {
    Ok(match read_row(tx).await? {
        Some(row) => BillingStatus {
            stripe_customer_id: row.stripe_customer_id.clone(),
            payment_method: row.card()?,
            subscription: row.subscription(),
        },
        None => BillingStatus {
            stripe_customer_id: None,
            payment_method: PaymentMethodStatus::None,
            subscription: None,
        },
    })
}

/// The org's Stripe customer and subscription, when the subscription is live
/// ([`LIVE_STATUSES`]). `None` for an org with no subscription or a dead one:
/// its usage is not billed through Stripe.
pub async fn live_subscription(tx: &mut Tx<'_>) -> Result<Option<LiveSubscription>> {
    let Some(row) = read_row(tx).await? else {
        return Ok(None);
    };
    Ok(
        match (row.stripe_customer_id.clone(), row.live_subscription()) {
            (Some(customer), Some(sub)) => Some(LiveSubscription {
                stripe_customer_id: customer,
                stripe_subscription_id: sub.stripe_subscription_id,
                status: sub.status,
            }),
            _ => None,
        },
    )
}

// ------------------------------------------------------------------- setup

/// What [`start_setup`] needs to know about the org and its owner.
#[derive(Debug, Clone)]
pub struct SetupParams<'a> {
    pub org: OrgId,
    /// The Stripe customer's name.
    pub org_name: &'a str,
    /// The requesting owner's email, for the Stripe customer (receipts and
    /// invoices go there). `None` for an account with no address yet.
    pub owner_email: Option<&'a str>,
    /// Where Checkout returns the owner on success and on cancel.
    pub success_url: String,
    pub cancel_url: String,
}

/// Start putting a card on file: create the org's Stripe customer if it has
/// none, then a Checkout session in setup mode for it, and return the
/// session's URL to send the owner to.
///
/// `audit` is the `billing.setup.started` entry with its actor and request
/// details; it is written, with the session id, in the transaction that
/// records the customer.
pub async fn start_setup(
    db: &Db,
    client: &Client,
    params: SetupParams<'_>,
    audit: Entry,
) -> Result<String> {
    let org = params.org;
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;

    let customer = match row.stripe_customer_id {
        Some(customer) => customer,
        None => {
            // Keyed by org: a retry after a lost response, or after this
            // transaction rolled back, gets the same customer back.
            let created = client
                .create_customer(
                    &CreateCustomer {
                        email: params.owner_email.map(str::to_owned),
                        name: Some(params.org_name.to_owned()),
                        metadata: [("org_id".to_owned(), org.to_string())].into(),
                    },
                    &idem(format!("otto-customer-{org}"))?,
                )
                .await?;
            record_customer(db, &created.id, org).await?;
            sqlx::query(
                "UPDATE subscriptions SET stripe_customer_id = $2, updated_at = now() \
                 WHERE org_id = $1",
            )
            .bind(org)
            .bind(&created.id)
            .execute(tx.conn())
            .await?;
            created.id
        }
    };

    // A fresh session per request: nothing retries this call, and a session
    // replayed from an earlier click may already be completed or expired.
    let session = client
        .create_setup_checkout_session(
            &CreateSetupCheckoutSession {
                customer: customer.clone(),
                payment_methods: SetupPaymentMethods::Currency(CURRENCY.to_owned()),
                success_url: params.success_url,
                cancel_url: params.cancel_url,
                org_id: org.to_string(),
            },
            &IdempotencyKey::random(),
        )
        .await?;
    let url = session
        .url
        .ok_or_else(|| Error::Unexpected("the Checkout session has no url".into()))?;

    tx.audit(
        audit
            .target("org", org.to_string())
            .detail(json!({ "checkoutSessionId": session.id })),
    )
    .await?;
    tx.commit().await?;
    Ok(url)
}

/// Record which org a Stripe customer belongs to. Unpinned: `otto_app` cannot
/// write the map. An org has one customer; a newer one replaces the record.
async fn record_customer(db: &Db, customer: &str, org: OrgId) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "INSERT INTO stripe_customers (stripe_customer_id, org_id) VALUES ($1, $2) \
         ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id",
    )
    .bind(customer)
    .bind(org)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The org a Stripe customer belongs to, if it is one of ours and the org
/// still exists.
async fn org_of_customer(db: &Db, customer: &str) -> Result<Option<OrgId>> {
    let mut tx = db.begin_unpinned().await?;
    let org: Option<Uuid> =
        sqlx::query_scalar("SELECT org_id FROM stripe_customers WHERE stripe_customer_id = $1")
            .bind(customer)
            .fetch_optional(tx.conn())
            .await?;
    tx.commit().await?;
    Ok(org.map(OrgId::from))
}

// ------------------------------------------------------------ subscriptions

/// A meter priced this month, with the Stripe Price of the version in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncedPrice {
    meter: String,
    version: Uuid,
    stripe_price_id: String,
}

/// Every meter with a price in effect during `month` whose in-effect version
/// has a Stripe Price, by meter key. A meter whose in-effect version has not
/// been synced yet is left out rather than billed at an older version.
async fn synced_prices(conn: &mut PgConnection, month: Month) -> Result<Vec<SyncedPrice>> {
    let rows: Vec<(String, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT ON (v.meter) v.meter, v.id, p.stripe_price_id \
         FROM price_versions v LEFT JOIN stripe_prices p ON p.price_version_id = v.id \
         WHERE v.effective_month <= $1 \
         ORDER BY v.meter, v.effective_month DESC",
    )
    .bind(month.first_day())
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(meter, version, price)| {
            Some(SyncedPrice {
                meter,
                version,
                stripe_price_id: price?,
            })
        })
        .collect())
}

/// 00:00 UTC on the first day of the month after `month`.
fn anchor_after(month: Month) -> Result<DateTime<Utc>> {
    let next = month
        .offset(1)
        .ok_or_else(|| Error::Unexpected(format!("no month after {month}")))?;
    Ok(Utc.from_utc_datetime(&next.first_day().and_time(NaiveTime::MIN)))
}

fn items_warning(org: OrgId, sub: &str, items: usize) -> String {
    format!(
        "org {org}: subscription {sub} has {items} of Stripe's {MAX_SUBSCRIPTION_ITEMS} items \
         per subscription; a meter priced past that cannot be billed"
    )
}

async fn record_item(tx: &mut Tx<'_>, sub: &str, item: &str, price: &SyncedPrice) -> Result<()> {
    let org = tx.org();
    sqlx::query(
        "INSERT INTO stripe_subscription_items \
           (org_id, meter, stripe_subscription_id, stripe_item_id, price_version_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (org_id, meter) DO UPDATE SET \
           stripe_subscription_id = EXCLUDED.stripe_subscription_id, \
           stripe_item_id = EXCLUDED.stripe_item_id, \
           price_version_id = EXCLUDED.price_version_id, \
           updated_at = now()",
    )
    .bind(org)
    .bind(&price.meter)
    .bind(sub)
    .bind(item)
    .bind(price.version)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Create the org's subscription if it should have one and does not: a card
/// is on file, there is no live subscription, and at least one meter has a
/// synced price this month. Runs in `tx`, which must hold the org's row
/// locked ([`lock_row`]). Returns the new subscription's id, and the warnings
/// to surface (too many priced meters).
///
/// One item per priced meter, `billing_cycle_anchor` at 00:00 UTC on the first
/// of next month, `proration_behavior=none` (the client always sends it).
async fn ensure_subscription(
    tx: &mut Tx<'_>,
    client: &Client,
    actor: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    let org = tx.org();
    let row = lock_row(tx).await?;
    if row.card()? != PaymentMethodStatus::Active || row.live_subscription().is_some() {
        return Ok(None);
    }
    let (Some(customer), Some(pm)) = (
        row.stripe_customer_id.clone(),
        row.stripe_payment_method_id.clone(),
    ) else {
        return Ok(None);
    };
    let month = pricebook::current_month(tx.conn()).await?;
    let mut prices = synced_prices(tx.conn(), month).await?;
    if prices.is_empty() {
        // Nothing is priced in Stripe yet; `stripe sync` creates it later.
        return Ok(None);
    }
    if prices.len() > MAX_SUBSCRIPTION_ITEMS {
        warnings.push(format!(
            "org {org}: {} meters are priced but a Stripe subscription holds at most \
             {MAX_SUBSCRIPTION_ITEMS} items; {} are not billed",
            prices.len(),
            prices.len() - MAX_SUBSCRIPTION_ITEMS
        ));
        prices.truncate(MAX_SUBSCRIPTION_ITEMS);
    }
    let (first, rest) = prices.split_at(prices.len().min(CREATE_WITH_AT_MOST));

    // Keyed by the card and by the subscription it replaces, so a retry gets
    // the same subscription and a later re-subscribe gets a new one.
    let previous = row.stripe_subscription_id.as_deref().unwrap_or("none");
    let anchor = anchor_after(month)?;
    let sub = client
        .create_subscription(
            &CreateSubscription {
                customer,
                prices: first.iter().map(|p| p.stripe_price_id.clone()).collect(),
                billing_cycle_anchor: Some(anchor),
                metadata: [("org_id".to_owned(), org.to_string())].into(),
            },
            &idem(format!("otto-subscription-{org}-{pm}-{previous}"))?,
        )
        .await?;

    sqlx::query(
        "UPDATE subscriptions SET stripe_subscription_id = $2, status = $3, \
           subscription_event_at = NULL, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(&sub.id)
    .bind(&sub.status)
    .execute(tx.conn())
    .await?;
    sqlx::query("DELETE FROM stripe_subscription_items WHERE org_id = $1")
        .bind(org)
        .execute(tx.conn())
        .await?;
    for price in first {
        let item = sub
            .items
            .data
            .iter()
            .find(|i| i.price.id == price.stripe_price_id)
            .ok_or_else(|| {
                Error::Unexpected(format!(
                    "subscription {} came back without an item for {}",
                    sub.id, price.stripe_price_id
                ))
            })?;
        record_item(tx, &sub.id, &item.id, price).await?;
    }
    // The subscription exists in Stripe now; record what was added even if a
    // later add fails, and report that failure after.
    let mut failed = None;
    let mut items = first.len();
    for price in rest {
        match client
            .add_subscription_item(
                &sub.id,
                &price.stripe_price_id,
                &idem(format!("otto-item-{}-{}", sub.id, price.stripe_price_id))?,
            )
            .await
        {
            Ok(item) => {
                record_item(tx, &sub.id, &item.id, price).await?;
                items += 1;
            }
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    tx.audit(
        Entry::new(actions::SUBSCRIPTION_CREATED)
            .actor_label(actor)
            .target("org", org.to_string())
            .detail(json!({
                "stripeSubscriptionId": sub.id,
                "status": sub.status,
                "billingCycleAnchor": anchor,
                "meters": prices.iter().map(|p| p.meter.as_str()).collect::<Vec<_>>(),
            })),
    )
    .await?;
    if let Some(e) = failed {
        warnings.push(format!(
            "org {org}: subscription {} was created but an item could not be added ({e}); \
             run `stripe sync` again",
            sub.id
        ));
    }
    if items >= ITEMS_WARN_AT {
        warnings.push(items_warning(org, &sub.id, items));
    }
    Ok(Some(sub.id))
}

// ----------------------------------------------------------------- webhooks

/// What [`handle_event`] did with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOutcome {
    /// Already in the ledger: acknowledged, nothing done.
    Duplicate,
    /// Handled; its effects (if any) are committed.
    Handled,
    /// Acknowledged with no action, and why (an unhandled type, an event for
    /// a customer that is not ours, a stale or superseded event).
    Ignored(String),
}

fn ignored(why: impl Into<String>) -> EventOutcome {
    EventOutcome::Ignored(why.into())
}

/// The event types [`handle_event`] acts on. Register the webhook endpoint for
/// exactly these.
pub const HANDLED_EVENT_TYPES: [&str; 5] = [
    "checkout.session.completed",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
    "payment_method.detached",
];

/// A string field of a Stripe object, or the `id` of an expanded one.
fn id_field<'a>(object: &'a Value, field: &str) -> Option<&'a str> {
    match object.get(field)? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id")?.as_str(),
        _ => None,
    }
    .filter(|s| !s.is_empty() && s.len() <= 255)
}

/// Whether an event created at `created` may set a status last set by an
/// event created at `last`. Equal times apply, so a replay is a no-op rather
/// than a refusal.
fn not_older(last: Option<DateTime<Utc>>, created: DateTime<Utc>) -> bool {
    last.is_none_or(|last| created >= last)
}

/// Handle one verified Stripe event, at most once by its id.
///
/// `payload` is the verified request body the event was parsed from; a
/// handler that needs a field [`WebhookEvent`] does not carry
/// (`data.previous_attributes`) reads it from there.
///
/// An `Err` means the event was not handled and is not in the ledger: answer
/// Stripe with a 5xx so it retries.
pub async fn handle_event(
    db: &Db,
    client: &Client,
    event: &WebhookEvent,
    payload: &[u8],
) -> Result<EventOutcome> {
    if already_handled(db, &event.id).await? {
        return Ok(EventOutcome::Duplicate);
    }
    let created = Utc
        .timestamp_opt(event.created, 0)
        .single()
        .ok_or_else(|| Error::Unexpected(format!("event created at {}", event.created)))?;
    let object = &event.data.object;
    let outcome = match event.event_type.as_str() {
        "checkout.session.completed" => checkout_completed(db, client, object, created).await?,
        "customer.subscription.updated" | "customer.subscription.deleted" => {
            subscription_changed(db, object, created).await?
        }
        "invoice.payment_failed" => payment_failed(db, object, created).await?,
        "payment_method.detached" => card_detached(db, object, payload, created).await?,
        _ => ignored("an event type billing does not handle"),
    };
    record_event(db, event, created).await?;
    Ok(outcome)
}

async fn already_handled(db: &Db, event_id: &str) -> Result<bool> {
    let mut tx = db.begin_unpinned().await?;
    let seen: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM stripe_events WHERE event_id = $1)")
            .bind(event_id)
            .fetch_one(tx.conn())
            .await?;
    tx.commit().await?;
    Ok(seen)
}

async fn record_event(db: &Db, event: &WebhookEvent, created: DateTime<Utc>) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "INSERT INTO stripe_events (event_id, event_type, stripe_created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `checkout.session.completed` in setup mode: make the collected card the
/// customer's default, mark it on file, and create the subscription.
async fn checkout_completed(
    db: &Db,
    client: &Client,
    session: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    if session.get("mode").and_then(Value::as_str) != Some("setup") {
        return Ok(ignored("not a setup-mode Checkout session"));
    }
    let Some(customer) = id_field(session, "customer") else {
        return Ok(ignored("the session names no customer"));
    };
    let Some(org) = org_of_customer(db, customer).await? else {
        return Ok(ignored("not one of our customers"));
    };
    let claimed = session
        .get("metadata")
        .and_then(|m| m.get("org_id"))
        .and_then(Value::as_str);
    if claimed.is_some_and(|claimed| claimed != org.to_string()) {
        return Ok(ignored(
            "the session's metadata names a different org from its customer",
        ));
    }
    let Some(setup_intent) = id_field(session, "setup_intent") else {
        return Ok(ignored("the session has no setup intent"));
    };

    let intent = client.retrieve_setup_intent(setup_intent).await?;
    if intent.status != "succeeded" {
        return Ok(ignored(format!(
            "the setup intent has status {:?}",
            intent.status
        )));
    }
    if intent.customer.as_deref() != Some(customer) {
        return Ok(ignored("the setup intent belongs to another customer"));
    }
    let Some(pm) = intent.payment_method else {
        return Ok(ignored("the setup intent has no payment method"));
    };
    client
        .set_default_payment_method(
            customer,
            &pm,
            &idem(format!("otto-default-pm-{}", intent.id))?,
        )
        .await?;

    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_customer_id.as_deref() != Some(customer) {
        return Ok(ignored("the org's row records another customer"));
    }
    let changed = row.card()? != PaymentMethodStatus::Active
        || row.stripe_payment_method_id.as_deref() != Some(pm.as_str());
    if changed && not_older(row.payment_method_event_at, created) {
        sqlx::query(
            "UPDATE subscriptions SET payment_method_status = 'active', \
               stripe_payment_method_id = $2, payment_method_event_at = $3, updated_at = now() \
             WHERE org_id = $1",
        )
        .bind(org)
        .bind(&pm)
        .bind(created)
        .execute(tx.conn())
        .await?;
        tx.audit(
            Entry::new(actions::CARD_ADDED)
                .actor_label(STRIPE_ACTOR)
                .target("org", org.to_string())
                .detail(json!({ "checkoutSessionId": id_field(session, "id") })),
        )
        .await?;
    }
    let mut warnings = Vec::new();
    ensure_subscription(&mut tx, client, STRIPE_ACTOR, &mut warnings).await?;
    tx.commit().await?;
    for w in warnings {
        tracing::warn!(%org, "{w}");
    }
    Ok(EventOutcome::Handled)
}

/// `customer.subscription.updated` and `.deleted`: record the status.
async fn subscription_changed(
    db: &Db,
    subscription: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    let (Some(id), Some(customer)) = (
        id_field(subscription, "id"),
        id_field(subscription, "customer"),
    ) else {
        return Ok(ignored("the subscription names no id or customer"));
    };
    let Some(status) = subscription
        .get("status")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 64)
    else {
        return Ok(ignored("the subscription has no status"));
    };
    let Some(org) = org_of_customer(db, customer).await? else {
        return Ok(ignored("not one of our customers"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_subscription_id.as_deref() != Some(id) {
        return Ok(ignored("not the org's current subscription"));
    }
    // Canceled is final in Stripe; a late `updated` cannot revive it.
    if row.status == "canceled" && status != "canceled" {
        return Ok(ignored("the subscription is already canceled"));
    }
    if !not_older(row.subscription_event_at, created) {
        return Ok(ignored("older than the status already recorded"));
    }
    sqlx::query(
        "UPDATE subscriptions SET status = $2, subscription_event_at = $3, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(status)
    .bind(created)
    .execute(tx.conn())
    .await?;
    if row.status != status {
        tx.audit(
            Entry::new(actions::SUBSCRIPTION_STATUS_CHANGED)
                .actor_label(STRIPE_ACTOR)
                .target("org", org.to_string())
                .detail(json!({ "stripeSubscriptionId": id, "from": row.status, "to": status })),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

/// `invoice.payment_failed`: the card on file could not pay.
async fn payment_failed(db: &Db, invoice: &Value, created: DateTime<Utc>) -> Result<EventOutcome> {
    let Some(customer) = id_field(invoice, "customer") else {
        return Ok(ignored("the invoice names no customer"));
    };
    let Some(org) = org_of_customer(db, customer).await? else {
        return Ok(ignored("not one of our customers"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    // Only a card that is on file can fail; a detached card stays detached.
    if row.card()? != PaymentMethodStatus::Active {
        return Ok(ignored("no active card on file"));
    }
    if !not_older(row.payment_method_event_at, created) {
        return Ok(ignored("older than the card's recorded status"));
    }
    sqlx::query(
        "UPDATE subscriptions SET payment_method_status = 'failed', \
           payment_method_event_at = $2, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(actions::PAYMENT_FAILED)
            .actor_label(STRIPE_ACTOR)
            .target("org", org.to_string())
            .detail(json!({ "invoiceId": id_field(invoice, "id") })),
    )
    .await?;
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

/// `payment_method.detached`: the card on file was removed. A detached
/// payment method no longer names its customer; the previous one is in
/// `data.previous_attributes.customer`.
async fn card_detached(
    db: &Db,
    payment_method: &Value,
    payload: &[u8],
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    let Some(pm) = id_field(payment_method, "id") else {
        return Ok(ignored("the payment method has no id"));
    };
    let previous = serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|v| v.get("data")?.get("previous_attributes").cloned());
    let customer = id_field(payment_method, "customer")
        .map(str::to_owned)
        .or_else(|| {
            previous
                .as_ref()
                .and_then(|p| id_field(p, "customer"))
                .map(str::to_owned)
        });
    let Some(customer) = customer else {
        return Ok(ignored("the payment method names no customer"));
    };
    let Some(org) = org_of_customer(db, &customer).await? else {
        return Ok(ignored("not one of our customers"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_payment_method_id.as_deref() != Some(pm) {
        return Ok(ignored("not the card on file"));
    }
    if row.card()? == PaymentMethodStatus::Detached {
        return Ok(ignored("already detached"));
    }
    if !not_older(row.payment_method_event_at, created) {
        return Ok(ignored("older than the card's recorded status"));
    }
    sqlx::query(
        "UPDATE subscriptions SET payment_method_status = 'detached', \
           payment_method_event_at = $2, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(actions::CARD_DETACHED)
            .actor_label(STRIPE_ACTOR)
            .target("org", org.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

// --------------------------------------------------------------------- sync

/// What one [`sync`] run did. Every list is in the order the work was done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// `(meter, stripe meter id)`.
    pub meters_created: Vec<(String, String)>,
    /// `(meter, effective month, stripe price id)`.
    pub prices_created: Vec<(String, Month, String)>,
    /// `(org, stripe subscription id)`.
    pub subscriptions_created: Vec<(OrgId, String)>,
    /// `(org, meter)`.
    pub items_added: Vec<(OrgId, String)>,
    /// `(org, meter, month of the version moved to)`.
    pub items_moved: Vec<(OrgId, String, Month)>,
    /// Worth an operator's attention; nothing failed.
    pub warnings: Vec<String>,
    /// What could not be done. The rest of the run went ahead; run again once
    /// fixed.
    pub errors: Vec<String>,
}

impl SyncReport {
    /// Whether the run changed nothing in Stripe.
    pub fn is_noop(&self) -> bool {
        self.meters_created.is_empty()
            && self.prices_created.is_empty()
            && self.subscriptions_created.is_empty()
            && self.items_added.is_empty()
            && self.items_moved.is_empty()
    }
}

/// Make Stripe match the price book. Idempotent: a second run with nothing
/// new does nothing.
///
/// 1. A Stripe billing meter for every declared meter that has none. A meter
///    key whose event name would exceed Stripe's limit is reported, with its
///    prices, and skipped.
/// 2. A Stripe Price for every price-book version that has none (current,
///    past and future versions alike), on one Stripe product per meter.
/// 3. For every org with a Stripe customer, pinned to that org: a subscription
///    if it has a card on file and no live subscription; otherwise, on its
///    live subscription, an item for each meter newly priced this month and
///    each item moved to the version in effect this month.
///
/// Per-meter, per-version and per-org failures are collected in
/// [`SyncReport::errors`] and the run carries on; `Err` is only for a failure
/// that stops everything (the database).
pub async fn sync(db: &Db, client: &Client) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    sync_meters(db, client, &mut report).await?;
    sync_prices(db, client, &mut report).await?;

    let mut tx = db.begin_unpinned().await?;
    let orgs: Vec<Uuid> =
        sqlx::query_scalar("SELECT org_id FROM stripe_customers ORDER BY created_at, org_id")
            .fetch_all(tx.conn())
            .await?;
    tx.commit().await?;
    for org in orgs.into_iter().map(OrgId::from) {
        if let Err(e) = sync_org(db, client, org, &mut report).await {
            report.errors.push(format!("org {org}: {e}"));
        }
    }
    Ok(report)
}

async fn sync_meters(db: &Db, client: &Client, report: &mut SyncReport) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    let missing: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.key, m.display_name FROM meters m \
         LEFT JOIN stripe_meters s ON s.meter = m.key \
         WHERE s.meter IS NULL ORDER BY m.key",
    )
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;

    for (key, display_name) in missing {
        let (service, meter) = key.split_once('/').unwrap_or((key.as_str(), ""));
        let event_name = match meter_event_name(service, meter) {
            Ok(name) => name,
            Err(source) => {
                report.errors.push(
                    Error::EventName {
                        meter: key.clone(),
                        source,
                    }
                    .to_string(),
                );
                continue;
            }
        };
        let created = match client
            .create_meter(
                &CreateMeter {
                    display_name,
                    event_name: event_name.clone(),
                },
                &idem(format!("otto-meter-{event_name}"))?,
            )
            .await
        {
            Ok(m) => m,
            Err(e) => {
                report.errors.push(format!("meter {key}: {e}"));
                continue;
            }
        };
        let mut tx = db.begin_unpinned().await?;
        sqlx::query(
            "INSERT INTO stripe_meters (meter, stripe_meter_id, event_name) VALUES ($1, $2, $3)",
        )
        .bind(&key)
        .bind(&created.id)
        .bind(&event_name)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        report.meters_created.push((key, created.id));
    }
    Ok(())
}

fn stripe_tiers(tiers: &Tiers) -> Result<Vec<PriceTier>> {
    tiers
        .as_slice()
        .iter()
        .map(|t| {
            let up_to = match t.up_to {
                None => TierUpTo::Inf,
                Some(n) => TierUpTo::Units(
                    u64::try_from(n).map_err(|_| Error::Unexpected(format!("tier bound {n}")))?,
                ),
            };
            Ok(PriceTier {
                up_to,
                unit_amount_ucents: t.unit_amount_ucents,
            })
        })
        .collect()
}

async fn sync_prices(db: &Db, client: &Client, report: &mut SyncReport) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    let versions = pricebook::list_versions(tx.conn()).await?;
    let priced: Vec<Uuid> = sqlx::query_scalar("SELECT price_version_id FROM stripe_prices")
        .fetch_all(tx.conn())
        .await?;
    let meters: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT s.meter, s.stripe_meter_id, s.stripe_product_id, m.display_name \
         FROM stripe_meters s JOIN meters m ON m.key = s.meter",
    )
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    let mut meters: BTreeMap<String, (String, Option<String>, String)> = meters
        .into_iter()
        .map(|(key, mtr, product, name)| (key, (mtr, product, name)))
        .collect();

    for version in versions.into_iter().filter(|v| !priced.contains(&v.id)) {
        let what = format!(
            "price of {} from {}",
            version.meter, version.effective_month
        );
        let Some((stripe_meter, product, display_name)) = meters.get(&version.meter).cloned()
        else {
            report
                .errors
                .push(format!("{what}: its meter has no Stripe meter"));
            continue;
        };
        let tiers = match version.tiers.as_ref() {
            Ok(tiers) => stripe_tiers(tiers)?,
            Err(reason) => {
                report.errors.push(format!("{what}: malformed: {reason}"));
                continue;
            }
        };
        let params = CreateMeteredPrice {
            currency: CURRENCY.to_owned(),
            product: match &product {
                Some(id) => PriceProduct::Id(id.clone()),
                None => PriceProduct::New { name: display_name },
            },
            meter: stripe_meter,
            tiers,
            lookup_key: None,
            nickname: Some(format!(
                "{} from {}",
                version.meter, version.effective_month
            )),
            metadata: [
                ("meter".to_owned(), version.meter.clone()),
                ("price_version_id".to_owned(), version.id.to_string()),
            ]
            .into(),
        };
        let price = match client
            .create_metered_price(&params, &idem(format!("otto-price-{}", version.id))?)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                report.errors.push(format!("{what}: {e}"));
                continue;
            }
        };
        let mut tx = db.begin_unpinned().await?;
        sqlx::query(
            "INSERT INTO stripe_prices (price_version_id, meter, stripe_price_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(version.id)
        .bind(&version.meter)
        .bind(&price.id)
        .execute(tx.conn())
        .await?;
        if product.is_none() {
            sqlx::query(
                "UPDATE stripe_meters SET stripe_product_id = $2 \
                 WHERE meter = $1 AND stripe_product_id IS NULL",
            )
            .bind(&version.meter)
            .bind(&price.product)
            .execute(tx.conn())
            .await?;
            if let Some(entry) = meters.get_mut(&version.meter) {
                entry.1 = Some(price.product.clone());
            }
        }
        tx.commit().await?;
        report
            .prices_created
            .push((version.meter, version.effective_month, price.id));
    }
    Ok(())
}

async fn sync_org(db: &Db, client: &Client, org: OrgId, report: &mut SyncReport) -> Result<()> {
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    let Some(sub) = row.live_subscription() else {
        if let Some(id) =
            ensure_subscription(&mut tx, client, SYNC_ACTOR, &mut report.warnings).await?
        {
            report.subscriptions_created.push((org, id));
        }
        tx.commit().await?;
        return Ok(());
    };
    let sub = sub.stripe_subscription_id;

    let month = pricebook::current_month(tx.conn()).await?;
    let desired = synced_prices(tx.conn(), month).await?;
    let current: Vec<(String, String, Uuid)> = sqlx::query_as(
        "SELECT meter, stripe_item_id, price_version_id FROM stripe_subscription_items \
         WHERE org_id = $1 AND stripe_subscription_id = $2",
    )
    .bind(org)
    .bind(&sub)
    .fetch_all(tx.conn())
    .await?;
    let current: BTreeMap<String, (String, Uuid)> = current
        .into_iter()
        .map(|(meter, item, version)| (meter, (item, version)))
        .collect();
    let mut count = current.len();
    let mut added = Vec::new();
    let mut moved = Vec::new();
    // Every Stripe call that succeeds is recorded before the next is made, and
    // the transaction commits whatever happened, so a failure part-way leaves
    // the database agreeing with Stripe.
    let mut failure = None;

    for price in &desired {
        let outcome = match current.get(&price.meter) {
            None if count >= MAX_SUBSCRIPTION_ITEMS => {
                report.errors.push(format!(
                    "org {org}: cannot add {} to subscription {sub}: Stripe allows at most \
                     {MAX_SUBSCRIPTION_ITEMS} items",
                    price.meter
                ));
                continue;
            }
            None => client
                .add_subscription_item(
                    &sub,
                    &price.stripe_price_id,
                    &idem(format!("otto-item-{sub}-{}", price.stripe_price_id))?,
                )
                .await
                .map(|item| (item.id, true)),
            Some((_, version)) if *version == price.version => continue,
            Some((item, _)) => client
                .change_subscription_item_price(
                    item,
                    &price.stripe_price_id,
                    &idem(format!("otto-move-{item}-{}", price.stripe_price_id))?,
                )
                .await
                .map(|item| (item.id, false)),
        };
        match outcome {
            Ok((item, is_new)) => {
                record_item(&mut tx, &sub, &item, price).await?;
                if is_new {
                    count += 1;
                    added.push(price.meter.clone());
                } else {
                    moved.push(price.meter.clone());
                }
            }
            Err(e) => {
                failure = Some(format!("{}: {e}", price.meter));
                break;
            }
        }
    }

    if !added.is_empty() || !moved.is_empty() {
        tx.audit(
            Entry::new(actions::SUBSCRIPTION_ITEMS_SYNCED)
                .actor_label(SYNC_ACTOR)
                .target("org", org.to_string())
                .detail(json!({
                    "stripeSubscriptionId": sub,
                    "added": added,
                    "moved": moved,
                    "month": month.to_string(),
                })),
        )
        .await?;
    }
    tx.commit().await?;

    if count >= ITEMS_WARN_AT {
        report.warnings.push(items_warning(org, &sub, count));
    }
    report
        .items_added
        .extend(added.into_iter().map(|m| (org, m)));
    report
        .items_moved
        .extend(moved.into_iter().map(|m| (org, m, month)));
    if let Some(f) = failure {
        report.errors.push(format!("org {org}: {f}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_anchor_is_midnight_utc_on_the_next_first() {
        let oct = Month::new(2026, 10).unwrap();
        assert_eq!(
            anchor_after(oct).unwrap(),
            Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap()
        );
        let dec = Month::new(2026, 12).unwrap();
        assert_eq!(
            anchor_after(dec).unwrap(),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn older_events_do_not_apply_and_replays_do() {
        let t = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
        assert!(not_older(None, t));
        assert!(not_older(Some(t), t));
        assert!(not_older(Some(t - chrono::Duration::seconds(1)), t));
        assert!(!not_older(Some(t + chrono::Duration::seconds(1)), t));
    }

    #[test]
    fn ids_are_read_plain_or_expanded_and_bounded() {
        let v = json!({
            "a": "cus_1", "b": {"id": "cus_2"}, "c": null, "d": "", "e": "x".repeat(256),
        });
        assert_eq!(id_field(&v, "a"), Some("cus_1"));
        assert_eq!(id_field(&v, "b"), Some("cus_2"));
        assert_eq!(id_field(&v, "c"), None);
        assert_eq!(id_field(&v, "d"), None);
        assert_eq!(id_field(&v, "e"), None);
        assert_eq!(id_field(&v, "missing"), None);
    }

    #[test]
    fn live_statuses() {
        for s in ["active", "trialing", "past_due", "unpaid"] {
            assert!(is_live_status(s), "{s}");
        }
        for s in ["canceled", "incomplete", "incomplete_expired", "paused", ""] {
            assert!(!is_live_status(s), "{s}");
        }
    }

    #[test]
    fn card_status_round_trips() {
        for s in [
            PaymentMethodStatus::None,
            PaymentMethodStatus::Active,
            PaymentMethodStatus::Failed,
            PaymentMethodStatus::Detached,
        ] {
            assert_eq!(PaymentMethodStatus::parse(s.as_str()).unwrap(), s);
            assert_eq!(serde_json::to_value(s).unwrap(), json!(s.as_str()));
        }
        assert!(PaymentMethodStatus::parse("maybe").is_err());
    }

    #[test]
    fn the_stripe_secrets_are_not_in_debug() {
        let stripe = Stripe {
            client: Client::with_base_url(
                crate::stripe::SecretKey::new("sk_test_supersecret").unwrap(),
                "http://127.0.0.1:1",
            )
            .unwrap(),
            webhook_secret: WebhookSecret::new("whsec_supersecret").unwrap(),
        };
        assert!(!format!("{stripe:?}").contains("supersecret"));
    }
}
