//! Card on file, Stripe subscriptions, webhooks and sync
//! (savvagent/otto-platform#61, epic #55).
//!
//! An org's owner puts a card on file through a Stripe Checkout session in
//! `setup` mode, cards only ([`start_setup`]); when Stripe reports it complete
//! ([`handle_event`], `checkout.session.completed`) the card becomes the Stripe
//! customer's default payment method and the org gets a Stripe subscription
//! with one metered item per priced meter, started at 00:00 UTC on the first
//! of this month and anchored to 00:00 UTC on the first of next month with
//! proration off, so usage is invoiced monthly in arrears (see "The first
//! month" below). [`sync`] makes Stripe match the price book: a billing meter
//! per platform meter, an immutable Stripe Price per price-book version, and
//! every live subscription on the right prices. It never removes an item.
//!
//! # One subscription per org, and only one carries meter prices
//!
//! An org has exactly one Stripe subscription, the one recorded in
//! `subscriptions`. Stripe meters count usage per **customer**, not per
//! subscription, so a second live subscription of the same customer holding
//! the same meters' prices would bill the same usage twice. Hence:
//!
//! - sync adopts a live subscription already in Stripe (the recorded one, or
//!   one tagged with the org) before it ever creates one, and reports more
//!   than one tagged live subscription as an error;
//! - it refuses to create a subscription for a customer that already has any
//!   other live subscription carrying a metered price;
//! - it only ever adds or moves items on the recorded subscription.
//!
//! **A future paid plan must reuse this subscription** (add its licensed
//! price as one more item), never start a second one alongside it.
//!
//! # The first month
//!
//! An org that puts a card on file mid-month has used the platform since the
//! month began, and that usage was counted (budgets, the console) but not
//! queued for Stripe, as it had no live subscription. Its first subscription
//! is therefore backdated (`backdate_start_date`) to 00:00 UTC on the first
//! of the current month, and as it is recorded live, in the same transaction,
//! [`crate::stripe_outbox::backfill_period`] queues the month's counted usage
//! that is not yet in the outbox. Stripe then rates the whole month through
//! one set of graduated tiers, with one free allowance, exactly as the
//! platform rates it.
//!
//! - **The previous month during its grace.** A subscription made between
//!   00:00 and 02:00 UTC on the first (while the previous month is still open
//!   for late events, [`crate::period`]) starts at the new month. The
//!   previous month's usage was accrued with no card on file and is not
//!   billed: it is neither backfilled nor covered by the subscription.
//! - **A re-subscription** (after Stripe canceled an earlier subscription)
//!   is backdated to the start of the month only if the earlier one's last
//!   status change was before the month began; otherwise to the start of the
//!   current hour (or not at all if the earlier one changed status within
//!   this hour), so no stretch of the month is covered by both. Usage between
//!   the cancellation and the new start is billed only as far as the backfill
//!   reaches it (the current hour, when the new subscription is backdated to
//!   it); a month split across two subscriptions gets each one's free
//!   allowance. When the earlier one changed status within this very hour,
//!   the new one starts mid-hour, unbackdated, and this hour's usage (stamped
//!   with the hour's start, before it) is not invoiced: logged at warn with
//!   the units the backfill queued, never repaired.
//! - **A subscription that goes live after it is recorded** (created
//!   `incomplete`, then paid) queued nothing while it was not live; the
//!   `customer.subscription.updated` webhook that records it live backfills
//!   the month in the same transaction. Sync's adoption only ever adopts a
//!   live subscription, and backfills as it records it.
//!
//! # Paying, and the payment grace
//!
//! Usage of a live subscription ([`LIVE_STATUSES`]) is queued for Stripe
//! whatever the state of its payments, so it is invoiced if they recover.
//! Whether more billable use is allowed is [`gate`]'s rule: a subscription
//! that is `unpaid`, or `past_due` (or whose card is `failed` or `detached`)
//! for [`gate::PAYMENT_GRACE`], answers `payment_required`.
//!
//! # Invoices wait for their usage
//!
//! A month's invoice is made at 00:00 UTC on the first of the next, but its
//! last usage reaches Stripe up to a couple of hours later. Each
//! subscription-cycle invoice is therefore held as a draft (the
//! `invoice.created` webhook) and finalized by sync once its usage has
//! shipped ([`INVOICE_SETTLE`]), or after [`MAX_INVOICE_HOLD`], with an
//! error log.
//!
//! # Prices switch at exactly 00:00 UTC on the first
//!
//! A price-book version takes effect at the start of a month and can only be
//! set for a future month. Sync does not wait for that month to move a
//! subscription's items: as soon as a future version exists (and has its
//! Stripe Price), sync puts the subscription under a Stripe **subscription
//! schedule** whose phases switch the items to the new prices at 00:00 UTC on
//! the first of each month a version takes effect, with
//! `proration_behavior=none` and `end_behavior=release`. The billing period
//! is anchored to the first, so each phase boundary is a period boundary:
//! Stripe invoices the closing month at the old prices and rates the new
//! month at the new ones, with no dependence on when sync next runs. Sync
//! runs on its own in the server (every 15 minutes and just after each month
//! starts), so a schedule exists well before its boundary unless the version
//! is set in the last minutes of a month. See [`sync`] for the residual
//! window.
//!
//! # Where state lives
//!
//! - `subscriptions` (tenant, one row per org): the Stripe customer,
//!   subscription and schedule ids, the subscription's Stripe `status`, our
//!   own [`PaymentMethodStatus`], whether billing was stopped, what sync last
//!   scheduled (`stripe_plan`), and a short per-org lease.
//! - `stripe_customers` (global, no `otto_app` access): customer to org, so a
//!   webhook that names only a customer can be pinned to its org.
//! - `stripe_events` (global, no `otto_app` access): the webhook idempotency
//!   ledger.
//! - `stripe_meters`, `stripe_prices` (global, read-only to `otto_app`): the
//!   Stripe ids of meters and price-book versions.
//! - `stripe_sync_lease` (global): who is running sync.
//! - `stripe_held_invoices` (tenant): invoices held as drafts until their
//!   usage has reached Stripe, and how each was released.
//! - `stripe_account_mode` (global, no `otto_app` access): whether the ids
//!   recorded here are live-mode or test-mode Stripe objects
//!   ([`check_key_mode`]).
//!
//! # Exactly once, with an API in the middle
//!
//! A Stripe call cannot join a database transaction, so:
//!
//! - **No transaction is open during a Stripe call.** Work on one org is
//!   serialized by a lease on its `subscriptions` row ([`OrgLease`]), claimed
//!   and released in short transactions of their own. Every read before a
//!   call and every write after one is its own short transaction, and none
//!   is ever opened while another is held, so a burst of requests needs one
//!   pool connection each at most and cannot deadlock the pool. The lease is
//!   renewed before every Stripe call, and every write after one opens with
//!   `UPDATE ... WHERE lease_token = <ours>`: a worker whose lease expired
//!   and was taken writes nothing ([`Error::LeaseLost`]).
//! - **Stripe ids are recorded the moment they exist**, each in its own short
//!   transaction right after the call that made it.
//! - **Creation looks before it leaps.** Before creating a customer, the org's
//!   customer is searched for by `metadata[org_id]`; before creating a
//!   subscription, the recorded subscription is retrieved and the customer's
//!   subscriptions are listed, and a live one (the recorded one, even if our
//!   copy of its status is stale, or one tagged with the org) is adopted. A crash between Stripe's answer and our
//!   write therefore never leads to a second customer or subscription.
//! - **Idempotency keys are derived from the request**: a hash of every
//!   parameter, plus the hour ([`idem`]). A retry with the same parameters
//!   replays Stripe's first answer; a retry with different ones gets a new
//!   key rather than Stripe's `idempotency_error`. The hour bounds how long a
//!   failure Stripe cached under a key keeps being replayed; the look-first
//!   rule above is what keeps a new key from duplicating anything. Creating a
//!   subscription is the exception: its key has no hour, so no retry ever
//!   makes a second one, at the cost of a cached failure blocking it for
//!   Stripe's 24 hours. More than one live subscription tagged with the org
//!   is reported as an error, never resolved by picking one.
//! - **Webhook handlers only move a status forward in event time**, and the
//!   `stripe_events` ledger is written after an event's effects commit.
//!
//! # Not here
//!
//! Shipping metered usage to Stripe meter events is #64; it needs only
//! [`live_subscription`]. Canceling a deleted org's subscription is
//! [`cancel`] (#73). A held draft invoice of a deleted org is not released by
//! sync, though: an operator finalizes or voids it in the dashboard
//! (docs/deploy/fly.md, "Deleting an org with a subscription").

pub mod cancel;
pub mod gate;
mod invoices;
#[cfg(any(test, feature = "test-support"))]
pub mod mock;
mod mode;
mod setup;
mod status;
mod sync;
mod webhook;

use std::fmt::Debug;
use std::time::Duration;

use chrono::{DateTime, NaiveTime, TimeZone, Utc};
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::pricebook::{self, Month};

use crate::stripe::{Client, EventNameError, IdempotencyKey, KeyMode, StripeError, WebhookSecret};

pub use invoices::{outcomes as invoice_outcomes, INVOICE_SETTLE, MAX_INVOICE_HOLD};
pub use mode::{check_key_mode, recorded_key_mode, RESET_MODE_SQL};
pub use setup::{start_setup, SetupParams};
pub use status::{
    is_live_status, live_subscription, status, BillingStatus, LiveSubscription,
    PaymentMethodStatus, SubscriptionState,
};
pub use sync::{backdate_start_for, sync, sync_until, SyncReport};
pub use webhook::{
    handle_event, sweep_events, EventOutcome, EVENT_RETENTION_DAYS, HANDLED_EVENT_TYPES,
    MIN_EVENT_RETENTION_DAYS,
};

/// The one currency billed in. Multi-currency is a non-goal.
pub const CURRENCY: &str = "usd";

/// Stripe's limit on items per subscription.
pub const MAX_SUBSCRIPTION_ITEMS: usize = 20;

/// [`sync`] warns once a subscription holds this many items.
pub const ITEMS_WARN_AT: usize = 16;

/// Stripe's limit on phases per subscription schedule.
pub const MAX_SCHEDULE_PHASES: usize = 10;

/// The Stripe subscription statuses that are live: the subscription exists,
/// accrues usage, and is invoiced (`unpaid` invoices are created but not
/// collected). Anything else (`canceled`, `incomplete`, `incomplete_expired`,
/// `paused`) is not. Metered usage of an org with a live subscription is
/// queued for Stripe, so it is invoiced if a failed payment recovers.
///
/// Live is not the same as allowed to run up more billable usage: `unpaid`,
/// and `past_due` past [`gate::PAYMENT_GRACE`], are live but answer
/// `payment_required` ([`gate`]).
pub const LIVE_STATUSES: [&str; 4] = ["active", "trialing", "past_due", "unpaid"];

/// How long an org lease lasts if its holder never releases it (a crash).
/// Longer than the slowest flow: five Stripe calls at the client's 30 s
/// timeout.
const LEASE_TTL_SECS: i64 = 300;

/// How long an owner's request or a webhook waits for another worker's lease
/// on the same org before giving up (`Error::Busy`).
pub const LEASE_WAIT: Duration = Duration::from_secs(15);

/// Audit actions. Dotted and stable: a console filter or a SIEM rule keys on
/// them.
pub mod actions {
    /// An owner started putting a card on file (a Checkout session was made).
    pub const SETUP_STARTED: &str = "billing.setup.started";
    /// Stripe confirmed the card; it is now the default payment method.
    pub const CARD_ADDED: &str = "billing.card.added";
    /// The card on file was removed from the Stripe customer.
    pub const CARD_DETACHED: &str = "billing.card.detached";
    /// Stripe could not collect an invoice of the subscription.
    pub const PAYMENT_FAILED: &str = "billing.payment.failed";
    /// An invoice of the subscription was paid after the card had failed.
    pub const PAYMENT_RECOVERED: &str = "billing.payment.recovered";
    /// A Stripe subscription was created for the org, or an existing one
    /// tagged with the org was adopted (`detail.adopted`).
    pub const SUBSCRIPTION_CREATED: &str = "billing.subscription.created";
    /// Stripe reported a new subscription status. `canceled` stops billing
    /// (`detail.billingStopped`) until the owner puts a card on file again.
    pub const SUBSCRIPTION_STATUS_CHANGED: &str = "billing.subscription.status_changed";
    /// Sync changed the subscription's prices: scheduled future switches,
    /// released a schedule, or corrected this month's items.
    pub const SUBSCRIPTION_ITEMS_SYNCED: &str = "billing.subscription.items_synced";
    /// A subscription-cycle invoice was held as a draft until its usage has
    /// reached Stripe.
    pub const INVOICE_HELD: &str = "billing.invoice.held";
    /// A held invoice was let go (`detail.outcome`: `finalized`,
    /// `finalized_late` or `not_draft`).
    pub const INVOICE_RELEASED: &str = "billing.invoice.released";
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
    /// Another worker holds the lease (an org's, or sync's). Try again.
    #[error("busy: {0}")]
    Busy(String),
    /// This worker's lease on the org expired and another worker took it,
    /// so nothing more was written. The other worker carries on.
    #[error("lost the billing lease on org {0} to another worker; nothing more was written")]
    LeaseLost(OrgId),
    /// Stripe answered with something billing cannot use.
    #[error("unexpected Stripe response: {0}")]
    Unexpected(String),
    /// The Stripe key is in a different mode from the one this database's
    /// Stripe objects were made in ([`check_key_mode`]).
    #[error(
        "STRIPE_SECRET_KEY is a {key}-mode key, but this database's Stripe customers, \
         subscriptions, meters and prices were made in {recorded} mode and do not exist in \
         {key} mode. Use a {recorded}-mode key, or, to switch this database to {key} mode on \
         purpose, see \"Switching Stripe modes\" in docs/deploy/fly.md"
    )]
    ModeMismatch { recorded: KeyMode, key: KeyMode },
    /// A Stripe key whose prefix says neither live nor test.
    #[error(
        "STRIPE_SECRET_KEY is neither a live-mode nor a test-mode key (expected sk_live_, \
         rk_live_, sk_test_ or rk_test_)"
    )]
    UnknownKeyMode,
}

/// A billing result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An idempotency key for a request: `otto-<scope>-<hash>-<hour>`, the hash
/// over every parameter (`params`' `Debug`, which every parameter struct
/// derives and which spells out every field, metadata in key order).
///
/// Same parameters within the hour: the same key, so a retry after a lost
/// response replays Stripe's first answer. Different parameters: a different
/// key, never Stripe's `idempotency_error`. A new hour: a new key, so a
/// failure Stripe cached under the old one (Stripe replays even a `500` for
/// the key's 24 hours) is not replayed forever. Creation never relies on the
/// key alone to avoid duplicates; it looks for what exists first.
fn idem(scope: &str, params: &impl Debug) -> Result<IdempotencyKey> {
    idem_at(scope, params, Utc::now())
}

fn idem_at(scope: &str, params: &impl Debug, now: DateTime<Utc>) -> Result<IdempotencyKey> {
    Ok(IdempotencyKey::new(format!(
        "{}-{}",
        idem_stable(scope, params)?.as_str(),
        now.format("%Y%m%d%H")
    ))?)
}

/// As [`idem`] with no hour: the same parameters always give the same key,
/// so a retry at any time within Stripe's 24 hours replays the first answer.
/// For creating a subscription, where a second one would bill twice; the
/// price is that a failure Stripe cached is replayed for those 24 hours.
fn idem_stable(scope: &str, params: &impl Debug) -> Result<IdempotencyKey> {
    let digest = Sha256::digest(format!("{params:?}").as_bytes());
    let hash: String = digest[..12].iter().map(|b| format!("{b:02x}")).collect();
    Ok(IdempotencyKey::new(format!("otto-{scope}-{hash}"))?)
}

/// 00:00 UTC on the first day of `month`.
fn month_start(month: Month) -> DateTime<Utc> {
    Utc.from_utc_datetime(&month.first_day().and_time(NaiveTime::MIN))
}

/// 00:00 UTC on the first day of the month after `month`.
fn month_after(month: Month) -> Result<(Month, DateTime<Utc>)> {
    let next = month
        .offset(1)
        .ok_or_else(|| Error::Unexpected(format!("no month after {month}")))?;
    Ok((next, month_start(next)))
}

// ------------------------------------------------------------------- rows

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubRow {
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    status: String,
    payment_method_status: String,
    stripe_payment_method_id: Option<String>,
    payment_method_event_at: Option<DateTime<Utc>>,
    subscription_event_at: Option<DateTime<Utc>>,
    past_due_since: Option<DateTime<Utc>>,
    billing_stopped_at: Option<DateTime<Utc>>,
    stripe_schedule_id: Option<String>,
    stripe_plan: Option<String>,
}

const SUB_COLS: &str = "stripe_customer_id, stripe_subscription_id, status, \
                        payment_method_status, stripe_payment_method_id, \
                        payment_method_event_at, subscription_event_at, \
                        past_due_since, billing_stopped_at, stripe_schedule_id, \
                        stripe_plan";

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

/// The org's row in a transaction of its own, or `None`.
async fn read_row(db: &Db, org: OrgId) -> Result<Option<SubRow>> {
    let mut tx = db.begin(org).await?;
    let row = read_row_in(&mut tx).await?;
    tx.commit().await?;
    Ok(row)
}

async fn read_row_in(tx: &mut otto_tenant::Tx<'_>) -> Result<Option<SubRow>> {
    let org = tx.org();
    Ok(sqlx::query_as(&format!(
        "SELECT {SUB_COLS} FROM subscriptions WHERE org_id = $1"
    ))
    .bind(org)
    .fetch_optional(tx.conn())
    .await?)
}

/// The org's row, locked until `tx` ends. Only ever in a short transaction
/// with no Stripe call inside it.
async fn lock_row(tx: &mut otto_tenant::Tx<'_>) -> Result<SubRow> {
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

// ------------------------------------------------------------------ leases

/// A short lease on one org's billing, so an owner's setup, a webhook and
/// sync never act on the same org's Stripe state at once. Claimed and
/// released in short transactions; nothing is held open while it is out.
/// Expires on its own after [`LEASE_TTL_SECS`] if never released.
struct OrgLease {
    org: OrgId,
    token: Uuid,
}

impl OrgLease {
    async fn try_acquire(db: &Db, org: OrgId) -> Result<Option<Self>> {
        let token = Uuid::new_v4();
        let mut tx = db.begin(org).await?;
        sqlx::query(
            "INSERT INTO subscriptions (org_id) VALUES ($1) ON CONFLICT (org_id) DO NOTHING",
        )
        .bind(org)
        .execute(tx.conn())
        .await?;
        let got = sqlx::query(
            "UPDATE subscriptions SET lease_token = $2, \
               lease_until = now() + make_interval(secs => $3) \
             WHERE org_id = $1 AND (lease_until IS NULL OR lease_until < now())",
        )
        .bind(org)
        .bind(token)
        .bind(LEASE_TTL_SECS as f64)
        .execute(tx.conn())
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        Ok(got.then_some(Self { org, token }))
    }

    /// Claim the lease, waiting up to `wait` for another holder to finish.
    async fn acquire(db: &Db, org: OrgId, wait: Duration) -> Result<Self> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(lease) = Self::try_acquire(db, org).await? {
                return Ok(lease);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Busy(format!(
                    "another billing change for org {org} is in progress"
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Prove the lease is still ours, and extend it, inside `tx`: the first
    /// statement of every write made under the lease. An `UPDATE ... WHERE
    /// lease_token = <ours>` that matches no row means another worker has
    /// taken the org ([`Error::LeaseLost`]); it also locks the row, so the
    /// lease cannot change hands before `tx` commits.
    async fn hold(&self, tx: &mut otto_tenant::Tx<'_>) -> Result<()> {
        let held = sqlx::query(
            "UPDATE subscriptions SET lease_until = now() + make_interval(secs => $3) \
             WHERE org_id = $1 AND lease_token = $2",
        )
        .bind(self.org)
        .bind(self.token)
        .bind(LEASE_TTL_SECS as f64)
        .execute(tx.conn())
        .await?
        .rows_affected();
        if held != 1 {
            return Err(Error::LeaseLost(self.org));
        }
        Ok(())
    }

    /// A transaction pinned to the org for a write under the lease: refused
    /// with [`Error::LeaseLost`] if the lease is no longer ours.
    async fn begin(&self, db: &Db) -> Result<otto_tenant::Tx<'static>> {
        let mut tx = db.begin(self.org).await?;
        self.hold(&mut tx).await?;
        Ok(tx)
    }

    /// Extend the lease in a short transaction of its own, before a Stripe
    /// call, so a run of calls cannot outlive it unnoticed.
    async fn renew(&self, db: &Db) -> Result<()> {
        self.begin(db).await?.commit().await?;
        Ok(())
    }

    /// Give the lease back. A failure is logged, not returned: the lease
    /// expires on its own, and the work it covered is already done.
    async fn release(self, db: &Db) {
        let result = async {
            let mut tx = db.begin(self.org).await?;
            sqlx::query(
                "UPDATE subscriptions SET lease_until = NULL, lease_token = NULL \
                 WHERE org_id = $1 AND lease_token = $2",
            )
            .bind(self.org)
            .bind(self.token)
            .execute(tx.conn())
            .await?;
            tx.commit().await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(org = %self.org, error = %e, "could not release a billing lease; it expires on its own");
        }
    }
}

// --------------------------------------------------------- customer map

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_boundaries_are_midnight_utc_on_the_first() {
        let oct = Month::new(2026, 10).unwrap();
        assert_eq!(
            month_start(oct),
            Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap()
        );
        let dec = Month::new(2026, 12).unwrap();
        assert_eq!(
            month_after(dec).unwrap().1,
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn keys_follow_every_parameter_and_the_hour() {
        let t = Utc.with_ymd_and_hms(2026, 10, 20, 12, 5, 0).unwrap();
        let a = idem_at("x", &("cus_1", "pm_1"), t).unwrap();
        assert_eq!(a, idem_at("x", &("cus_1", "pm_1"), t).unwrap());
        assert!(a.as_str().starts_with("otto-x-"));
        assert!(a.as_str().ends_with("-2026102012"));
        assert_ne!(a, idem_at("x", &("cus_1", "pm_2"), t).unwrap());
        assert_ne!(a, idem_at("y", &("cus_1", "pm_1"), t).unwrap());
        let later = t + chrono::Duration::hours(1);
        assert_ne!(a, idem_at("x", &("cus_1", "pm_1"), later).unwrap());
    }

    #[test]
    fn a_stable_key_has_no_hour() {
        let a = idem_stable("subscription", &("cus_1", "pm_1")).unwrap();
        assert!(!a
            .as_str()
            .ends_with(&Utc::now().format("%Y%m%d%H").to_string()));
        assert_eq!(a, idem_stable("subscription", &("cus_1", "pm_1")).unwrap());
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_lost_lease_refuses_every_write(pool: sqlx::PgPool) {
        let db = Db::from_pool(pool.clone());
        let org: Uuid = sqlx::query_scalar(
            "INSERT INTO orgs (slug, name) VALUES ('acme', 'Acme') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let org = OrgId::from(org);
        let lease = OrgLease::acquire(&db, org, Duration::from_secs(1))
            .await
            .unwrap();
        lease.renew(&db).await.unwrap();
        assert!(matches!(
            OrgLease::acquire(&db, org, Duration::from_millis(200)).await,
            Err(Error::Busy(_))
        ));

        // It expires and another worker takes it.
        sqlx::query("UPDATE subscriptions SET lease_until = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        let thief = OrgLease::acquire(&db, org, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(matches!(lease.renew(&db).await, Err(Error::LeaseLost(o)) if o == org));
        assert!(matches!(lease.begin(&db).await, Err(Error::LeaseLost(_))));
        // Releasing a lost lease leaves the new holder's alone.
        lease.release(&db).await;
        thief.renew(&db).await.unwrap();
        thief.release(&db).await;
        OrgLease::acquire(&db, org, Duration::from_millis(200))
            .await
            .unwrap();
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
