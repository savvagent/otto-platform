//! Making Stripe match the price book.
//!
//! # The plan
//!
//! For every org, sync computes a **plan**: the Stripe prices its subscription
//! should hold this month, then at the start of each future month in which a
//! price-book version takes effect, the prices it should switch to. A plan of
//! one phase needs nothing but the right items now. A plan with future phases
//! is written to a Stripe subscription schedule (see the module docs of
//! [`super`]): phase 0 is the current phase, keeping its start, and each later
//! phase starts at 00:00 UTC on the first of its month, with proration off.
//! The last phase ends a month after it starts and the schedule then releases
//! the subscription, which keeps the last phase's prices.
//!
//! What was last written is stored per org (`subscriptions.stripe_plan`), so
//! an org whose plan has not changed costs no Stripe call.
//!
//! # The residual window
//!
//! A switch is exact once its schedule is in Stripe. It is in Stripe within
//! one sync run of the version's Stripe Price existing, and sync runs every
//! 15 minutes in the server, so the window is a version set (`pricebook set`)
//! in the last ~15 minutes before the month it takes effect: those minutes
//! of usage, from 00:00 UTC until the next run, are billed at the previous
//! price. `pricebook set` only accepts a future month, so setting prices any
//! earlier than that leaves no window at all.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use otto_tenant::audit::Entry;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use serde_json::json;
use uuid::Uuid;

use super::{
    actions, idem, idem_stable, is_live_status, month_after, month_start, read_row, Error,
    OrgLease, PaymentMethodStatus, Result, SubRow, ITEMS_WARN_AT, MAX_SCHEDULE_PHASES,
    MAX_SUBSCRIPTION_ITEMS, SYNC_ACTOR,
};
use crate::pricebook::{self, Month, Tiers};
use crate::stripe::{
    meter_event_name, Client, CreateMeter, CreateMeteredPrice, CreateSubscription, PriceProduct,
    PriceTier, SchedulePhaseParams, SubscriptionSchedule, TierUpTo, UpdateSchedule,
};

/// How long one sync run may hold the sync lease before another may take
/// over (a crashed run).
const SYNC_LEASE_SECS: i64 = 1800;

/// How long sync waits for an org another worker is busy with before moving
/// on; the org is picked up by the next run.
const ORG_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// What one [`sync`] run did. Every list is in the order the work was done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// `(meter, stripe meter id)`.
    pub meters_created: Vec<(String, String)>,
    /// `(meter, stripe meter id)`: an active Stripe meter with the event name
    /// already existed and was recorded instead of created.
    pub meters_adopted: Vec<(String, String)>,
    /// `(meter, effective month, stripe price id)`.
    pub prices_created: Vec<(String, Month, String)>,
    /// `(org, stripe subscription id)`.
    pub subscriptions_created: Vec<(OrgId, String)>,
    /// `(org, stripe subscription id)`: a live subscription tagged with the
    /// org already existed and was recorded instead of created.
    pub subscriptions_adopted: Vec<(OrgId, String)>,
    /// `(org, the months at whose start its prices switch)`.
    pub schedules_set: Vec<(OrgId, Vec<Month>)>,
    /// Orgs whose schedule was released (no switch is pending any more).
    pub schedules_released: Vec<OrgId>,
    /// `(org, meter)`: this month's item added or moved to the right price.
    pub items_changed: Vec<(OrgId, String)>,
    /// Worth an operator's attention; nothing failed.
    pub warnings: Vec<String>,
    /// What could not be done. The rest of the run went ahead; the next run
    /// tries again.
    pub errors: Vec<String>,
}

impl SyncReport {
    /// Whether the run changed nothing in Stripe.
    pub fn is_noop(&self) -> bool {
        self.meters_created.is_empty()
            && self.meters_adopted.is_empty()
            && self.prices_created.is_empty()
            && self.subscriptions_created.is_empty()
            && self.subscriptions_adopted.is_empty()
            && self.schedules_set.is_empty()
            && self.schedules_released.is_empty()
            && self.items_changed.is_empty()
    }
}

/// Make Stripe match the price book. Idempotent: a second run with nothing
/// new calls Stripe for nothing.
///
/// 1. A Stripe billing meter for every declared meter that has none (an
///    active Stripe meter with the same event name is adopted). A meter key
///    whose event name would exceed Stripe's limit is reported and skipped.
/// 2. A Stripe Price for every price-book version that has none (current,
///    past and future versions alike), on one Stripe product per meter.
/// 3. For every org with a Stripe customer: a subscription if it has an
///    active card, is not stopped and has no live subscription; and every
///    live subscription brought to its plan (see the module docs).
///
/// One run at a time across every machine (a lease in `stripe_sync_lease`):
/// [`Error::Busy`] if another is running. Per-meter, per-version and per-org
/// failures are collected in [`SyncReport::errors`] and the run carries on.
pub async fn sync(db: &Db, client: &Client) -> Result<SyncReport> {
    sync_until(db, client, &|| false).await
}

/// As [`sync`], stopping between orgs once `stop` says so (a graceful
/// shutdown), so every lease is given back rather than left to expire. The
/// orgs not reached are picked up by the next run.
pub async fn sync_until(
    db: &Db,
    client: &Client,
    stop: &(dyn Fn() -> bool + Send + Sync),
) -> Result<SyncReport> {
    let token = acquire_sync_lease(db)
        .await?
        .ok_or_else(|| Error::Busy("another stripe sync is running".into()))?;
    let result = run(db, client, stop).await;
    if let Err(e) = release_sync_lease(db, token).await {
        tracing::warn!(error = %e, "could not release the sync lease; it expires on its own");
    }
    result
}

async fn acquire_sync_lease(db: &Db) -> Result<Option<Uuid>> {
    let token = Uuid::new_v4();
    let mut tx = db.begin_unpinned().await?;
    let got: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO stripe_sync_lease (name, token, until) \
         VALUES ('sync', $1, now() + make_interval(secs => $2)) \
         ON CONFLICT (name) DO UPDATE SET token = EXCLUDED.token, until = EXCLUDED.until \
           WHERE stripe_sync_lease.until < now() \
         RETURNING token",
    )
    .bind(token)
    .bind(SYNC_LEASE_SECS as f64)
    .fetch_optional(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(got)
}

async fn release_sync_lease(db: &Db, token: Uuid) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("DELETE FROM stripe_sync_lease WHERE name = 'sync' AND token = $1")
        .bind(token)
        .execute(tx.conn())
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn run(
    db: &Db,
    client: &Client,
    stop: &(dyn Fn() -> bool + Send + Sync),
) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    sync_meters(db, client, &mut report).await?;
    sync_prices(db, client, &mut report).await?;
    let mut plan = Plan::load(db, &mut report.warnings).await?;

    let mut tx = db.begin_unpinned().await?;
    let orgs: Vec<Uuid> =
        sqlx::query_scalar("SELECT org_id FROM stripe_customers ORDER BY created_at, org_id")
            .fetch_all(tx.conn())
            .await?;
    tx.commit().await?;
    for org in orgs.into_iter().map(OrgId::from) {
        if stop() {
            report
                .warnings
                .push("stopped early for shutdown; the next run finishes".into());
            break;
        }
        // A month that began during the run changes what "now" is.
        if current_month(db).await? != plan.now().month {
            plan = Plan::load(db, &mut report.warnings).await?;
        }
        // Nothing to do for this org: no lease taken, nothing written.
        if !needs_work(db, org, &plan).await? {
            continue;
        }
        let lease = match OrgLease::acquire(db, org, ORG_WAIT).await {
            Ok(lease) => lease,
            Err(Error::Busy(_)) => {
                report.warnings.push(format!(
                    "org {org}: busy with another billing change; next run"
                ));
                continue;
            }
            Err(e) => {
                report.errors.push(format!("org {org}: {e}"));
                continue;
            }
        };
        let result = reconcile_with(db, client, &lease, org, SYNC_ACTOR, &plan, &mut report).await;
        lease.release(db).await;
        if let Err(e) = result {
            report.errors.push(format!("org {org}: {e}"));
        }
    }
    Ok(report)
}

/// The current month by the database's clock, in a short transaction.
async fn current_month(db: &Db) -> Result<Month> {
    let mut tx = db.begin_unpinned().await?;
    let month = pricebook::current_month(tx.conn()).await?;
    tx.commit().await?;
    Ok(month)
}

/// Whether [`reconcile_with`] could change anything for the org, judged
/// from its row without the lease (it decides again under the lease).
async fn needs_work(db: &Db, org: OrgId, plan: &Plan) -> Result<bool> {
    if plan.now().prices.is_empty() {
        return Ok(false);
    }
    let Some(row) = read_row(db, org).await? else {
        return Ok(false);
    };
    Ok(match row.live_subscription() {
        Some(_) => row.stripe_plan.as_deref() != Some(plan.fingerprint().as_str()),
        None => row.card()? == PaymentMethodStatus::Active && row.billing_stopped_at.is_none(),
    })
}

// ------------------------------------------------------------------ meters

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
    if missing.is_empty() {
        return Ok(());
    }
    // Stripe refuses a second active meter with an event name, so one left
    // behind by an earlier run (created, then not recorded) is adopted.
    let existing = match stripe_meters_by_event_name(client).await {
        Ok(m) => m,
        Err(e) => {
            report
                .errors
                .push(format!("could not list Stripe's meters: {e}"));
            return Ok(());
        }
    };

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
        let id = if let Some(id) = existing.get(&event_name) {
            report.meters_adopted.push((key.clone(), id.clone()));
            id.clone()
        } else {
            let params = CreateMeter {
                display_name,
                event_name: event_name.clone(),
            };
            match client.create_meter(&params, &idem("meter", &params)?).await {
                Ok(m) => {
                    report.meters_created.push((key.clone(), m.id.clone()));
                    m.id
                }
                Err(e) => {
                    report.errors.push(format!("meter {key}: {e}"));
                    continue;
                }
            }
        };
        let mut tx = db.begin_unpinned().await?;
        sqlx::query(
            "INSERT INTO stripe_meters (meter, stripe_meter_id, event_name) VALUES ($1, $2, $3)",
        )
        .bind(&key)
        .bind(&id)
        .bind(&event_name)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Every active Stripe meter, by event name.
async fn stripe_meters_by_event_name(client: &Client) -> Result<BTreeMap<String, String>> {
    let mut all = BTreeMap::new();
    let mut after: Option<String> = None;
    // Bounded: 50 pages of 100 is far past any real account.
    for _ in 0..50 {
        let page = client.list_meters(after.as_deref()).await?;
        after = page.data.last().map(|m| m.id.clone());
        for m in page.data {
            all.insert(m.event_name, m.id);
        }
        if !page.has_more || after.is_none() {
            break;
        }
    }
    Ok(all)
}

// ------------------------------------------------------------------ prices

fn stripe_tiers(tiers: &Tiers) -> Result<Vec<PriceTier>, String> {
    tiers
        .as_slice()
        .iter()
        .map(|t| {
            let up_to = match t.up_to {
                None => TierUpTo::Inf,
                Some(n) => {
                    TierUpTo::Units(u64::try_from(n).map_err(|_| format!("tier bound {n}"))?)
                }
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
        let tiers = match version
            .tiers
            .as_ref()
            .map_err(String::clone)
            .and_then(stripe_tiers)
        {
            Ok(tiers) => tiers,
            Err(reason) => {
                report.errors.push(format!("{what}: malformed: {reason}"));
                continue;
            }
        };
        let params = CreateMeteredPrice {
            currency: super::CURRENCY.to_owned(),
            product: match &product {
                Some(id) => PriceProduct::Id(id.clone()),
                None => PriceProduct::New { name: display_name },
            },
            meter: stripe_meter,
            tiers,
            lookup_key: None,
            nickname: Some(what.clone()),
            metadata: [
                ("meter".to_owned(), version.meter.clone()),
                ("price_version_id".to_owned(), version.id.to_string()),
            ]
            .into(),
        };
        let price = match client
            .create_metered_price(&params, &idem("price", &params)?)
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

// -------------------------------------------------------------------- plan

/// A meter's price in a month, with its Stripe ids.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncedPrice {
    meter: String,
    stripe_meter_id: String,
    stripe_price_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase {
    month: Month,
    /// By meter key, at most [`MAX_SUBSCRIPTION_ITEMS`].
    prices: Vec<SyncedPrice>,
}

impl Phase {
    fn price_ids(&self) -> Vec<String> {
        self.prices
            .iter()
            .map(|p| p.stripe_price_id.clone())
            .collect()
    }
}

/// What every subscription should hold this month and at each coming switch.
/// The same for every org: one price book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plan {
    /// Phase 0 is this month. Later phases are the months a switch happens,
    /// in order, each differing from the one before.
    phases: Vec<Phase>,
}

impl Plan {
    /// Read the plan from the price book (in one short unpinned
    /// transaction).
    ///
    /// This month: every meter whose in-effect version has a Stripe Price (a
    /// meter whose version has none yet is left out, never billed at an older
    /// version). Each later month in which some version takes effect: a phase,
    /// unless a version in effect then has no Stripe Price yet, in which case
    /// that month and every later one wait for the next run (so an item is
    /// never scheduled away). At most [`MAX_SCHEDULE_PHASES`] phases and
    /// [`MAX_SUBSCRIPTION_ITEMS`] items each; anything past that is a warning.
    pub(super) async fn load(db: &Db, warnings: &mut Vec<String>) -> Result<Self> {
        let mut tx = db.begin_unpinned().await?;
        let now = pricebook::current_month(tx.conn()).await?;
        let future: Vec<chrono::NaiveDate> = sqlx::query_scalar(
            "SELECT DISTINCT effective_month FROM price_versions \
             WHERE effective_month > $1 ORDER BY 1",
        )
        .bind(now.first_day())
        .fetch_all(tx.conn())
        .await?;
        let mut phases: Vec<Phase> = Vec::new();
        for month in std::iter::once(now).chain(future.into_iter().map(Month::containing)) {
            let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT DISTINCT ON (v.meter) v.meter, sm.stripe_meter_id, p.stripe_price_id \
                 FROM price_versions v \
                 LEFT JOIN stripe_prices p ON p.price_version_id = v.id \
                 LEFT JOIN stripe_meters sm ON sm.meter = v.meter \
                 WHERE v.effective_month <= $1 \
                 ORDER BY v.meter, v.effective_month DESC",
            )
            .bind(month.first_day())
            .fetch_all(tx.conn())
            .await?;
            let mut prices = Vec::new();
            let mut unsynced = Vec::new();
            for (meter, mtr, price) in rows {
                match (mtr, price) {
                    (Some(stripe_meter_id), Some(stripe_price_id)) => prices.push(SyncedPrice {
                        meter,
                        stripe_meter_id,
                        stripe_price_id,
                    }),
                    _ => unsynced.push(meter),
                }
            }
            if month != now && !unsynced.is_empty() {
                warnings.push(format!(
                    "the {month} price of {} has no Stripe price yet; switches from {month} \
                     on are not scheduled until it does",
                    unsynced.join(", ")
                ));
                break;
            }
            if prices.len() > MAX_SUBSCRIPTION_ITEMS {
                warnings.push(format!(
                    "{} meters are priced for {month} but a Stripe subscription holds at most \
                     {MAX_SUBSCRIPTION_ITEMS} items; {} are not billed",
                    prices.len(),
                    prices.len() - MAX_SUBSCRIPTION_ITEMS
                ));
                prices.truncate(MAX_SUBSCRIPTION_ITEMS);
            }
            let phase = Phase { month, prices };
            if phases
                .last()
                .is_some_and(|last| last.price_ids() == phase.price_ids())
            {
                continue;
            }
            if phases.len() == MAX_SCHEDULE_PHASES {
                warnings.push(format!(
                    "price switches from {month} on are past Stripe's {MAX_SCHEDULE_PHASES} \
                     schedule phases; they are scheduled as earlier ones pass"
                ));
                break;
            }
            phases.push(phase);
        }
        tx.commit().await?;
        Ok(Self { phases })
    }

    fn now(&self) -> &Phase {
        &self.phases[0]
    }

    /// A stable summary of the plan, compared with what was last written.
    /// Phase 0 is not labelled with its month, so a month passing with no
    /// switch changes nothing.
    fn fingerprint(&self) -> String {
        self.phases
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let label = if i == 0 {
                    "now".to_owned()
                } else {
                    p.month.to_string()
                };
                format!("{label}:{}", p.price_ids().join(","))
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn only_now(&self) -> Self {
        Self {
            phases: vec![self.now().clone()],
        }
    }
}

// --------------------------------------------------------------- per org

/// Bring one org's subscription to the current plan: create (or adopt) it if
/// the org should have one, then make its prices match. The caller holds the
/// org's lease; every Stripe call renews it and every write is made under
/// it ([`OrgLease::begin`]).
pub(super) async fn reconcile_org(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    actor: &str,
    report: &mut SyncReport,
) -> Result<()> {
    let plan = Plan::load(db, &mut report.warnings).await?;
    reconcile_with(db, client, lease, org, actor, &plan, report).await
}

async fn reconcile_with(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    actor: &str,
    plan: &Plan,
    report: &mut SyncReport,
) -> Result<()> {
    if plan.now().prices.is_empty() {
        // Nothing is priced in Stripe this month: nothing to subscribe to.
        return Ok(());
    }
    let Some(row) = read_row(db, org).await? else {
        return Ok(());
    };
    let (sub, row) = match row.live_subscription() {
        Some(s) => (s.stripe_subscription_id, row),
        None => {
            if row.card()? != PaymentMethodStatus::Active || row.billing_stopped_at.is_some() {
                return Ok(());
            }
            let Some(sub) =
                ensure_subscription(db, client, lease, org, &row, plan, actor, report).await?
            else {
                return Ok(());
            };
            let Some(row) = read_row(db, org).await? else {
                return Ok(());
            };
            (sub, row)
        }
    };
    reconcile_prices(db, client, lease, org, &sub, &row, plan, actor, report).await
}

/// Create the org's subscription, or adopt a live one already tagged with the
/// org (left by an earlier attempt whose write did not happen), and record it
/// at once. One item per meter priced this month, `billing_cycle_anchor` at
/// 00:00 UTC on the first of next month, `proration_behavior=none` (the
/// client always sends it).
///
/// More than one live subscription tagged with the org is an error, not a
/// choice: billing would double, and only a person can say which to keep.
#[allow(clippy::too_many_arguments)]
async fn ensure_subscription(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    row: &SubRow,
    plan: &Plan,
    actor: &str,
    report: &mut SyncReport,
) -> Result<Option<String>> {
    let (Some(customer), Some(pm)) = (
        row.stripe_customer_id.clone(),
        row.stripe_payment_method_id.clone(),
    ) else {
        return Ok(None);
    };
    let org_id = org.to_string();
    lease.renew(db).await?;
    let mut tagged: Vec<_> = client
        .list_subscriptions(&customer)
        .await?
        .data
        .into_iter()
        .filter(|s| {
            s.metadata.get("org_id") == Some(&org_id)
                && is_live_status(&s.status)
                // Never the one Stripe already told us is gone.
                && Some(&s.id) != row.stripe_subscription_id.as_ref()
        })
        .collect();
    if tagged.len() > 1 {
        let ids: Vec<&str> = tagged.iter().map(|s| s.id.as_str()).collect();
        return Err(Error::Unexpected(format!(
            "{} live Stripe subscriptions are tagged with org {org} ({}); cancel all but \
             one in the Stripe dashboard",
            ids.len(),
            ids.join(", ")
        )));
    }
    let existing = tagged.pop();
    let now = plan.now();
    let (_, anchor) = month_after(now.month)?;
    let (sub, status, adopted, stripe_plan) = match existing {
        Some(s) => (s.id, s.status, true, None),
        None => {
            let params = CreateSubscription {
                customer,
                prices: now.price_ids(),
                billing_cycle_anchor: Some(anchor),
                metadata: [("org_id".to_owned(), org_id)].into(),
            };
            // The card and the subscription this replaces are part of the
            // key, so a re-subscribe after a cancellation is a new request.
            // No hour in it: a retry at any time replays the first answer
            // rather than making a second subscription.
            let key = idem_stable("subscription", &(&params, &pm, &row.stripe_subscription_id))?;
            lease.renew(db).await?;
            let s = client.create_subscription(&params, &key).await?;
            (s.id, s.status, false, Some(plan.only_now().fingerprint()))
        }
    };

    let mut tx = lease.begin(db).await?;
    sqlx::query(
        "UPDATE subscriptions SET stripe_subscription_id = $2, status = $3, \
           subscription_event_at = NULL, stripe_schedule_id = NULL, stripe_plan = $4, \
           updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(&sub)
    .bind(&status)
    .bind(&stripe_plan)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(actions::SUBSCRIPTION_CREATED)
            .actor_label(actor)
            .target("org", org.to_string())
            .detail(json!({
                "stripeSubscriptionId": sub,
                "status": status,
                "adopted": adopted,
                "billingCycleAnchor": anchor,
                "meters": now.prices.iter().map(|p| p.meter.as_str()).collect::<Vec<_>>(),
            })),
    )
    .await?;
    tx.commit().await?;

    if adopted {
        report.subscriptions_adopted.push((org, sub.clone()));
    } else {
        report.subscriptions_created.push((org, sub.clone()));
        if now.prices.len() >= ITEMS_WARN_AT {
            report
                .warnings
                .push(items_warning(org, &sub, now.prices.len()));
        }
    }
    Ok(Some(sub))
}

fn items_warning(org: OrgId, sub: &str, items: usize) -> String {
    format!(
        "org {org}: subscription {sub} has {items} of Stripe's {MAX_SUBSCRIPTION_ITEMS} items \
         per subscription; a meter priced past that cannot be billed"
    )
}

/// The open schedule managing `sub`, if any: the one last recorded if it
/// still is, else whatever the subscription names.
async fn open_schedule(
    client: &Client,
    sub: &str,
    recorded: Option<&str>,
) -> Result<Option<SubscriptionSchedule>> {
    if let Some(id) = recorded {
        let schedule = client.retrieve_schedule(id).await?;
        if schedule.is_open() && schedule.subscription.as_deref() == Some(sub) {
            return Ok(Some(schedule));
        }
    }
    let Some(id) = client.retrieve_subscription(sub).await?.schedule else {
        return Ok(None);
    };
    let schedule = client.retrieve_schedule(&id).await?;
    Ok(schedule.is_open().then_some(schedule))
}

/// Make the subscription's prices follow `plan`. Skipped (no Stripe call)
/// when the plan is what was last written.
#[allow(clippy::too_many_arguments)]
async fn reconcile_prices(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    sub: &str,
    row: &SubRow,
    plan: &Plan,
    actor: &str,
    report: &mut SyncReport,
) -> Result<()> {
    let desired = plan.fingerprint();
    if row.stripe_plan.as_deref() == Some(desired.as_str()) {
        return Ok(());
    }
    lease.renew(db).await?;
    let existing = open_schedule(client, sub, row.stripe_schedule_id.as_deref()).await?;
    let mut changed = Vec::new();
    let (schedule, switches) = if plan.phases.len() == 1 {
        // No switch pending: no schedule, and this month's items right now.
        if let Some(s) = existing {
            lease.renew(db).await?;
            client
                .release_schedule(&s.id, &idem("release-schedule", &s.id)?)
                .await?;
            report.schedules_released.push(org);
        }
        changed = fix_items(db, client, lease, org, sub, plan.now(), report).await?;
        (None, Vec::new())
    } else {
        let s = match existing {
            Some(s) => s,
            None => {
                lease.renew(db).await?;
                client
                    .create_schedule_from_subscription(sub, &idem("schedule", &sub)?)
                    .await?
            }
        };
        let start = s
            .current_phase
            .map(|p| p.start_date)
            .or_else(|| s.phases.first().map(|p| p.start_date))
            .and_then(|t| Utc.timestamp_opt(t, 0).single())
            .ok_or_else(|| Error::Unexpected(format!("schedule {} has no current phase", s.id)))?;
        let mut phases = Vec::with_capacity(plan.phases.len());
        for (i, phase) in plan.phases.iter().enumerate() {
            let end_date = match plan.phases.get(i + 1) {
                Some(next) => month_start(next.month),
                None => month_after(phase.month)?.1,
            };
            phases.push(SchedulePhaseParams {
                start_date: (i == 0).then_some(start),
                end_date,
                prices: phase.price_ids(),
            });
        }
        let params = UpdateSchedule { phases };
        lease.renew(db).await?;
        client
            .update_schedule(&s.id, &params, &idem("schedule-update", &(&s.id, &params))?)
            .await?;
        let switches: Vec<Month> = plan.phases[1..].iter().map(|p| p.month).collect();
        report.schedules_set.push((org, switches.clone()));
        (Some(s.id), switches)
    };

    let mut tx = lease.begin(db).await?;
    sqlx::query(
        "UPDATE subscriptions SET stripe_plan = $3, stripe_schedule_id = $4, updated_at = now() \
         WHERE org_id = $1 AND stripe_subscription_id = $2",
    )
    .bind(org)
    .bind(sub)
    .bind(&desired)
    .bind(&schedule)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(actions::SUBSCRIPTION_ITEMS_SYNCED)
            .actor_label(actor)
            .target("org", org.to_string())
            .detail(json!({
                "stripeSubscriptionId": sub,
                "stripeScheduleId": schedule,
                "switchesAt": switches.iter().map(|m| month_start(*m)).collect::<Vec<_>>(),
                "changedNow": changed,
            })),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Bring this month's items to `phase` directly (no switch is pending): add
/// an item for a meter with none, move an item on the wrong price. Without
/// proration. Returns the meters changed.
#[allow(clippy::too_many_arguments)]
async fn fix_items(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    sub: &str,
    phase: &Phase,
    report: &mut SyncReport,
) -> Result<Vec<String>> {
    let items = client.list_subscription_items(sub).await?.data;
    let by_meter: BTreeMap<String, (String, String)> = items
        .iter()
        .filter_map(|i| {
            let meter = i.price.recurring.as_ref()?.meter.clone()?;
            Some((meter, (i.id.clone(), i.price.id.clone())))
        })
        .collect();
    let mut count = items.len();
    let mut changed = Vec::new();
    for p in &phase.prices {
        match by_meter.get(&p.stripe_meter_id) {
            Some((_, price)) if *price == p.stripe_price_id => {}
            Some((item, _)) => {
                lease.renew(db).await?;
                client
                    .change_subscription_item_price(
                        item,
                        &p.stripe_price_id,
                        &idem("item-price", &(item, &p.stripe_price_id))?,
                    )
                    .await?;
                changed.push(p.meter.clone());
            }
            None if count >= MAX_SUBSCRIPTION_ITEMS => report.errors.push(format!(
                "org {org}: cannot add {} to subscription {sub}: Stripe allows at most \
                 {MAX_SUBSCRIPTION_ITEMS} items",
                p.meter
            )),
            None => {
                lease.renew(db).await?;
                client
                    .add_subscription_item(
                        sub,
                        &p.stripe_price_id,
                        &idem("item-add", &(sub, &p.stripe_price_id))?,
                    )
                    .await?;
                count += 1;
                changed.push(p.meter.clone());
            }
        }
    }
    report
        .items_changed
        .extend(changed.iter().map(|m| (org, m.clone())));
    if count >= ITEMS_WARN_AT {
        report.warnings.push(items_warning(org, sub, count));
    }
    Ok(changed)
}
