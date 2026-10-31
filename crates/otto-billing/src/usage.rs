//! Metering statements.
//!
//! The policy — which tools are billable, what a bucket is worth, when to
//! refuse a call — belongs to each otto-* service that calls
//! [`UsageExt::record_usage`] (e.g. a `flags-mcp`-style classifier deciding
//! whether a given tool call counts). What lives here is the SQL, because
//! `usage_events`, `org_period_usage`, `plans` and `subscriptions` are tenant
//! tables owned by `otto-tenant`'s RLS pattern and every statement against a
//! tenant table goes through a pinned [`Tx`].
//!
//! **The counter is incremented in the caller's own transaction, on purpose.**
//! [`UsageExt::record_usage`] takes `&mut Tx` rather than a `Db`, so the meter
//! and the work it is metering commit or abort together. That single fact is
//! what makes both halves of the billing promise true: a call that fails is
//! never billed (the row rolls back with the work), and a call that succeeds
//! is never billed twice (there is no second transaction to retry).
//!
//! # Value meters and per-service pools
//!
//! A shipped event may name one of the shipping service's declared meters
//! (`meters`, see [`crate::meters`]) and a quantity. [`check_metering`] decides,
//! without a query, whether the event is acceptable;
//! [`UsageExt::ingest_usage_deferred`] then counts it in three places, all in
//! the ingest transaction:
//!
//! - `org_period_usage`, the legacy family-wide bucket, exactly as before
//!   (its `billable` flag included), for the console usage page;
//! - `org_service_period_usage`, the shipping service's own pool
//!   (`billable_count` from the `billable` flag, `total_count` always), when
//!   the shipper has a service slug;
//! - `org_meter_period_usage`, the meter's quantity, for a metered event.
//!
//! A metered event's quantity always counts toward its meter, whatever its
//! `billable` flag says: the flag is the legacy call classification and only
//! feeds the call counters. An event with no meter is unmetered and free: it
//! adds to no meter, so nothing priced by meters (spend, budgets, invoices)
//! ever sees it.
//!
//! After the counters, a metered event of a budgeted service is noted for
//! the budget step ([`crate::budgets::PendingBudgets`]), which runs once per
//! service and period in the same transaction before commit: it records and
//! emails any budget threshold the service has newly reached. It never
//! rejects or fails an event.
//!
//! A metered event of an org with a live Stripe subscription is also added
//! to the org's open Stripe meter outbox row for its meter and hour
//! (`stripe_meter_outbox`, aggregated, see [`crate::stripe_outbox`]) by the
//! same statement that counts it, at no extra round trip. An org without one
//! is not billed through Stripe, and queues nothing.
//!
//! # Which period an event is billed in
//!
//! An event is billed at the instant it happened (`occurred_at`, never later
//! than its arrival), so an event that sat in a resource server's outbox
//! across midnight on the 1st still counts in the month it was earned in,
//! **until that month's period closes**: [`PERIOD_CLOSE_GRACE`](crate::period::PERIOD_CLOSE_GRACE) (2 hours)
//! into the next month ([`crate::period`]). An event that arrives after its
//! month has closed is **late**: it is still accepted and counted, but billed
//! at the moment it arrives ([`crate::period::billed_at`]), in the current
//! period, for its counters, its budget and its Stripe meter event alike. So
//! the platform and Stripe always agree on the period of every event, and a
//! period's invoice, once its period has closed, never grows. The ingest
//! receipt does not distinguish a late event: it is `accepted` like any other.
//! The ledger (`usage_events.created_at`) records the billed instant.
//!
//! # Concurrency
//!
//! One batch of one org runs in one transaction, which takes the org's
//! ingest lock first ([`lock_org_ingest`]), so two batches of one org never
//! interleave: whatever order their events touch counter rows in, they cannot
//! deadlock. Within a statement the counter rows are taken in a fixed order
//! (see `ingest_usage_deferred`).
//!
//! Meter declarations are add-only ([`crate::meters`] never removes one), so
//! an event accepted once stays acceptable: a replay of it reaches the ledger
//! claim and comes back [`IngestOutcome::Duplicate`], never `unknown_meter`.
//! Removing meters would break that, and with it the shipper's ability to
//! retry a batch blindly.

use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

use chrono::{DateTime, Datelike, Duration, Months, NaiveTime, Utc};
use otto_core::error::{Error, Result};
use otto_core::orgs::Plan;
use otto_tenant::ids::UserId;
use otto_tenant::Tx;
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::billing::LIVE_STATUSES;
use crate::budgets::PendingBudgets;
use crate::period::{self, Month};
use crate::stripe_outbox;

/// The first day of the current UTC billing month, as SQL.
///
/// `now()` is `timestamptz`; the `AT TIME ZONE 'utc'` converts it to a UTC wall
/// clock before truncating, so the month boundary is the same instant for every
/// customer regardless of where the database thinks it is.
const PERIOD: &str = "date_trunc('month', now() AT TIME ZONE 'utc')::date";

/// One org's usage in one billing month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PeriodUsage {
    pub period_start: chrono::NaiveDate,
    /// Calls that consume the plan's bucket.
    pub billable_count: i64,
    /// Every recorded call, billable or not. Kept so the free/billable split can
    /// be repriced later against real history rather than guesses.
    pub total_count: i64,
}

impl PeriodUsage {
    /// A month in which nothing has been recorded yet.
    fn empty(period_start: chrono::NaiveDate) -> Self {
        Self {
            period_start,
            billable_count: 0,
            total_count: 0,
        }
    }
}

/// What an org is entitled to this month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanLimits {
    pub plan: Plan,
    pub display_name: String,
    /// Billable operations included in the plan, after any negotiated override.
    pub included_ops: i64,
    /// Whether exceeding the bucket stops billable work rather than metering
    /// overage.
    pub hard_stop: bool,
    /// Capabilities the plan unlocks, as a JSON object keyed by capability
    /// (`plans.features`). Opaque to the platform: the services that read a
    /// key own its meaning.
    pub features: serde_json::Value,
}

/// A usage event shipped by a resource server from its own outbox.
#[derive(Debug, Clone)]
pub struct ShippedUsage<'a> {
    /// Minted by the resource server when it wrote its outbox row, and reused
    /// verbatim on every retry. The idempotency key, scoped per resource server.
    pub event_id: Uuid,
    pub user: Option<UserId>,
    pub tool: &'a str,
    pub billable: bool,
    /// When the work happened, which decides the billing month: an event that
    /// sat in an outbox across midnight on the 1st belongs to the month it was
    /// earned in. Bounded by [`earliest_occurred_at`] and [`MAX_FUTURE_SKEW`].
    pub occurred_at: DateTime<Utc>,
    /// The *shipping* resource server's service slug, whose pool the event
    /// counts in. `None` for a server with no slug yet: the event then counts
    /// only in the legacy family-wide bucket.
    pub service: Option<&'a str>,
    /// The meter and quantity, for a metered event that passed
    /// [`check_metering`]; `None` for an unmetered (free) one.
    pub metered: Option<Metered<'a>>,
}

/// The largest quantity one event may carry. Large enough for any real batch
/// of work, small enough that no plausible number of events overflows a
/// `bigint` total.
///
/// The wire contract's copy is `otto_resource::MAX_METER_QUANTITY`. It is
/// repeated here rather than imported because the dependency cannot run either
/// way cleanly: `otto-resource` is the database-free client every resource
/// server links, so it must not depend on this crate (sqlx, otto-tenant), and
/// this crate is the SQL layer, which should not take on the HTTP client crate
/// for one number. `otto-platform-server`'s `quantities_are_bounded_per_event`
/// test asserts the two are equal, as does migration 0019's CHECK.
pub const MAX_METER_QUANTITY: u64 = 1_000_000_000;

/// Rejection code: the event names a meter its shipper has not declared.
pub const UNKNOWN_METER: &str = "unknown_meter";
/// Rejection code: the event's `service` is not its shipper's.
pub const SERVICE_MISMATCH: &str = "service_mismatch";
/// Rejection code: a quantity of 0, above [`MAX_METER_QUANTITY`], or sent
/// without a meter.
pub const INVALID_QUANTITY: &str = "invalid_quantity";

/// How much of a refused meter key is echoed back. A valid key is at most
/// 63 + 1 + 63 bytes.
const MAX_ECHOED_METER: usize = 128;

/// A metered event's meter key and quantity, as [`check_metering`] accepted
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metered<'a> {
    /// A declared `meters.key`.
    pub meter: &'a str,
    /// 1 to [`MAX_METER_QUANTITY`].
    pub quantity: i64,
}

/// Why [`check_metering`] refused an event: a machine-readable `code`
/// ([`UNKNOWN_METER`], [`SERVICE_MISMATCH`] or [`INVALID_QUANTITY`]) and a
/// sentence for the shipper's log. Displays as `<code>: <detail>`, which is the
/// `reason` a rejected event carries in the ingest receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteringRejection {
    pub code: &'static str,
    pub detail: String,
}

impl fmt::Display for MeteringRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for MeteringRejection {}

fn reject(code: &'static str, detail: impl Into<String>) -> MeteringRejection {
    MeteringRejection {
        code,
        detail: detail.into(),
    }
}

/// The resource server shipping a batch, as [`check_metering`] needs it.
#[derive(Debug, Clone, Copy)]
pub struct Shipper<'a> {
    /// Its service slug, `None` until an operator assigns one.
    pub service: Option<&'a str>,
    /// The meter keys that service has declared, loaded once per batch so no
    /// event costs a query. Empty for a shipper with no service.
    pub declared: &'a HashSet<String>,
}

/// One event's metering fields, as it was shipped.
#[derive(Debug, Clone, Copy, Default)]
pub struct MeteringFields<'a> {
    /// The service the event claims to come from.
    pub service: Option<&'a str>,
    /// The meter key it counts toward, `<service>/<meter>`.
    pub meter: Option<&'a str>,
    pub quantity: Option<u64>,
}

/// Check an event's metering fields against its shipper.
///
/// Returns the meter and quantity for a metered event, `None` for an
/// unmetered one, or why the event must be refused. A meter named without a
/// quantity counts 1.
///
/// ```
/// use std::collections::HashSet;
/// use otto_billing::usage::{check_metering, Metered, MeteringFields, Shipper, UNKNOWN_METER};
///
/// let declared: HashSet<String> = ["otto-flags/evaluations".to_owned()].into();
/// let flags = Shipper { service: Some("otto-flags"), declared: &declared };
///
/// let ok = check_metering(&flags, MeteringFields {
///     meter: Some("otto-flags/evaluations"),
///     quantity: Some(3),
///     ..Default::default()
/// });
/// assert_eq!(ok, Ok(Some(Metered { meter: "otto-flags/evaluations", quantity: 3 })));
///
/// // Unmetered events are free and always fine.
/// assert_eq!(check_metering(&flags, MeteringFields::default()), Ok(None));
///
/// let refused = check_metering(&flags, MeteringFields {
///     meter: Some("otto-flags/nope"),
///     ..Default::default()
/// });
/// assert_eq!(refused.unwrap_err().code, UNKNOWN_METER);
/// ```
pub fn check_metering<'a>(
    shipper: &Shipper<'_>,
    event: MeteringFields<'a>,
) -> std::result::Result<Option<Metered<'a>>, MeteringRejection> {
    let caller_service = shipper.service;
    let MeteringFields {
        service,
        meter,
        quantity,
    } = event;
    if let Some(claimed) = service {
        if caller_service != Some(claimed) {
            return Err(reject(
                SERVICE_MISMATCH,
                match caller_service {
                    Some(own) => format!("`service` must be this resource server's own, `{own}`"),
                    None => "this resource server has no service slug yet; leave `service` unset"
                        .to_owned(),
                },
            ));
        }
    }
    let Some(meter) = meter else {
        return match quantity {
            Some(_) => Err(reject(INVALID_QUANTITY, "`quantity` requires a `meter`")),
            None => Ok(None),
        };
    };
    // A server with no service slug cannot have declared anything, and a key
    // outside the caller's namespace is never its meter, whatever `declared`
    // holds.
    let own = caller_service.is_some_and(|svc| {
        meter
            .split_once('/')
            .is_some_and(|(prefix, _)| prefix == svc)
    });
    if !own || !shipper.declared.contains(meter) {
        return Err(reject(
            UNKNOWN_METER,
            format!(
                "`{}` is not a meter this resource server has declared",
                truncate(meter, MAX_ECHOED_METER)
            ),
        ));
    }
    match quantity.unwrap_or(1) {
        q @ 1..=MAX_METER_QUANTITY => Ok(Some(Metered {
            meter,
            quantity: i64::try_from(q).expect("MAX_METER_QUANTITY fits in i64"),
        })),
        _ => Err(reject(
            INVALID_QUANTITY,
            format!("`quantity` must be 1 to {MAX_METER_QUANTITY}"),
        )),
    }
}

/// At most `max` bytes of `s`, cut on a character boundary.
fn truncate(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// One declared meter's quantity this month, for the usage-status of the
/// service that declared it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct MeterPeriodUsage {
    /// The meter's key, `<service>/<meter>`.
    pub meter: String,
    pub display_name: String,
    pub unit: String,
    /// Zero when nothing has been shipped for it this month.
    pub quantity: i64,
}

/// How far ahead of the platform's clock an event's `occurred_at` may be.
pub const MAX_FUTURE_SKEW: Duration = Duration::minutes(5);

/// The oldest `occurred_at` accepted at `now`: the start of the previous UTC
/// month. A resource server's outbox may legitimately hold events across a
/// month boundary, but not for longer, and an unbounded window would let a
/// buggy or compromised shipper rewrite arbitrarily old billing periods.
pub fn earliest_occurred_at(now: DateTime<Utc>) -> DateTime<Utc> {
    let first = now.date_naive().with_day(1).expect("day 1 exists");
    let prev = first
        .checked_sub_months(Months::new(1))
        .expect("a month before a real date exists");
    prev.and_time(NaiveTime::MIN).and_utc()
}

/// The first key of the transaction-scoped advisory lock
/// [`lock_org_ingest`] takes (`pg_advisory_xact_lock(INGEST_LOCK_NAMESPACE,
/// hashtext(org_id::text))`). The two-key form lives in its own key space,
/// apart from the one-`bigint` advisory locks elsewhere (the auth rate
/// limiter's, sqlx's migration lock); any other two-key advisory lock must
/// use a different first key. The usage-ledger lock
/// (`otto_auth::resources::USAGE_LEDGER_LOCK_NAMESPACE`) is `0x0055_1002`.
pub const INGEST_LOCK_NAMESPACE: i32 = 0x0055_1001;

/// Take the org's ingest lock for the rest of `tx`, waiting for any other
/// transaction that holds it (another ingest batch of the org, or
/// [`crate::stripe_outbox::backfill_period`]) to end.
///
/// Call it first, right after `begin`: it serializes whole batches of one
/// org, so their counter row locks cannot deadlock whatever order the events
/// arrive in, and so a backfill sees no batch half-way. Two orgs whose ids
/// hash alike only wait for each other, which is harmless.
pub async fn lock_org_ingest(tx: &mut Tx<'_>) -> std::result::Result<(), sqlx::Error> {
    let org = tx.org();
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2::uuid::text))")
        .bind(INGEST_LOCK_NAMESPACE)
        .bind(org)
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// What [`UsageExt::ingest_usage_deferred`] did with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New: recorded and counted.
    Counted,
    /// Already recorded for this org; nothing changed.
    Duplicate,
    /// Refused, with nothing recorded. Retrying unchanged will fail again.
    Rejected(&'static str),
    /// Not counted: it would take the org's total of its meter past the
    /// sanity threshold, so it waits in `usage_held_events` for an operator.
    /// Carries the reason, which starts with `held_for_review`.
    Held(String),
}

/// The default sanity threshold of [`UsageExt::ingest_usage_held`]: the most
/// of one meter an org may accrue in one billing month before further events
/// are held for operator review. A thousand times one event's own cap
/// ([`MAX_METER_QUANTITY`]): above any plausible month of any meter, so only a
/// runaway or hostile shipper reaches it, and still a bound, where without it
/// a shipper could bill 500 events of 1e9 per request without end. Operators
/// tune it down to their meters with `SAVVAGENT_USAGE_HOLD_THRESHOLD`.
pub const DEFAULT_HOLD_THRESHOLD: i64 = 1_000_000_000_000;

/// Whether `org` (the transaction's) has authorized the resource server whose
/// canonical URI is `resource_uri`: a token of any kind was ever issued in the
/// org for it (`org_resource_grants`, migration 0027, which also follows the
/// server's aliases). "Ever" and not "active" on purpose: usage is shipped
/// from an outbox, possibly long after the work, so the token that did the
/// work has often expired or been revoked by the time the event arrives, and
/// that usage is still owed.
pub async fn org_authorized_resource(
    tx: &mut Tx<'_>,
    resource_uri: &str,
) -> std::result::Result<bool, sqlx::Error> {
    let org = tx.org();
    sqlx::query_scalar("SELECT org_authorized_resource($1, $2)")
        .bind(org)
        .bind(resource_uri)
        .fetch_one(tx.conn())
        .await
}

/// One event held for review (`usage_held_events`).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct HeldEvent {
    pub org_id: Uuid,
    pub resource_uri: String,
    pub event_id: Uuid,
    pub meter: String,
    pub quantity: i64,
    pub period_start: chrono::NaiveDate,
    pub occurred_at: DateTime<Utc>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// Every org's held events, oldest first, for the operator.
pub async fn list_held(db: &otto_tenant::Db) -> Result<Vec<HeldEvent>> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SELECT set_config('app.usage_held_review', 'on', true)")
        .execute(tx.conn())
        .await?;
    let rows = sqlx::query_as(
        "SELECT org_id, resource_uri, event_id, meter, quantity, period_start, \
                occurred_at, reason, created_at \
         FROM usage_held_events ORDER BY created_at, id",
    )
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// The statement that counts one usage event (see
/// [`UsageExt::ingest_usage_deferred`] for what each part does), built once:
/// only the open outbox row's conflict clause is spliced in, and it never
/// changes.
static INGEST_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "WITH event AS ( \
           INSERT INTO usage_events \
             (org_id, user_id, tool, billable, created_at, resource_uri, meter, quantity) \
           VALUES ($1, (SELECT id FROM users WHERE id = $2), $3, $4, $5, \
                   canonical_resource_uri($6::text), $7::text, $8::bigint) \
         ), legacy AS ( \
           INSERT INTO org_period_usage (org_id, period_start, billable_count, total_count) \
           VALUES ($1, date_trunc('month', $5::timestamptz AT TIME ZONE 'utc')::date, \
                   $4::boolean::int, 1) \
           ON CONFLICT (org_id, period_start) DO UPDATE \
             SET billable_count = org_period_usage.billable_count + EXCLUDED.billable_count, \
                 total_count = org_period_usage.total_count + 1, \
                 updated_at = now() \
           RETURNING period_start \
         ), service AS ( \
           INSERT INTO org_service_period_usage \
             (org_id, service, period_start, billable_count, total_count) \
           SELECT $1, $9::text, legacy.period_start, $4::boolean::int, 1 \
           FROM legacy \
           WHERE $9::text IS NOT NULL \
           ON CONFLICT (org_id, service, period_start) DO UPDATE \
             SET billable_count = org_service_period_usage.billable_count \
                                  + EXCLUDED.billable_count, \
                 total_count = org_service_period_usage.total_count + 1, \
                 updated_at = now() \
           RETURNING 1 \
         ), meter AS ( \
           INSERT INTO org_meter_period_usage (org_id, meter, period_start, quantity) \
           SELECT $1, $7::text, legacy.period_start, $8::bigint \
           FROM legacy CROSS JOIN (SELECT count(*) FROM service) AS service_done \
           WHERE $7::text IS NOT NULL \
           ON CONFLICT (org_id, meter, period_start) DO UPDATE \
             SET quantity = org_meter_period_usage.quantity + EXCLUDED.quantity, \
                 updated_at = now() \
           RETURNING 1 \
         ), stripe AS ( \
           INSERT INTO stripe_meter_outbox \
             (org_id, event_name, stripe_customer_id, value, bucket_start, \
              next_attempt_at) \
           SELECT $1, $10::text, s.stripe_customer_id, $8::bigint, $11::timestamptz, \
                  $11::timestamptz + interval '1 hour' \
           FROM subscriptions s CROSS JOIN (SELECT count(*) FROM meter) AS meter_done \
           WHERE $10::text IS NOT NULL AND s.org_id = $1 \
             AND s.stripe_customer_id IS NOT NULL \
             AND s.stripe_subscription_id IS NOT NULL \
             AND s.status = ANY($12::text[]) \
           {add_to_open_row} \
         ) \
         SELECT b.monthly_budget_cents, b.hard_stop, \
                (SELECT max(a.threshold) FROM budget_alerts a \
                 WHERE a.org_id = $1 AND a.service = $9::text \
                   AND a.period_start = \
                       date_trunc('month', $5::timestamptz AT TIME ZONE 'utc')::date) \
                  AS max_fired \
         FROM service_budgets b \
         WHERE $7::text IS NOT NULL AND b.org_id = $1 AND b.service = $9::text",
        add_to_open_row = stripe_outbox::add_to_open_row(),
    )
});

/// Extension methods on [`otto_tenant::Tx`] for metering and plan limits. See
/// `otto-core`'s crate docs for why these are an extension trait rather than
/// inherent methods.
pub trait UsageExt {
    fn record_usage(
        &mut self,
        user: Option<UserId>,
        tool: &str,
        billable: bool,
    ) -> impl std::future::Future<Output = Result<PeriodUsage>> + Send;

    /// Record a usage event shipped from a resource server's outbox,
    /// idempotently (see [`IngestOutcome`]), with its budget step noted in
    /// `budgets`: call [`PendingBudgets::run`] on this transaction once the
    /// batch's events are counted, before committing. Take
    /// [`lock_org_ingest`] first, and feed a batch's events in billed order
    /// (period, then `occurred_at`).
    ///
    /// Lock order (the canonical statement is the "Lock order" section of
    /// `otto_auth::resources`). The event's dedupe claim (`claim_usage_event`)
    /// takes the usage-ledger advisory lock of `resource_uri` shared, and a
    /// resource rename takes it exclusively before it locks the
    /// `resource_servers` row it moves. So in an ingest transaction the first
    /// claim must come before any write that references `resource_servers`:
    /// such a write (a row with a foreign key to it, such as a service's pool,
    /// budget or alert rows, or a `FOR SHARE`/`FOR UPDATE` read of it) holds a
    /// lock on that row, and waiting for the ledger lock while holding it
    /// deadlocks against a rename waiting for the row. This method claims
    /// before it writes anything; a caller that adds writes of its own to the
    /// transaction makes them after its first call.
    ///
    /// The event is recorded under the canonical URI `resource_uri` names
    /// (`canonical_resource_uri`, migration 0026), read after the claim, so
    /// a batch that authenticated before a rename and claimed after it files
    /// its `usage_events` row under the new URI, like its dedupe entry.
    fn ingest_usage_deferred(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
    ) -> impl std::future::Future<Output = Result<IngestOutcome>> + Send;

    /// [`ingest_usage_deferred`](Self::ingest_usage_deferred) as if the
    /// platform's clock read `now`, which decides the accepted window and
    /// whether the event's period has closed. For tests of period boundaries
    /// only; production ingest uses the real clock.
    #[doc(hidden)]
    fn ingest_usage_deferred_at(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<IngestOutcome>> + Send;

    /// [`ingest_usage_deferred`](Self::ingest_usage_deferred) with the sanity
    /// limit of savvagent/otto-platform#79: a metered event that would take the
    /// org's total of its meter in its billing month past `threshold` is not
    /// counted but kept in `usage_held_events` for an operator
    /// ([`IngestOutcome::Held`]). Its dedupe claim is kept, so a resend is a
    /// duplicate and it is held once. Only `POST /internal/usage` passes a
    /// threshold; the others count whatever they are given.
    fn ingest_usage_held(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        threshold: i64,
    ) -> impl std::future::Future<Output = Result<IngestOutcome>> + Send;

    /// [`ingest_usage_held`](Self::ingest_usage_held) as if the platform's
    /// clock read `now`. For tests of period boundaries only.
    #[doc(hidden)]
    fn ingest_usage_held_at(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        now: DateTime<Utc>,
        threshold: Option<i64>,
    ) -> impl std::future::Future<Output = Result<IngestOutcome>> + Send;

    fn current_usage(&mut self) -> impl std::future::Future<Output = Result<PeriodUsage>> + Send;

    /// This month's quantity of every meter `service` has declared, by key,
    /// zero for one with no usage yet. Only that service's meters.
    fn service_meter_usage(
        &mut self,
        service: &str,
    ) -> impl std::future::Future<Output = Result<Vec<MeterPeriodUsage>>> + Send;

    fn plan_limits(&mut self) -> impl std::future::Future<Output = Result<PlanLimits>> + Send;
}

impl UsageExt for Tx<'_> {
    /// Record one tool call and return the org's running totals.
    ///
    /// `user` is optional because a call can arrive on a token whose user has
    /// since been deleted; the event still belongs to the org, and losing the
    /// org's count to protect a foreign key would be the wrong trade.
    async fn record_usage(
        &mut self,
        user: Option<UserId>,
        tool: &str,
        billable: bool,
    ) -> Result<PeriodUsage> {
        let org = self.org();

        sqlx::query(
            "INSERT INTO usage_events (org_id, user_id, tool, billable) VALUES ($1,$2,$3,$4)",
        )
        .bind(org)
        .bind(user)
        .bind(tool)
        .bind(billable)
        .execute(self.conn())
        .await?;

        // Upsert rather than read-then-write: two concurrent calls in the same
        // org must both count, and only the database can arbitrate that. The
        // increment is expressed against the stored value, so it is correct
        // under any interleaving.
        let usage: PeriodUsage = sqlx::query_as(&format!(
            "INSERT INTO org_period_usage (org_id, period_start, billable_count, total_count) \
             VALUES ($1, {PERIOD}, $2, 1) \
             ON CONFLICT (org_id, period_start) DO UPDATE \
               SET billable_count = org_period_usage.billable_count + EXCLUDED.billable_count, \
                   total_count = org_period_usage.total_count + 1, \
                   updated_at = now() \
             RETURNING period_start, billable_count, total_count"
        ))
        .bind(org)
        .bind(i64::from(billable))
        .fetch_one(self.conn())
        .await?;

        Ok(usage)
    }

    /// The ledger claim, the `usage_events` insert, and the counter increment
    /// share this transaction, so a replay can never count twice: the claim
    /// (`claim_usage_event`, migration 0009) either says `new` and the rest
    /// lands with it, or says `duplicate` and nothing happens. It resolves in
    /// the database rather than in a read-then-write because two concurrent
    /// shippers of the same batch must not race.
    async fn ingest_usage_deferred(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
    ) -> Result<IngestOutcome> {
        self.ingest_usage_deferred_at(resource_uri, event, budgets, Utc::now())
            .await
    }

    async fn ingest_usage_deferred_at(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        now: DateTime<Utc>,
    ) -> Result<IngestOutcome> {
        self.ingest_usage_held_at(resource_uri, event, budgets, now, None)
            .await
    }

    async fn ingest_usage_held(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        threshold: i64,
    ) -> Result<IngestOutcome> {
        self.ingest_usage_held_at(resource_uri, event, budgets, Utc::now(), Some(threshold))
            .await
    }

    async fn ingest_usage_held_at(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
        budgets: &mut PendingBudgets,
        now: DateTime<Utc>,
        threshold: Option<i64>,
    ) -> Result<IngestOutcome> {
        let org = self.org();
        // Checked before the claim so a rejected event leaves no trace and can
        // be corrected and resent under the same id.
        if event.occurred_at < earliest_occurred_at(now) {
            return Ok(IngestOutcome::Rejected(
                "occurred_at is older than the start of the previous billing month",
            ));
        }
        if event.occurred_at > now + MAX_FUTURE_SKEW {
            return Ok(IngestOutcome::Rejected("occurred_at is in the future"));
        }

        let claim: String = sqlx::query_scalar("SELECT claim_usage_event($1, $2, $3)")
            .bind(resource_uri)
            .bind(event.event_id)
            .bind(org)
            .fetch_one(self.conn())
            .await?;
        match claim.as_str() {
            "new" => {}
            "duplicate" => return Ok(IngestOutcome::Duplicate),
            _ => {
                return Ok(IngestOutcome::Rejected(
                    "event_id was already used for a different org",
                ))
            }
        }

        // The sanity limit, after the claim so that a resend of an event that
        // was already counted (a duplicate, above) is never held, and a held
        // event stays claimed (a resend is a duplicate too). Judged against
        // the counters this transaction has written so far, so a batch is
        // cumulative; events arrive in billed order.
        if let (Some(threshold), Some(m)) = (threshold, event.metered) {
            let at = period::billed_at(event.occurred_at, now);
            let period_start = Month::of(at).first_day();
            let current: i64 = sqlx::query_scalar(
                "SELECT COALESCE((SELECT quantity FROM org_meter_period_usage \
                   WHERE org_id = $1 AND meter = $2 AND period_start = $3), 0)",
            )
            .bind(org)
            .bind(m.meter)
            .bind(period_start)
            .fetch_one(self.conn())
            .await?;
            let total = current.saturating_add(m.quantity);
            if total > threshold {
                let reason = format!(
                    "held_for_review: {total} of {} in the month starting {period_start} \
                     would pass the review threshold of {threshold}",
                    m.meter
                );
                sqlx::query(
                    "INSERT INTO usage_held_events \
                       (org_id, resource_uri, event_id, user_id, tool, billable, \
                        occurred_at, service, meter, quantity, period_start, reason) \
                     VALUES ($1, canonical_resource_uri($2::text), $3, \
                             (SELECT id FROM users WHERE id = $4), $5, $6, $7, $8, $9, \
                             $10, $11, $12) \
                     ON CONFLICT (resource_uri, event_id) DO NOTHING",
                )
                .bind(org)
                .bind(resource_uri)
                .bind(event.event_id)
                .bind(event.user)
                .bind(event.tool)
                .bind(event.billable)
                .bind(event.occurred_at)
                .bind(event.service)
                .bind(m.meter)
                .bind(m.quantity)
                .bind(period_start)
                .bind(&reason)
                .execute(self.conn())
                .await?;
                return Ok(IngestOutcome::Held(reason));
            }
        }

        // One statement after the claim, so an event costs two round trips
        // while this transaction holds the org's counter row locks.
        //
        // `user_id` is resolved through a subselect so an account deleted
        // since the event was written leaves it NULL instead of failing the
        // foreign key (the same trade `record_usage` documents).
        //
        // LOCK ORDER, within this statement. The three counter upserts and
        // the outbox upsert each lock one row, always in the same order: the
        // legacy `org_period_usage` row first, then the service's
        // `org_service_period_usage` row, then the meter's
        // `org_meter_period_usage` row, then the open `stripe_meter_outbox`
        // row. Data-modifying CTEs run in no guaranteed order on their own, so
        // the order is forced by data dependencies: `service` selects from
        // `legacy`'s RETURNING, `meter` cannot produce its row until it has
        // read both `legacy` and the completed `service`, and `stripe` waits
        // for the completed `meter`. Whoever retires the legacy bucket must
        // keep that chain (have `meter` read `service`), not just delete the
        // `legacy` CTE.
        //
        // This alone does NOT stop two transactions from deadlocking: the
        // rows are per period (and per service and meter), so two batches
        // holding events of different periods or meters lock different rows
        // in whatever order their events come. What prevents that is the
        // org's ingest lock ([`lock_org_ingest`]), which serializes batches
        // of one org; the caller also feeds events in billed order. A caller
        // that skips the lock (a single event in its own transaction) only
        // ever waits on another's rows, which is safe for one statement.
        //
        // `service` and `meter` insert nothing when $9 / $7 is NULL: an event
        // from a server with no slug counts only in the legacy bucket, and an
        // unmetered one adds to no meter. A metered event's quantity counts
        // whatever `billable` says (module docs).
        //
        // `stripe` adds the event to the org's open Stripe meter outbox row
        // for its event name, customer and hour ($11), or opens one, when it
        // is metered ($10 is its Stripe event name, NULL otherwise) and the
        // org has a live subscription: a customer, and a subscription whose
        // status is one of $12, as `billing::live_subscription` reads it. An
        // org with none inserts nothing, and the read costs no round trip.
        // It cannot fail the event: the values satisfy the table's checks by
        // construction (`stripe_outbox::enqueue_event_name`, an hour bucket,
        // a quantity far below `stripe_outbox::MAX_ADDITION` added to a row
        // at most `OPEN_ROW_MAX_VALUE`), and it reads `subscriptions` without
        // locking it. The event is new (the claim above just said so), so it
        // is added exactly once. A new row is first due when its hour ends.
        //
        // The final SELECT reads the service's budget for a metered event
        // (no row otherwise, or with no budget), and the highest threshold
        // already fired for the event's period, so the budget step costs
        // nothing for the common case and nothing once 100% has fired. It
        // reads, it does not lock.
        // The instant it is billed at: when it happened, or now for an event
        // of a closed period (module docs).
        let at = period::billed_at(event.occurred_at, now);
        let bucket = period::hour_bucket(at);
        let (meter, quantity) = match event.metered {
            Some(m) => (Some(m.meter), Some(m.quantity)),
            None => (None, None),
        };
        // An hour already too old for Stripe is not queued (see
        // `stripe_outbox`): it would only expire.
        let event_name =
            stripe_outbox::enqueue_event_name(event.service, event.metered, bucket, now);
        let budget: Option<crate::budgets::IngestBudget> = sqlx::query_as(&INGEST_SQL)
            .bind(org)
            .bind(event.user)
            .bind(event.tool)
            .bind(event.billable)
            .bind(at)
            .bind(resource_uri)
            .bind(meter)
            .bind(quantity)
            .bind(event.service)
            .bind(event_name)
            .bind(bucket)
            .bind(&LIVE_STATUSES[..])
            .fetch_optional(self.conn())
            .await?;

        // After the counters, in this same transaction: steps that read what
        // the event just counted. Each must leave a valid event counted
        // whatever happens to it (see `PendingBudgets::run`).
        //
        // Budget alerts, for a metered event of a service with a budget
        // only: an unmetered event adds no spend, so it can reach no
        // threshold. Noted here and run once per service and period before
        // commit. The period is the event's month, the one its counters were
        // written to.
        if let (Some(service), Some(budget)) = (event.service, budget) {
            budgets.note(service, Month::of(at), budget);
        }
        // The Stripe meter outbox row, if any, was written by the statement
        // above.
        Ok(IngestOutcome::Counted)
    }

    /// This month's totals, without recording anything.
    async fn current_usage(&mut self) -> Result<PeriodUsage> {
        let org = self.org();

        let row: Option<PeriodUsage> = sqlx::query_as(&format!(
            "SELECT period_start, billable_count, total_count FROM org_period_usage \
             WHERE org_id = $1 AND period_start = {PERIOD}"
        ))
        .bind(org)
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(usage) => Ok(usage),
            // No row yet this month. Zero is the honest answer, and reporting it
            // saves every caller from special-casing a missing row.
            None => {
                let period_start: chrono::NaiveDate =
                    sqlx::query_scalar(&format!("SELECT {PERIOD}"))
                        .fetch_one(self.conn())
                        .await?;
                Ok(PeriodUsage::empty(period_start))
            }
        }
    }

    /// `meters` is global reference data `otto_app` may read; the usage side
    /// is this org's rows only, through the pinned transaction's RLS.
    async fn service_meter_usage(&mut self, service: &str) -> Result<Vec<MeterPeriodUsage>> {
        let org = self.org();
        let rows = sqlx::query_as(&format!(
            "SELECT m.key AS meter, m.display_name, m.unit, \
                    COALESCE(u.quantity, 0) AS quantity \
             FROM meters m \
             LEFT JOIN org_meter_period_usage u \
               ON u.meter = m.key AND u.org_id = $1 AND u.period_start = {PERIOD} \
             WHERE m.service = $2 \
             ORDER BY m.key"
        ))
        .bind(org)
        .bind(service)
        .fetch_all(self.conn())
        .await?;
        Ok(rows)
    }

    /// The org's plan and its bucket.
    ///
    /// `included_ops` comes from the `plans` table so a bucket can be adjusted
    /// without a deploy, and a subscription's `included_ops_override` wins over
    /// it so an enterprise contract does not need a new plan row.
    async fn plan_limits(&mut self) -> Result<PlanLimits> {
        let org = self.org();

        let limits: Option<PlanLimits> = sqlx::query_as(
            "SELECT p.plan, p.display_name, \
                    COALESCE(s.included_ops_override, p.included_ops) AS included_ops, \
                    p.hard_stop, p.features \
             FROM orgs o \
             JOIN plans p ON p.plan = o.plan \
             LEFT JOIN subscriptions s ON s.org_id = o.id \
             WHERE o.id = $1",
        )
        .bind(org)
        .fetch_optional(self.conn())
        .await?;

        limits.ok_or(Error::OrgNotFound(org))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn the_window_opens_at_the_start_of_the_previous_month() {
        let at = |y, m, d| Utc.with_ymd_and_hms(y, m, d, 13, 30, 0).unwrap();
        let start = |y, m| Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).unwrap();
        assert_eq!(earliest_occurred_at(at(2026, 10, 7)), start(2026, 9));
        assert_eq!(earliest_occurred_at(at(2026, 10, 1)), start(2026, 9));
        assert_eq!(earliest_occurred_at(at(2026, 1, 31)), start(2025, 12));
        assert_eq!(earliest_occurred_at(at(2026, 3, 31)), start(2026, 2));
    }

    const EVALS: &str = "otto-flags/evaluations";

    fn declared() -> HashSet<String> {
        [EVALS.to_owned()].into()
    }

    /// `check_metering` for a shipper with service `caller`, which declared
    /// [`EVALS`] (ignored when `caller` is `None`, as in production).
    fn check(
        caller: Option<&str>,
        service: Option<&str>,
        meter: Option<&str>,
        quantity: Option<u64>,
    ) -> std::result::Result<Option<(String, i64)>, MeteringRejection> {
        let declared = if caller.is_some() {
            declared()
        } else {
            HashSet::new()
        };
        check_metering(
            &Shipper {
                service: caller,
                declared: &declared,
            },
            MeteringFields {
                service,
                meter,
                quantity,
            },
        )
        .map(|m| m.map(|m| (m.meter.to_owned(), m.quantity)))
    }

    fn code<T: fmt::Debug>(r: std::result::Result<T, MeteringRejection>) -> &'static str {
        r.unwrap_err().code
    }

    const FLAGS: Option<&str> = Some("otto-flags");

    #[test]
    fn an_unmetered_event_is_free_and_needs_no_service() {
        assert_eq!(check(None, None, None, None), Ok(None));
        assert_eq!(check(FLAGS, None, None, None), Ok(None));
        assert_eq!(check(FLAGS, FLAGS, None, None), Ok(None));
    }

    #[test]
    fn a_declared_meter_counts_its_quantity_or_one() {
        assert_eq!(
            check(FLAGS, None, Some(EVALS), Some(7)),
            Ok(Some((EVALS.to_owned(), 7)))
        );
        assert_eq!(
            check(FLAGS, FLAGS, Some(EVALS), None),
            Ok(Some((EVALS.to_owned(), 1)))
        );
    }

    #[test]
    fn an_undeclared_meter_is_unknown() {
        assert_eq!(
            code(check(FLAGS, None, Some("otto-flags/other"), Some(1))),
            UNKNOWN_METER
        );
        // A server with no slug cannot have declared anything.
        assert_eq!(code(check(None, None, Some(EVALS), Some(1))), UNKNOWN_METER);
        // Another service's key is never this caller's, whatever `declared`
        // holds.
        let declared = declared();
        let cxp = Shipper {
            service: Some("otto-cxp"),
            declared: &declared,
        };
        let fields = MeteringFields {
            meter: Some(EVALS),
            ..Default::default()
        };
        assert_eq!(code(check_metering(&cxp, fields)), UNKNOWN_METER);
        // An absurd key is echoed bounded.
        let long = format!("otto-flags/{}", "é".repeat(500));
        let r = check(FLAGS, None, Some(&long), Some(1)).unwrap_err();
        assert!(r.detail.len() < MAX_ECHOED_METER + 100, "{}", r.detail);
    }

    #[test]
    fn a_service_other_than_the_shippers_is_a_mismatch() {
        let cxp = Some("otto-cxp");
        assert_eq!(
            code(check(FLAGS, cxp, Some(EVALS), Some(1))),
            SERVICE_MISMATCH
        );
        assert_eq!(code(check(None, FLAGS, None, None)), SERVICE_MISMATCH);
        // Checked for unmetered events too.
        assert_eq!(code(check(FLAGS, cxp, None, None)), SERVICE_MISMATCH);
    }

    #[test]
    fn quantity_bounds() {
        let q = |n| check(FLAGS, None, Some(EVALS), Some(n));
        assert_eq!(code(q(0)), INVALID_QUANTITY);
        assert_eq!(code(q(MAX_METER_QUANTITY + 1)), INVALID_QUANTITY);
        assert_eq!(code(q(u64::MAX)), INVALID_QUANTITY);
        assert_eq!(q(1), Ok(Some((EVALS.to_owned(), 1))));
        assert_eq!(
            q(MAX_METER_QUANTITY),
            Ok(Some((EVALS.to_owned(), 1_000_000_000)))
        );
        assert_eq!(code(check(FLAGS, None, None, Some(1))), INVALID_QUANTITY);
    }

    #[test]
    fn a_rejection_reads_code_first() {
        let r = reject(UNKNOWN_METER, "x");
        assert_eq!(r.to_string(), "unknown_meter: x");
    }
}
