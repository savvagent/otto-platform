//! Per-service monthly budgets, their alerts, and the hard stop
//! (savvagent/otto-platform#63, epic #55).
//!
//! An org's owners and admins may give any service that has declared meters a
//! **monthly budget** in US cents (`service_budgets`, migration 0022). A
//! service's **spend** in a period is what its meters cost that period:
//! [`service_spend`], the sum over its meters of the price book's
//! [`rate`] of each meter's quantity against the tiers in effect for that
//! period. An unpriced meter, and an unmetered event, contribute nothing.
//! The period is the UTC calendar month, as everywhere in metering.
//!
//! **Alerts.** When a service's spend first reaches 50, 80 or 100% of its
//! budget in a period, ingest records the threshold in `budget_alerts` and
//! queues one email to every active owner and admin, in the ingest
//! transaction ([`PendingBudgets`]). The primary key of `budget_alerts` makes
//! each threshold fire exactly once per service and period, however many
//! events cross it at once or concurrently. A budget lowered mid-period can
//! put spend past several thresholds at once; each fires once, in one email.
//! Alert rows are kept when a budget is changed or cleared, so a threshold
//! never fires twice in a period, even after the budget is raised.
//!
//! **The hard stop** is opt-in. With it set and spend at or past the budget,
//! the service's own usage-status reports `blocked` with reason
//! [`BUDGET_EXCEEDED`], and the resource server refuses new billable calls.
//! The platform itself never refuses ingest: usage already done is counted.
//! A budget is per service, so a stop on one service never blocks another.
//!
//! **Budgets never break ingest.** The alert step runs inside a savepoint of
//! the ingest transaction; any failure in it is logged and rolled back to the
//! savepoint, leaving the events counted. The alert row and its emails roll
//! back together, so an alert whose emails could not be queued is retried by
//! the next ingest rather than recorded without mail.
//!
//! **No way to pay, no billable usage.** An org that is not in good standing
//! to pay (no subscription, a failed payment past its grace; see
//! [`crate::billing::gate`]) whose spend on a service this period is above
//! zero (past the service's free tiers) must add a payment method: that
//! service's usage-status reports reason [`PAYMENT_REQUIRED`] and the
//! resource server refuses new billable calls; other services, and free
//! calls, are unaffected. A budget's hard stop wins when both apply. While no
//! price is set, spend is zero everywhere and this blocks no one. The one
//! function that decides the reason is
//! [`crate::billing::gate::blocked_reason`].
//!
//! **Spend can be unknown.** A price version the rater refuses, or a total
//! that overflows, makes a service's spend uncomputable. Readers degrade that
//! service only ([`ServiceBudgetStatus::spend_cents`] is `None`) and never
//! block on it: enforcement fails open.
//!
//! ```
//! use otto_billing::budgets::{percent_used, thresholds_reached_at};
//!
//! // $8.00 spent of a $10.00 budget.
//! assert_eq!(percent_used(800, 1_000), 80);
//! assert_eq!(thresholds_reached_at(800, 1_000), [50, 80]);
//! // Spend can pass the budget.
//! assert_eq!(percent_used(2_550, 1_000), 255);
//! assert_eq!(thresholds_reached_at(2_550, 1_000), [50, 80, 100]);
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};
use otto_core::notifications;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Tx;
use sqlx::FromRow;

use crate::pricebook::{self, rate, Month, RateError, Tiers};

/// The alert thresholds, in percent of the budget, ascending.
pub const THRESHOLDS: [u8; 3] = [50, 80, 100];

/// The largest monthly budget, in cents ($10,000,000). Also the
/// `service_budgets_cents_range` check in migration 0022.
pub const MAX_MONTHLY_BUDGET_CENTS: i64 = 1_000_000_000;

/// The reason a hard-stopped service reports when spend has reached its
/// budget. `otto_resource::BUDGET_EXCEEDED` is the wire contract's copy.
pub const BUDGET_EXCEEDED: &str = "budget_exceeded";

/// The reason usage-status gives when the org is not in good standing to
/// pay ([`crate::billing::gate`]) and a service's spend this period is above
/// zero.
/// `otto_resource::PAYMENT_REQUIRED` is the wire contract's copy.
pub const PAYMENT_REQUIRED: &str = "payment_required";

/// The reason usage-status gives when a budgeted service's spend cannot be
/// computed. Never blocks. `otto_resource::SPEND_UNAVAILABLE` is the wire
/// contract's copy.
pub const SPEND_UNAVAILABLE: &str = "spend_unavailable";

/// The console's `spendError` when a service's spend cannot be computed.
pub const PRICING_UNAVAILABLE: &str = "pricing_unavailable";

/// Audit actions for budget changes.
pub mod actions {
    /// An owner or admin set or changed a service's budget.
    pub const SET: &str = "billing.budget.set";
    /// An owner or admin removed a service's budget.
    pub const CLEARED: &str = "billing.budget.cleared";
}

/// A budget failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The service has no declared meters, so there is nothing to budget.
    #[error("no service {0:?} with declared meters")]
    UnknownService(String),
    #[error("a monthly budget must be 1 to {MAX_MONTHLY_BUDGET_CENTS} cents")]
    OutOfRange,
    /// [`service_spend`] was asked about an org other than its transaction's.
    #[error("the transaction is pinned to another org")]
    WrongOrg,
    #[error("a service's spend overflows")]
    Overflow,
    #[error(transparent)]
    Price(#[from] pricebook::Error),
    #[error(transparent)]
    Rate(#[from] RateError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Core(#[from] otto_core::error::Error),
}

impl Error {
    /// Whether the database failed, as opposed to the data: a caller that
    /// can degrade on bad data (a malformed price) should still fail on this.
    pub fn is_database(&self) -> bool {
        use otto_core::error::Error as Core;
        matches!(
            self,
            Error::Db(_)
                | Error::Price(pricebook::Error::Db(_))
                | Error::Core(Core::Db(_) | Core::Tenant(_))
        )
    }
}

/// A budget result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Whether `s` is a service slug: `^[a-z][a-z0-9-]{0,62}$`, the
/// `resource_servers_service_slug` check of migration 0017. Anything else
/// names no service, so callers can refuse it before touching the database.
///
/// ```
/// use otto_billing::budgets::is_service_slug;
///
/// assert!(is_service_slug("otto-flags"));
/// assert!(!is_service_slug("otto-flags/evaluations"));
/// assert!(!is_service_slug(&"a".repeat(64)));
/// ```
pub fn is_service_slug(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && s.len() <= 63
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// One service's budget, as `service_budgets` holds it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Budget {
    pub service: String,
    /// 1 to [`MAX_MONTHLY_BUDGET_CENTS`].
    pub monthly_budget_cents: i64,
    /// Refuse billable calls once spend reaches the budget.
    pub hard_stop: bool,
    /// Who last set it; `None` once that account is gone.
    pub updated_by: Option<UserId>,
    pub updated_at: DateTime<Utc>,
}

impl Budget {
    /// Whether billable calls must be refused at `spend_cents`: only with the
    /// hard stop on and spend at or past the budget.
    pub fn blocks_at(&self, spend_cents: i64) -> bool {
        self.hard_stop && spend_cents >= self.monthly_budget_cents
    }
}

/// Where one service stands against its budget in one period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBudgetStatus {
    pub service: String,
    pub period: Month,
    /// [`service_spend`] for the period, or `None` when it cannot be
    /// computed (a malformed price version, an overflow). Logged when it
    /// happens; never blocks.
    pub spend_cents: Option<i64>,
    /// The thresholds whose alerts have fired this period, ascending. Kept
    /// when the budget changes, so it can list a threshold the current budget
    /// is not at.
    pub thresholds_reached: Vec<u8>,
    /// `None` when no budget is set.
    pub budget: Option<Budget>,
}

impl ServiceBudgetStatus {
    /// [`percent_used`] of the budget: `None` with no budget, or when spend
    /// is unknown.
    pub fn percent_used(&self) -> Option<i64> {
        let spend = self.spend_cents?;
        self.budget
            .as_ref()
            .map(|b| percent_used(spend, b.monthly_budget_cents))
    }

    /// Whether billable calls must be refused. Never with no budget, and
    /// never when spend is unknown (fail open).
    pub fn blocked(&self) -> bool {
        match (self.budget.as_ref(), self.spend_cents) {
            (Some(b), Some(spend)) => b.blocks_at(spend),
            _ => false,
        }
    }
}

/// Whole percent of `budget_cents` that `spend_cents` is, rounded down. Can
/// exceed 100. A non-positive budget (which the table forbids) reads as
/// `i64::MAX` rather than dividing by zero.
pub fn percent_used(spend_cents: i64, budget_cents: i64) -> i64 {
    if budget_cents <= 0 {
        return i64::MAX;
    }
    let pct = i128::from(spend_cents.max(0)) * 100 / i128::from(budget_cents);
    i64::try_from(pct).unwrap_or(i64::MAX)
}

/// The [`THRESHOLDS`] that `spend_cents` has reached against `budget_cents`,
/// ascending. Exact: compared in cents, not through a rounded percentage.
pub fn thresholds_reached_at(spend_cents: i64, budget_cents: i64) -> Vec<u8> {
    THRESHOLDS
        .into_iter()
        .filter(|&t| {
            i128::from(spend_cents) * 100 >= i128::from(t) * i128::from(budget_cents.max(1))
        })
        .collect()
}

/// The tiers in effect per `(meter, period)`, as read so far. `None` is a
/// meter with no price in effect.
type TierCache = HashMap<(String, Month), Option<Tiers>>;

/// What `service`'s meters cost `org` in `period`, in whole US cents.
///
/// The sum, over the service's meters with usage in `period`
/// (`org_meter_period_usage`), of [`rate`] of the meter's quantity against
/// the tiers in effect for `period` ([`pricebook::tiers_in_effect`]), each
/// line rounded as [`rate`] rounds it. A past period is rated with that
/// period's prices. An unpriced meter adds 0.
///
/// `tx` must be pinned to `org` ([`Error::WrongOrg`] otherwise): spend is
/// tenant data, read through the pinned transaction's row-level security.
pub async fn service_spend(
    tx: &mut Tx<'_>,
    org: OrgId,
    service: &str,
    period: Month,
) -> Result<i64> {
    service_spend_cached(tx, org, service, period, &mut TierCache::new()).await
}

async fn service_spend_cached(
    tx: &mut Tx<'_>,
    org: OrgId,
    service: &str,
    period: Month,
    tiers: &mut TierCache,
) -> Result<i64> {
    if tx.org() != org {
        return Err(Error::WrongOrg);
    }
    let lines: Vec<(String, i64)> = sqlx::query_as(
        "SELECT u.meter, u.quantity FROM org_meter_period_usage u \
         JOIN meters m ON m.key = u.meter \
         WHERE u.org_id = $1 AND m.service = $2 AND u.period_start = $3 AND u.quantity > 0 \
         ORDER BY u.meter",
    )
    .bind(org)
    .bind(service)
    .bind(period.first_day())
    .fetch_all(tx.conn())
    .await?;

    let mut total: i64 = 0;
    for (meter, quantity) in lines {
        let key = (meter, period);
        if !tiers.contains_key(&key) {
            let version = pricebook::tiers_in_effect(tx.conn(), &key.0, period).await?;
            tiers.insert(key.clone(), version.map(|v| v.tiers));
        }
        let line = rate(quantity, tiers[&key].as_ref())?;
        total = total.checked_add(line.cents()).ok_or(Error::Overflow)?;
    }
    Ok(total)
}

/// Every service with declared meters, by slug: the services an org can
/// budget.
pub async fn budgetable_services(tx: &mut Tx<'_>) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT DISTINCT service FROM meters ORDER BY service")
            .fetch_all(tx.conn())
            .await?,
    )
}

async fn has_meters(tx: &mut Tx<'_>, service: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM meters WHERE service = $1)")
            .bind(service)
            .fetch_one(tx.conn())
            .await?,
    )
}

const BUDGET_COLS: &str = "service, monthly_budget_cents, hard_stop, updated_by, updated_at";

/// `service`'s budget in the transaction's org, if one is set.
pub async fn get_budget(tx: &mut Tx<'_>, service: &str) -> Result<Option<Budget>> {
    let org = tx.org();
    Ok(sqlx::query_as(&format!(
        "SELECT {BUDGET_COLS} FROM service_budgets WHERE org_id = $1 AND service = $2"
    ))
    .bind(org)
    .bind(service)
    .fetch_optional(tx.conn())
    .await?)
}

/// The thresholds that have fired for `service` in `period`, ascending.
pub async fn fired_thresholds(tx: &mut Tx<'_>, service: &str, period: Month) -> Result<Vec<u8>> {
    let org = tx.org();
    let fired: Vec<i16> = sqlx::query_scalar(
        "SELECT threshold FROM budget_alerts \
         WHERE org_id = $1 AND service = $2 AND period_start = $3 ORDER BY threshold",
    )
    .bind(org)
    .bind(service)
    .bind(period.first_day())
    .fetch_all(tx.conn())
    .await?;
    // The column's check admits only THRESHOLDS, which all fit.
    Ok(fired
        .into_iter()
        .filter_map(|t| u8::try_from(t).ok())
        .collect())
}

/// Where `service` stands against its budget in `period`, in the
/// transaction's org. Answers for any service, budgeted or not.
///
/// A data fault in the spend (a malformed price, an overflow) is logged and
/// reported as `spend_cents: None`; only a database error fails the call.
pub async fn service_status(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
) -> Result<ServiceBudgetStatus> {
    let org = tx.org();
    let budget = get_budget(tx, service).await?;
    let spend_cents = match service_spend(tx, org, service, period).await {
        Ok(cents) => Some(cents),
        Err(e) if e.is_database() => return Err(e),
        Err(e) => {
            report_fault(
                org,
                service,
                period,
                &e,
                "budget spend could not be computed",
            );
            None
        }
    };
    let thresholds_reached = fired_thresholds(tx, service, period).await?;
    Ok(ServiceBudgetStatus {
        service: service.to_owned(),
        period,
        spend_cents,
        thresholds_reached,
        budget,
    })
}

/// [`service_status`] for every service with declared meters, by slug.
pub async fn org_status(tx: &mut Tx<'_>, period: Month) -> Result<Vec<ServiceBudgetStatus>> {
    let services = budgetable_services(tx).await?;
    let mut out = Vec::with_capacity(services.len());
    for service in services {
        out.push(service_status(tx, &service, period).await?);
    }
    Ok(out)
}

/// Set (or replace) `service`'s budget in the transaction's org, as `actor`.
///
/// [`Error::OutOfRange`] unless `monthly_budget_cents` is 1 to
/// [`MAX_MONTHLY_BUDGET_CENTS`]; [`Error::UnknownService`] unless the
/// service has declared meters. The caller audits ([`actions::SET`]) in the
/// same transaction.
pub async fn set_budget(
    tx: &mut Tx<'_>,
    service: &str,
    monthly_budget_cents: i64,
    hard_stop: bool,
    actor: UserId,
) -> Result<Budget> {
    if !(1..=MAX_MONTHLY_BUDGET_CENTS).contains(&monthly_budget_cents) {
        return Err(Error::OutOfRange);
    }
    if !has_meters(tx, service).await? {
        return Err(Error::UnknownService(service.to_owned()));
    }
    let org = tx.org();
    Ok(sqlx::query_as(&format!(
        "INSERT INTO service_budgets \
           (org_id, service, monthly_budget_cents, hard_stop, updated_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (org_id, service) DO UPDATE SET \
           monthly_budget_cents = EXCLUDED.monthly_budget_cents, \
           hard_stop = EXCLUDED.hard_stop, \
           updated_by = EXCLUDED.updated_by, \
           updated_at = now() \
         RETURNING {BUDGET_COLS}"
    ))
    .bind(org)
    .bind(service)
    .bind(monthly_budget_cents)
    .bind(hard_stop)
    .bind(actor)
    .fetch_one(tx.conn())
    .await?)
}

/// Remove `service`'s budget in the transaction's org, returning it, or
/// `None` when none was set. [`Error::UnknownService`] unless the service
/// has declared meters. The caller audits ([`actions::CLEARED`]).
pub async fn clear_budget(tx: &mut Tx<'_>, service: &str) -> Result<Option<Budget>> {
    if !has_meters(tx, service).await? {
        return Err(Error::UnknownService(service.to_owned()));
    }
    let org = tx.org();
    Ok(sqlx::query_as(&format!(
        "DELETE FROM service_budgets WHERE org_id = $1 AND service = $2 RETURNING {BUDGET_COLS}"
    ))
    .bind(org)
    .bind(service)
    .fetch_optional(tx.conn())
    .await?)
}

// ------------------------------------------------------------------ faults

/// The `(org, service, period)`s whose data faults this process has logged
/// at error level. A fault that persists (a malformed price) would otherwise
/// log on every event and every read.
static REPORTED: OnceLock<Mutex<HashSet<(OrgId, String, Month)>>> = OnceLock::new();

/// How many distinct faults are remembered before the set starts over.
const MAX_REPORTED: usize = 10_000;

/// Log a data fault at error level the first time this process sees it for
/// `(org, service, period)`, and at debug level after that.
fn report_fault(org: OrgId, service: &str, period: Month, e: &Error, what: &str) {
    let first = {
        let mut seen = REPORTED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() >= MAX_REPORTED {
            seen.clear();
        }
        seen.insert((org, service.to_owned(), period))
    };
    if first {
        tracing::error!(error = %e, org = %org, service, period = %period, "{what}");
    } else {
        tracing::debug!(error = %e, org = %org, service, period = %period, "{what}");
    }
}

// ------------------------------------------------------------------ ingest

/// A service's budget as ingest reads it, returned by each event's own
/// counter statement so that an event for a service with no budget costs no
/// extra query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub(crate) struct IngestBudget {
    pub monthly_budget_cents: i64,
    pub hard_stop: bool,
    /// The highest threshold already fired for the event's service and
    /// period, if any.
    pub max_fired: Option<i16>,
}

/// The budget step of one ingest transaction, collected per event and run
/// once per `(service, period)` before commit.
///
/// [`crate::usage::UsageExt::ingest_usage_deferred`] notes each budgeted
/// service and period an event touched; [`PendingBudgets::run`] then rates
/// each one once, however many events touched it, reusing the tiers it read
/// for each `(meter, period)`. A service whose 100% alert has already fired
/// is not noted at all: nothing more can fire for it that period.
///
/// ```no_run
/// # async fn f(db: otto_tenant::Db, org: otto_tenant::ids::OrgId,
/// #            events: Vec<otto_billing::usage::ShippedUsage<'_>>) {
/// use otto_billing::budgets::PendingBudgets;
/// use otto_billing::usage::UsageExt;
///
/// let mut tx = db.begin(org).await.unwrap();
/// let mut budgets = PendingBudgets::default();
/// for event in &events {
///     tx.ingest_usage_deferred("https://svc.example/mcp", event, &mut budgets)
///         .await
///         .unwrap();
/// }
/// budgets.run(&mut tx).await.unwrap();
/// tx.commit().await.unwrap();
/// # }
/// ```
#[derive(Debug, Default)]
#[must_use = "budget alerts never fire unless `run` is called before commit"]
pub struct PendingBudgets {
    touched: BTreeMap<(String, Month), IngestBudget>,
    tiers: TierCache,
}

impl PendingBudgets {
    /// Note that an event counted for `service` in `period`, whose budget is
    /// `budget`. Ignored once 100% has fired.
    pub(crate) fn note(&mut self, service: &str, period: Month, budget: IngestBudget) {
        if budget.max_fired.is_some_and(|t| t >= 100) {
            return;
        }
        self.touched.insert((service.to_owned(), period), budget);
    }

    /// Whether no step is pending.
    pub fn is_empty(&self) -> bool {
        self.touched.is_empty()
    }

    /// Run the budget step once for each `(service, period)` noted since the
    /// last run, in `tx`, before it commits. Returns how many steps ran.
    ///
    /// Each step rates the service's spend for the period (a few rows), and
    /// only when a threshold is reached does it write: an `INSERT … ON
    /// CONFLICT DO NOTHING RETURNING` into `budget_alerts`, and one email per
    /// active owner and admin for the thresholds that insert newly recorded.
    ///
    /// **It never fails the events.** Each step runs in a savepoint; an error
    /// is logged and rolled back to it, taking the step's alert rows and
    /// emails with it, so the next ingest retries the alert. An address the
    /// outbox refuses is skipped on its own. Only a failure of the savepoint
    /// commands themselves (a broken connection, which the events' own writes
    /// could not survive either) is returned.
    ///
    /// **Lock order.** It runs after every event's counter upserts, so it
    /// extends the order [`crate::usage`] documents (legacy, service, meter)
    /// with `budget_alerts` last. Two ingests of the same org and period are
    /// already serialized by the legacy `org_period_usage` row, which each
    /// holds until commit, so they cannot interleave here.
    pub async fn run(&mut self, tx: &mut Tx<'_>) -> otto_core::error::Result<usize> {
        let touched = std::mem::take(&mut self.touched);
        let steps = touched.len();
        for ((service, period), budget) in touched {
            sqlx::query("SAVEPOINT budget_alerts")
                .execute(tx.conn())
                .await?;
            if let Err(e) = fire_alerts(tx, &service, period, budget, &mut self.tiers).await {
                let what = "budget alert step failed; the usage events are still counted";
                if e.is_database() {
                    tracing::error!(error = %e, org = %tx.org(), service, period = %period, "{what}");
                } else {
                    report_fault(tx.org(), &service, period, &e, what);
                }
                sqlx::query("ROLLBACK TO SAVEPOINT budget_alerts")
                    .execute(tx.conn())
                    .await?;
            }
            sqlx::query("RELEASE SAVEPOINT budget_alerts")
                .execute(tx.conn())
                .await?;
        }
        Ok(steps)
    }
}

async fn fire_alerts(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
    budget: IngestBudget,
    tiers: &mut TierCache,
) -> Result<()> {
    let org = tx.org();
    let spend = service_spend_cached(tx, org, service, period, tiers).await?;
    let reached: Vec<i16> = thresholds_reached_at(spend, budget.monthly_budget_cents)
        .into_iter()
        .map(i16::from)
        .filter(|&t| budget.max_fired.is_none_or(|fired| t > fired))
        .collect();
    if reached.is_empty() {
        return Ok(());
    }
    let fired: Vec<i16> = sqlx::query_scalar(
        "INSERT INTO budget_alerts (org_id, service, period_start, threshold) \
         SELECT $1, $2, $3, t FROM unnest($4::smallint[]) AS t \
         ON CONFLICT (org_id, service, period_start, threshold) DO NOTHING \
         RETURNING threshold",
    )
    .bind(org)
    .bind(service)
    .bind(period.first_day())
    .bind(&reached)
    .fetch_all(tx.conn())
    .await?;
    let Some(highest) = fired.iter().max().and_then(|&t| u8::try_from(t).ok()) else {
        return Ok(());
    };

    let (slug, recipients) = alert_recipients(tx).await?;
    let alert = AlertEmail {
        service,
        org_slug: &slug,
        period,
        threshold: highest,
        spend_cents: spend,
        budget_cents: budget.monthly_budget_cents,
        hard_stop: budget.hard_stop,
    };
    let subject = alert.subject();
    let body = alert.body();
    for to in &recipients {
        match notifications::enqueue_email(tx, to, &subject, &body).await {
            Ok(_) => {}
            // The address, not the outbox: skip it, mail the rest.
            Err(e @ otto_core::error::Error::Invalid(_)) => {
                tracing::warn!(error = %e, service, "budget alert email skipped");
            }
            // The database: fail the step, so the alert row rolls back with
            // the emails and the next ingest tries again.
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The org's slug, and the addresses of its active owners and admins.
async fn alert_recipients(tx: &mut Tx<'_>) -> Result<(String, Vec<String>)> {
    let org = tx.org();
    let slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org)
        .fetch_one(tx.conn())
        .await?;
    let recipients = sqlx::query_scalar(
        "SELECT DISTINCT u.email FROM org_members m JOIN users u ON u.id = m.user_id \
         WHERE m.org_id = $1 AND m.role IN ('owner', 'admin') \
           AND u.disabled_at IS NULL AND u.email IS NOT NULL \
         ORDER BY u.email",
    )
    .bind(org)
    .fetch_all(tx.conn())
    .await?;
    Ok((slug, recipients))
}

/// One budget alert email. English only for now: recipients' locales are a
/// follow-up.
#[derive(Debug, Clone)]
struct AlertEmail<'a> {
    service: &'a str,
    org_slug: &'a str,
    period: Month,
    /// The highest threshold newly reached.
    threshold: u8,
    spend_cents: i64,
    budget_cents: i64,
    hard_stop: bool,
}

impl AlertEmail<'_> {
    /// One line: the service and org slugs are `[a-z0-9-]` by construction.
    fn subject(&self) -> String {
        format!(
            "{} has reached {}% of its monthly budget in {}",
            self.service, self.threshold, self.org_slug
        )
    }

    fn body(&self) -> String {
        let stop = if self.hard_stop {
            format!(
                "Hard stop is on: once spend reaches the budget, {} refuses billable calls \
                 until the month ends or the budget is raised. Free calls keep working.",
                self.service
            )
        } else {
            format!(
                "Hard stop is off: {} keeps working past the budget, and usage over it is \
                 billed.",
                self.service
            )
        };
        format!(
            "{service} has used {pct}% of its monthly budget in the {org} organization.\n\
             \n\
             Spend in {period} (UTC): {spend}\n\
             Monthly budget: {budget}\n\
             \n\
             {stop}\n\
             \n\
             You are receiving this because you are an owner or admin of {org}. Owners and \
             admins can change or remove the budget in the Otto console.\n",
            service = self.service,
            pct = percent_used(self.spend_cents, self.budget_cents),
            org = self.org_slug,
            period = self.period,
            spend = dollars(self.spend_cents),
            budget = dollars(self.budget_cents),
        )
    }
}

/// `$12.34`, for a non-negative amount in cents.
fn dollars(cents: i64) -> String {
    let cents = cents.max(0);
    format!("${}.{:02}", cents / 100, cents % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_is_floored_and_can_pass_100() {
        assert_eq!(percent_used(0, 1_000), 0);
        assert_eq!(percent_used(499, 1_000), 49);
        assert_eq!(percent_used(500, 1_000), 50);
        assert_eq!(percent_used(1_000, 1_000), 100);
        assert_eq!(percent_used(3_333, 1_000), 333);
        assert_eq!(percent_used(1, 3), 33);
        assert_eq!(percent_used(i64::MAX, 1), i64::MAX);
        assert_eq!(percent_used(5, 0), i64::MAX);
    }

    #[test]
    fn thresholds_are_compared_exactly() {
        assert!(thresholds_reached_at(0, 1_000).is_empty());
        assert!(thresholds_reached_at(499, 1_000).is_empty());
        assert_eq!(thresholds_reached_at(500, 1_000), [50]);
        assert_eq!(thresholds_reached_at(799, 1_000), [50]);
        assert_eq!(thresholds_reached_at(800, 1_000), [50, 80]);
        assert_eq!(thresholds_reached_at(999, 1_000), [50, 80]);
        assert_eq!(thresholds_reached_at(1_000, 1_000), [50, 80, 100]);
        // 50% of 3 cents is 1.5: 1 cent has not reached it, 2 have.
        assert!(thresholds_reached_at(1, 3).is_empty());
        assert_eq!(thresholds_reached_at(2, 3), [50]);
        assert_eq!(
            thresholds_reached_at(i64::MAX, MAX_MONTHLY_BUDGET_CENTS),
            [50, 80, 100]
        );
    }

    #[test]
    fn service_slugs() {
        for ok in ["a", "otto-flags", "x1-2", &"a".repeat(63)] {
            assert!(is_service_slug(ok), "{ok}");
        }
        for bad in [
            "",
            "1a",
            "-a",
            "A",
            "otto_flags",
            "a/b",
            "a.b",
            &"a".repeat(64),
        ] {
            assert!(!is_service_slug(bad), "{bad}");
        }
    }

    fn budget(cents: i64, hard_stop: bool) -> Budget {
        Budget {
            service: "otto-flags".into(),
            monthly_budget_cents: cents,
            hard_stop,
            updated_by: None,
            updated_at: Utc::now(),
        }
    }

    fn status(spend: Option<i64>, b: Option<Budget>) -> ServiceBudgetStatus {
        ServiceBudgetStatus {
            service: "otto-flags".into(),
            period: Month::new(2026, 10).unwrap(),
            spend_cents: spend,
            thresholds_reached: vec![],
            budget: b,
        }
    }

    #[test]
    fn only_a_hard_stop_at_or_past_the_budget_blocks() {
        assert!(!budget(1_000, false).blocks_at(5_000));
        assert!(!budget(1_000, true).blocks_at(999));
        assert!(budget(1_000, true).blocks_at(1_000));
        assert!(
            !status(Some(10_000), None).blocked(),
            "no budget never blocks"
        );
        assert_eq!(status(Some(10_000), None).percent_used(), None);
        let over = status(Some(10_000), Some(budget(1_000, true)));
        assert!(over.blocked());
        assert_eq!(over.percent_used(), Some(1_000));
        let unknown = status(None, Some(budget(1_000, true)));
        assert!(!unknown.blocked(), "unknown spend fails open");
        assert_eq!(unknown.percent_used(), None);
    }

    #[test]
    fn a_service_past_100_is_not_noted() {
        let mut p = PendingBudgets::default();
        let period = Month::new(2026, 10).unwrap();
        let b = |max_fired| IngestBudget {
            monthly_budget_cents: 1,
            hard_stop: false,
            max_fired,
        };
        p.note("otto-flags", period, b(Some(100)));
        assert!(p.is_empty());
        p.note("otto-flags", period, b(Some(80)));
        p.note("otto-flags", period, b(None));
        p.note("otto-cxp", period, b(None));
        assert_eq!(p.touched.len(), 2);
    }

    #[test]
    fn the_email_is_one_line_subject_and_plain_text() {
        let alert = AlertEmail {
            service: "otto-flags",
            org_slug: "acme",
            period: Month::new(2026, 10).unwrap(),
            threshold: 80,
            spend_cents: 812,
            budget_cents: 1_000,
            hard_stop: true,
        };
        assert_eq!(
            alert.subject(),
            "otto-flags has reached 80% of its monthly budget in acme"
        );
        let body = alert.body();
        assert!(body.contains("used 81%"), "{body}");
        assert!(body.contains("Spend in 2026-10 (UTC): $8.12"), "{body}");
        assert!(body.contains("Monthly budget: $10.00"), "{body}");
        assert!(body.contains("Hard stop is on"), "{body}");
        assert_eq!(dollars(5), "$0.05");
    }
}
