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
//! budget in a period, [`crate::usage::UsageExt::ingest_usage`] records the
//! threshold in `budget_alerts` and queues one email to every owner and admin,
//! in the ingest transaction. The unique key on
//! `budget_alerts` makes each threshold fire exactly once per service and
//! period, however many events cross it at once or concurrently. A budget
//! lowered mid-period can put spend past several thresholds at once; each
//! fires once, in one email. Alert rows are kept when a budget is changed or
//! cleared, so a threshold never fires twice in a period.
//!
//! **The hard stop** is opt-in. With it set and spend at or past the budget,
//! the service's own usage-status reports `blocked` with reason
//! [`BUDGET_EXCEEDED`], and the resource server refuses new billable calls.
//! The platform itself never refuses ingest: usage already done is counted.
//! A budget is per service, so a stop on one service never blocks another.
//!
//! **Budgets never break ingest.** Everything the alert step does runs inside
//! a savepoint of the ingest transaction; any failure in it is logged and
//! rolled back to the savepoint, leaving the event counted. A failure to queue
//! an email keeps the alert row, so the alert does not refire: the email is
//! lost, the alert is not.
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

use chrono::{DateTime, Utc};
use otto_core::notifications;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Tx;
use sqlx::FromRow;

use crate::pricebook::{self, rate, Month, RateError};

/// The alert thresholds, in percent of the budget, ascending.
pub const THRESHOLDS: [i16; 3] = [50, 80, 100];

/// The largest monthly budget, in cents ($10,000,000). Also the
/// `service_budgets_cents_range` check in migration 0022.
pub const MAX_MONTHLY_BUDGET_CENTS: i64 = 1_000_000_000;

/// The reason a hard-stopped service reports when spend has reached its
/// budget. `otto_resource::BUDGET_EXCEEDED` is the wire contract's copy.
pub const BUDGET_EXCEEDED: &str = "budget_exceeded";

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
}

impl Error {
    /// Whether the database failed, as opposed to the data: a caller that
    /// can degrade on bad data (a malformed price) should still fail on this.
    pub fn is_database(&self) -> bool {
        matches!(self, Error::Db(_) | Error::Price(pricebook::Error::Db(_)))
    }
}

/// A budget result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

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
    /// [`service_spend`] for the period.
    pub spend_cents: i64,
    /// The thresholds whose alerts have fired this period, ascending. Kept
    /// when the budget changes, so it can list a threshold the current budget
    /// is not at.
    pub thresholds_reached: Vec<i16>,
    /// `None` when no budget is set.
    pub budget: Option<Budget>,
}

impl ServiceBudgetStatus {
    /// [`percent_used`] of the budget, `None` with no budget.
    pub fn percent_used(&self) -> Option<i64> {
        self.budget
            .as_ref()
            .map(|b| percent_used(self.spend_cents, b.monthly_budget_cents))
    }

    /// Whether billable calls must be refused. Never with no budget.
    pub fn blocked(&self) -> bool {
        self.budget
            .as_ref()
            .is_some_and(|b| b.blocks_at(self.spend_cents))
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
pub fn thresholds_reached_at(spend_cents: i64, budget_cents: i64) -> Vec<i16> {
    THRESHOLDS
        .into_iter()
        .filter(|&t| {
            i128::from(spend_cents) * 100 >= i128::from(t) * i128::from(budget_cents.max(1))
        })
        .collect()
}

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
        let version = pricebook::tiers_in_effect(tx.conn(), &meter, period).await?;
        let line = rate(quantity, version.as_ref().map(|v| &v.tiers))?;
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
pub async fn fired_thresholds(tx: &mut Tx<'_>, service: &str, period: Month) -> Result<Vec<i16>> {
    let org = tx.org();
    Ok(sqlx::query_scalar(
        "SELECT threshold FROM budget_alerts \
         WHERE org_id = $1 AND service = $2 AND period_start = $3 ORDER BY threshold",
    )
    .bind(org)
    .bind(service)
    .bind(period.first_day())
    .fetch_all(tx.conn())
    .await?)
}

/// Where `service` stands against its budget in `period`, in the
/// transaction's org. Answers for any service, budgeted or not.
pub async fn service_status(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
) -> Result<ServiceBudgetStatus> {
    let org = tx.org();
    let budget = get_budget(tx, service).await?;
    let spend_cents = service_spend(tx, org, service, period).await?;
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

// ------------------------------------------------------------------ ingest

/// A service's budget as ingest reads it: the limit and the hard-stop flag,
/// returned by the event's own counter statement so that an event for a
/// service with no budget costs no extra query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub(crate) struct IngestBudget {
    pub monthly_budget_cents: i64,
    pub hard_stop: bool,
}

/// The budget step of ingest, run after a metered event's counters are
/// written, in the same transaction, for a service that has a `budget`.
///
/// It rates the service's spend for `period` (a few rows), and only when a
/// threshold is reached does it write: an `INSERT … ON CONFLICT DO NOTHING
/// RETURNING` into `budget_alerts`, and one email per owner and admin for the
/// thresholds that insert newly recorded.
///
/// **It never fails the event.** All of it runs in a savepoint; an error is
/// logged and rolled back to it. Only a failure of the savepoint commands
/// themselves (a broken connection, which the event's own writes could not
/// survive either) is returned.
///
/// **Lock order.** It runs after the event's counter upserts, so it extends
/// the order [`crate::usage`] documents (legacy, service, meter) with
/// `budget_alerts` last. Two ingests of the same org and period are already
/// serialized by the legacy `org_period_usage` row, which each holds until
/// commit, so they cannot interleave here.
pub(crate) async fn after_metered_event(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
    budget: IngestBudget,
) -> otto_core::error::Result<()> {
    sqlx::query("SAVEPOINT budget_alerts")
        .execute(tx.conn())
        .await?;
    if let Err(e) = fire_alerts(
        tx,
        service,
        period,
        budget.monthly_budget_cents,
        budget.hard_stop,
    )
    .await
    {
        tracing::error!(
            error = %e, org = %tx.org(), service, period = %period,
            "budget alert step failed; the usage event is still counted"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT budget_alerts")
            .execute(tx.conn())
            .await?;
    }
    sqlx::query("RELEASE SAVEPOINT budget_alerts")
        .execute(tx.conn())
        .await?;
    Ok(())
}

async fn fire_alerts(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
    budget_cents: i64,
    hard_stop: bool,
) -> Result<()> {
    let org = tx.org();
    let spend = service_spend(tx, org, service, period).await?;
    let reached = thresholds_reached_at(spend, budget_cents);
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
    let Some(&highest) = fired.iter().max() else {
        return Ok(());
    };

    let (slug, recipients) = alert_recipients(tx).await?;
    let alert = AlertEmail {
        service,
        org_slug: &slug,
        period,
        threshold: highest,
        spend_cents: spend,
        budget_cents,
        hard_stop,
    };
    queue_emails(tx, &recipients, &alert).await
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

/// Queue the alert to each recipient, in a nested savepoint: an address the
/// outbox refuses is skipped, and a database error drops the emails but
/// keeps the alert rows already written, so the alert does not fire again.
async fn queue_emails(
    tx: &mut Tx<'_>,
    recipients: &[String],
    alert: &AlertEmail<'_>,
) -> Result<()> {
    let subject = alert.subject();
    let body = alert.body();
    sqlx::query("SAVEPOINT budget_alert_emails")
        .execute(tx.conn())
        .await?;
    for to in recipients {
        match notifications::enqueue_email(tx, to, &subject, &body).await {
            Ok(_) => {}
            Err(e @ otto_core::error::Error::Invalid(_)) => {
                tracing::warn!(error = %e, service = alert.service, "budget alert email skipped");
            }
            Err(e) => {
                tracing::error!(
                    error = %e, service = alert.service,
                    "could not queue budget alert emails; the alert is recorded"
                );
                sqlx::query("ROLLBACK TO SAVEPOINT budget_alert_emails")
                    .execute(tx.conn())
                    .await?;
                break;
            }
        }
    }
    sqlx::query("RELEASE SAVEPOINT budget_alert_emails")
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// One budget alert email. English only for now: recipients' locales are a
/// follow-up.
#[derive(Debug, Clone)]
struct AlertEmail<'a> {
    service: &'a str,
    org_slug: &'a str,
    period: Month,
    /// The highest threshold newly reached.
    threshold: i16,
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

    fn budget(cents: i64, hard_stop: bool) -> Budget {
        Budget {
            service: "otto-flags".into(),
            monthly_budget_cents: cents,
            hard_stop,
            updated_by: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn only_a_hard_stop_at_or_past_the_budget_blocks() {
        assert!(!budget(1_000, false).blocks_at(5_000));
        assert!(!budget(1_000, true).blocks_at(999));
        assert!(budget(1_000, true).blocks_at(1_000));
        let status = |b: Option<Budget>| ServiceBudgetStatus {
            service: "otto-flags".into(),
            period: Month::new(2026, 10).unwrap(),
            spend_cents: 10_000,
            thresholds_reached: vec![],
            budget: b,
        };
        assert!(!status(None).blocked(), "no budget never blocks");
        assert_eq!(status(None).percent_used(), None);
        assert!(status(Some(budget(1_000, true))).blocked());
        assert_eq!(
            status(Some(budget(1_000, true))).percent_used(),
            Some(1_000)
        );
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
