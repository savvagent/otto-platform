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

use chrono::{DateTime, Datelike, Duration, Months, NaiveTime, Utc};
use otto_core::error::{Error, Result};
use otto_core::orgs::Plan;
use otto_tenant::ids::UserId;
use otto_tenant::Tx;
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

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

/// What [`UsageExt::ingest_usage`] did with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New: recorded and counted.
    Counted,
    /// Already recorded for this org; nothing changed.
    Duplicate,
    /// Refused, with nothing recorded. Retrying unchanged will fail again.
    Rejected(&'static str),
}

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
    /// idempotently. See [`IngestOutcome`].
    fn ingest_usage(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
    ) -> impl std::future::Future<Output = Result<IngestOutcome>> + Send;

    fn current_usage(&mut self) -> impl std::future::Future<Output = Result<PeriodUsage>> + Send;

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
    async fn ingest_usage(
        &mut self,
        resource_uri: &str,
        event: &ShippedUsage<'_>,
    ) -> Result<IngestOutcome> {
        let org = self.org();
        let now = Utc::now();
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

        // `user_id` is resolved through a subselect so an account deleted
        // since the event was written leaves it NULL instead of failing the
        // foreign key (the same trade `record_usage` documents).
        sqlx::query(
            "INSERT INTO usage_events (org_id, user_id, tool, billable, created_at) \
             VALUES ($1, (SELECT id FROM users WHERE id = $2), $3, $4, $5)",
        )
        .bind(org)
        .bind(event.user)
        .bind(event.tool)
        .bind(event.billable)
        .bind(event.occurred_at.min(now))
        .execute(self.conn())
        .await?;

        sqlx::query(
            "INSERT INTO org_period_usage (org_id, period_start, billable_count, total_count) \
             VALUES ($1, date_trunc('month', $2::timestamptz AT TIME ZONE 'utc')::date, $3, 1) \
             ON CONFLICT (org_id, period_start) DO UPDATE \
               SET billable_count = org_period_usage.billable_count + EXCLUDED.billable_count, \
                   total_count = org_period_usage.total_count + 1, \
                   updated_at = now()",
        )
        .bind(org)
        .bind(event.occurred_at.min(now))
        .bind(i64::from(event.billable))
        .execute(self.conn())
        .await?;
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
                    p.hard_stop \
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
}
