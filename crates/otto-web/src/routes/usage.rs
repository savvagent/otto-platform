//! The usage meter, read-only.
//!
//! The same numbers the resource servers' own `usage` reports are built from
//! (`otto_billing::usage`), so the figure in the console and the figure an agent
//! sees cannot disagree: one plan and one usage bucket, family-wide, whichever
//! otto-* service the calls were made against.
//!
//! **Reading your own bill is free.** Nothing here records usage, and nothing
//! here refuses anything — enforcement belongs to the resource servers, which
//! charge each call in their own work. Billing a customer for looking at what
//! they have been billed is the kind of detail that costs more in trust than it
//! could ever earn in revenue, and an org that has run out must be able to see
//! *why* it has run out.

use axum::extract::{Json, State};
use otto_billing::usage::{PeriodUsage, PlanLimits, UsageExt};
use otto_tenant::audit::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::error::ApiResult;
use crate::session::OrgCtx;
use crate::state::AppState;

/// Where an org stands against its bucket this month.
///
/// The wire shape of `GET /api/orgs/{org}/usage`. Assembled here from
/// [`PeriodUsage`] and [`PlanLimits`] rather than taken from a resource
/// server's meter, because this server has no meter: it reports, it does not
/// charge.
#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageStatus {
    pub plan: String,
    /// Billable operations included this month, after any negotiated override.
    pub included_ops: i64,
    pub billable_used: i64,
    /// Never negative: an org past its bucket has none left, not a debt.
    pub remaining: i64,
    /// Every recorded call this month, billable or not.
    pub total_calls: i64,
    pub period_start: chrono::NaiveDate,
    /// True once the org has used four fifths of its bucket. Worth surfacing to
    /// a human.
    pub warning: bool,
    /// Whether exceeding the bucket stops billable work rather than metering
    /// overage.
    pub hard_stop: bool,
    /// Whether the resource servers are currently refusing calls over the
    /// bucket at all. See [`crate::state::Config::enforce_quotas`].
    pub enforced: bool,
}

/// Fraction of the bucket at which an org is warned. Matches what the resource
/// servers' meters use, so the console's warning and an agent's agree.
const WARN_AT: f64 = 0.8;

impl UsageStatus {
    fn new(usage: PeriodUsage, limits: PlanLimits, enforced: bool) -> Self {
        let warning = if limits.included_ops <= 0 {
            // A bucket of zero is exhausted from the first call, not a division
            // by zero.
            true
        } else {
            usage.billable_count as f64 >= limits.included_ops as f64 * WARN_AT
        };
        Self {
            plan: limits.display_name,
            included_ops: limits.included_ops,
            billable_used: usage.billable_count,
            remaining: limits
                .included_ops
                .saturating_sub(usage.billable_count)
                .max(0),
            total_calls: usage.total_count,
            period_start: usage.period_start,
            warning,
            hard_stop: limits.hard_stop,
            enforced,
        }
    }
}

/// `GET /api/orgs/{org}/usage` — this period's usage against the plan.
pub async fn get_usage(State(state): State<AppState>, ctx: OrgCtx) -> ApiResult<Json<UsageStatus>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let usage = tx.current_usage().await?;
    let limits = tx.plan_limits().await?;
    tx.commit().await?;
    Ok(Json(UsageStatus::new(
        usage,
        limits,
        state.config.enforce_quotas,
    )))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    /// Restrict to one family of events — `auth.`, `oauth.`, `org.`.
    #[serde(default)]
    pub action_prefix: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/orgs/{org}/audit` — the org's security log.
///
/// Admin-only, unlike the rest of the console's reads. Membership changes, token
/// issuance, and failed logins are exactly the trail an attacker with a
/// low-privilege session would want to read before deciding whom to target.
pub async fn get_audit(
    State(state): State<AppState>,
    ctx: OrgCtx,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let events = tx
        .audit_trail(q.action_prefix.as_deref(), q.limit.unwrap_or(100))
        .await?;
    tx.commit().await?;
    Ok(Json(events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use otto_core::orgs::Plan;

    fn status(used: i64, included: i64) -> UsageStatus {
        UsageStatus::new(
            PeriodUsage {
                period_start: chrono::NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
                billable_count: used,
                total_count: used,
            },
            PlanLimits {
                plan: Plan::Free,
                display_name: "Free".into(),
                included_ops: included,
                hard_stop: true,
            },
            false,
        )
    }

    #[test]
    fn remaining_never_goes_negative() {
        assert_eq!(status(0, 500).remaining, 500);
        assert_eq!(status(500, 500).remaining, 0);
        assert_eq!(
            status(900, 500).remaining,
            0,
            "an org past its bucket has none left, not a debt"
        );
    }

    /// The boundary customers actually notice: a plan sold as 500 operations
    /// has to deliver 500, not 499.
    #[test]
    fn the_warning_starts_at_four_fifths() {
        assert!(!status(399, 500).warning);
        assert!(status(400, 500).warning);
    }

    #[test]
    fn an_empty_bucket_is_always_over() {
        assert!(status(0, 0).warning);
        assert_eq!(status(0, 0).remaining, 0);
    }
}
