//! The usage meter, read-only.
//!
//! The same numbers the resource servers' own `usage` reports are built from
//! (`otto_billing::usage`, `otto_billing::budgets`), so the figure in the
//! console and the figure an agent sees cannot disagree. Two generations
//! share the body: the legacy family-wide bucket (one plan, one count across
//! every otto-* service), and `services`, each metered service's own meters,
//! spend and budget.
//!
//! **Reading your own bill is free.** Nothing here records usage, and nothing
//! here refuses anything — enforcement belongs to the resource servers, which
//! charge each call in their own work. Billing a customer for looking at what
//! they have been billed is the kind of detail that costs more in trust than it
//! could ever earn in revenue, and an org that has run out must be able to see
//! *why* it has run out.

use axum::extract::{Json, State};
use otto_billing::billing;
use otto_billing::budgets;
use otto_billing::pricebook::Month;
use otto_billing::usage::{MeterPeriodUsage, PeriodUsage, PlanLimits, UsageExt};
use otto_tenant::audit::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::routes::budgets::{from_budgets, spend_error, BudgetView};
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
    /// **Deprecated**, always `false`, as `/internal/.../usage-status` serves
    /// it: the family-wide bucket never stops work. A service's own budget
    /// hard stop is `services[].budget.hardStop`.
    pub hard_stop: bool,
    /// Whether the resource servers are currently refusing calls over the
    /// bucket at all. See [`crate::state::Config::enforce_quotas`].
    pub enforced: bool,
    /// Each service with declared meters, by slug: its meters' usage, its
    /// spend and its budget this month. Added alongside the legacy fields
    /// above, which keep their meaning.
    pub services: Vec<ServiceUsage>,
}

/// One metered service's usage this month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceUsage {
    pub service: String,
    /// Every meter the service has declared, by key, zero when unused.
    pub meters: Vec<MeterUsageView>,
    /// What the meters have cost this month, in US cents. `None` when it
    /// cannot be computed; [`spend_error`](Self::spend_error) says so.
    pub spend_cents: Option<i64>,
    /// `pricing_unavailable` when [`spend_cents`](Self::spend_cents) is
    /// `None`, otherwise `None`.
    pub spend_error: Option<&'static str>,
    /// `None` when no budget is set.
    pub budget: Option<BudgetView>,
    /// Whether the service is refusing billable calls until the org adds a
    /// payment method: the org has no live subscription, and the service's
    /// spend this month is above zero (past its free tiers). Never with
    /// unknown spend.
    pub payment_required: bool,
}

/// One meter's quantity this month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeterUsageView {
    /// `<service>/<meter>`.
    pub meter: String,
    pub display_name: String,
    pub unit: String,
    pub quantity: i64,
}

impl From<MeterPeriodUsage> for MeterUsageView {
    fn from(m: MeterPeriodUsage) -> Self {
        Self {
            meter: m.meter,
            display_name: m.display_name,
            unit: m.unit,
            quantity: m.quantity,
        }
    }
}

/// Fraction of the bucket at which an org is warned. Matches what the resource
/// servers' meters use, so the console's warning and an agent's agree.
const WARN_AT: f64 = 0.8;

impl UsageStatus {
    fn new(
        usage: PeriodUsage,
        limits: PlanLimits,
        enforced: bool,
        services: Vec<ServiceUsage>,
    ) -> Self {
        let warning = if limits.included_ops <= 0 {
            // A bucket of zero is exhausted from the first call, not a division
            // by zero.
            true
        } else {
            usage.billable_count as f64 >= limits.included_ops as f64 * WARN_AT
        };
        // `limits.hard_stop` (the plan's flag) is deliberately not served:
        // see the field.
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
            hard_stop: false,
            enforced,
            services,
        }
    }
}

/// `GET /api/orgs/{org}/usage` — this period's usage against the plan.
pub async fn get_usage(State(state): State<AppState>, ctx: OrgCtx) -> ApiResult<Json<UsageStatus>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let usage = tx.current_usage().await?;
    let limits = tx.plan_limits().await?;
    // `now()` is fixed for the transaction, so this is the month
    // `current_usage` just read.
    let period = Month::containing(usage.period_start);
    let statuses = budgets::org_status(&mut tx, period)
        .await
        .map_err(|e| from_budgets("read service usage", e))?;
    let live = billing::live_subscription(&mut tx)
        .await
        .map_err(|e| ApiError::internal("read the org's subscription", e))?
        .is_some();
    let mut services = Vec::with_capacity(statuses.len());
    for status in statuses {
        let meters = tx.service_meter_usage(&status.service).await?;
        services.push(ServiceUsage {
            payment_required: status.payment_required(live),
            budget: BudgetView::of(&status),
            spend_error: spend_error(&status),
            meters: meters.into_iter().map(Into::into).collect(),
            spend_cents: status.spend_cents,
            service: status.service,
        });
    }
    tx.commit().await?;
    Ok(Json(UsageStatus::new(
        usage,
        limits,
        state.config.enforce_quotas,
        services,
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
                features: serde_json::json!({}),
            },
            false,
            Vec::new(),
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
    fn the_legacy_hard_stop_is_never_served() {
        assert!(!status(900, 500).hard_stop, "the plan's own flag is true");
    }

    #[test]
    fn an_empty_bucket_is_always_over() {
        assert!(status(0, 0).warning);
        assert_eq!(status(0, 0).remaining, 0);
    }
}
