//! Per-service monthly budgets: read by any member, set and cleared by an
//! owner or admin.
//!
//! A budget caps what one service's value meters may cost the org in a UTC
//! calendar month. Alerts fire at 50, 80 and 100% of it, once each per month,
//! by email to the owners and admins (at ingest, see
//! `otto_billing::budgets`). The hard stop is opt-in: with it on, the service
//! refuses billable calls once spend reaches the budget, and every other
//! service keeps working.
//!
//! **Console only.** Like every `/api` route, these take the session cookie
//! and nothing else: a bearer token or personal access token never
//! authenticates here, so an agent can read its service's budget (through
//! that service's `usage` tool) but can never change it. Writes go through the
//! cross-site guard (`crate::csrf`) like every other cookie-bearing write, and
//! are audited in the same transaction.
//!
//! **Reading is free** and works however far over budget the org is. All SQL
//! is in `otto_billing::budgets`.

use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDate, Utc};
use http::request::Parts;
use http::StatusCode;
use otto_billing::budgets::{self, actions, Budget, ServiceBudgetStatus};
use otto_billing::pricebook::{self, Month};
use otto_tenant::audit::Entry;
use otto_tenant::Tx;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::session::OrgCtx;
use crate::state::{client_ip, AppState};

/// The wire shape of `GET /api/orgs/{org}/budgets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BudgetsView {
    /// First day of the UTC billing month the spend is for.
    pub period_start: NaiveDate,
    /// Every service with declared meters, by slug, budgeted or not.
    pub services: Vec<ServiceBudgetView>,
}

/// One service's budget and spend this month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceBudgetView {
    pub service: String,
    /// What the service's meters have cost this month, in US cents.
    pub spend_cents: i64,
    /// The alert thresholds (percent) that have fired this month, ascending.
    pub thresholds_reached: Vec<i16>,
    /// `None` when no budget is set.
    pub budget: Option<BudgetView>,
}

/// A service's budget, and where spend stands against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BudgetView {
    pub monthly_budget_cents: i64,
    pub hard_stop: bool,
    /// Whole percent spent, rounded down. Can exceed 100.
    pub percent_used: i64,
    /// Whether the service is refusing billable calls: hard stop on and spend
    /// at or past the budget.
    pub blocked: bool,
    pub updated_at: DateTime<Utc>,
}

impl BudgetView {
    /// The budget part of `status`, if it has one.
    pub fn of(status: &ServiceBudgetStatus) -> Option<Self> {
        let budget: &Budget = status.budget.as_ref()?;
        Some(Self {
            monthly_budget_cents: budget.monthly_budget_cents,
            hard_stop: budget.hard_stop,
            percent_used: status.percent_used().unwrap_or_default(),
            blocked: status.blocked(),
            updated_at: budget.updated_at,
        })
    }
}

impl From<ServiceBudgetStatus> for ServiceBudgetView {
    fn from(status: ServiceBudgetStatus) -> Self {
        let budget = BudgetView::of(&status);
        Self {
            service: status.service,
            spend_cents: status.spend_cents,
            thresholds_reached: status.thresholds_reached,
            budget,
        }
    }
}

/// The body of `PUT /api/orgs/{org}/budgets/{service}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetBudgetRequest {
    /// 1 to `otto_billing::budgets::MAX_MONTHLY_BUDGET_CENTS`.
    pub monthly_budget_cents: i64,
    /// Opt-in; off when omitted.
    #[serde(default)]
    pub hard_stop: bool,
}

/// A budget failure, for a console caller. The database's words are logged,
/// never sent.
pub(crate) fn from_budgets(context: &str, e: budgets::Error) -> ApiError {
    match e {
        // The slug is not echoed: it is whatever the caller put in the path.
        budgets::Error::UnknownService(_) => {
            ApiError::not_found("this org has no service of that name with metered usage")
        }
        budgets::Error::OutOfRange => ApiError::bad_request(e.to_string()),
        other => ApiError::internal(context, other),
    }
}

/// The current billing month, by the database's clock.
pub(crate) async fn current_period(tx: &mut Tx<'_>) -> ApiResult<Month> {
    pricebook::current_month(tx.conn())
        .await
        .map_err(|e| ApiError::internal("read the current month", e))
}

/// `GET /api/orgs/{org}/budgets` — every metered service's budget and spend.
pub async fn list_budgets(
    State(state): State<AppState>,
    ctx: OrgCtx,
) -> ApiResult<Json<BudgetsView>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let period = current_period(&mut tx).await?;
    let services = budgets::org_status(&mut tx, period)
        .await
        .map_err(|e| from_budgets("read budgets", e))?;
    tx.commit().await?;
    Ok(Json(BudgetsView {
        period_start: period.first_day(),
        services: services.into_iter().map(Into::into).collect(),
    }))
}

/// `PUT /api/orgs/{org}/budgets/{service}` — set or change a budget.
pub async fn set_budget(
    State(state): State<AppState>,
    ctx: OrgCtx,
    parts: Parts,
    Path((_org, service)): Path<(String, String)>,
    Json(req): Json<SetBudgetRequest>,
) -> ApiResult<Json<ServiceBudgetView>> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let previous = budgets::get_budget(&mut tx, &service)
        .await
        .map_err(|e| from_budgets("read a budget", e))?;
    let budget = budgets::set_budget(
        &mut tx,
        &service,
        req.monthly_budget_cents,
        req.hard_stop,
        ctx.user.id,
    )
    .await
    .map_err(|e| from_budgets("set a budget", e))?;
    tx.audit(
        Entry::new(actions::SET)
            .actor(ctx.user.id)
            .target("service", &service)
            .from_request(client_ip(&parts, &state.config).as_deref(), None)
            .detail(json!({
                "monthlyBudgetCents": budget.monthly_budget_cents,
                "hardStop": budget.hard_stop,
                "previous": previous.map(|p| json!({
                    "monthlyBudgetCents": p.monthly_budget_cents,
                    "hardStop": p.hard_stop,
                })),
            })),
    )
    .await?;
    let period = current_period(&mut tx).await?;
    let status = budgets::service_status(&mut tx, &service, period)
        .await
        .map_err(|e| from_budgets("read a budget", e))?;
    tx.commit().await?;
    Ok(Json(status.into()))
}

/// `DELETE /api/orgs/{org}/budgets/{service}` — remove a budget, and with it
/// any hard stop. `204` whether or not one was set; audited only when one
/// was.
pub async fn clear_budget(
    State(state): State<AppState>,
    ctx: OrgCtx,
    parts: Parts,
    Path((_org, service)): Path<(String, String)>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let removed = budgets::clear_budget(&mut tx, &service)
        .await
        .map_err(|e| from_budgets("clear a budget", e))?;
    if let Some(removed) = removed {
        tx.audit(
            Entry::new(actions::CLEARED)
                .actor(ctx.user.id)
                .target("service", &service)
                .from_request(client_ip(&parts, &state.config).as_deref(), None)
                .detail(json!({
                    "monthlyBudgetCents": removed.monthly_budget_cents,
                    "hardStop": removed.hard_stop,
                })),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
