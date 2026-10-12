//! The public plan catalog.
//!
//! What the marketing site's pricing page reads, so the prices a visitor sees
//! are the prices the `plans` table bills against rather than a copy in page
//! source that drifts the first time an operator changes a tier. Plans are
//! operator-maintained reference data with no `org_id`, not tenant data, which
//! is why this needs no credential and reads on an unpinned transaction.
//!
//! **Cached for five minutes, publicly.** The page is prerendered and served
//! from a CDN; a tier changes a few times a year, and letting a shared cache
//! hold the answer keeps an anonymous, unthrottled endpoint off the database
//! for every page view. Five minutes is how stale a price change may look.

use axum::extract::{Json, State};
use axum::response::IntoResponse;
use otto_billing::plans::{list_plans, PlanOffer};
use serde::Serialize;

use crate::error::ApiResult;
use crate::state::AppState;

/// `Cache-Control` on the catalog. See the module docs.
const CACHE_CONTROL: &str = "public, max-age=300";

/// The wire shape of `GET /api/plans`. An object rather than a bare array so
/// the catalog can grow (a currency, say) without breaking a reader.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlansResponse {
    pub plans: Vec<PublicPlan>,
}

/// One tier as a pricing page shows it.
///
/// Mapped field by field from [`PlanOffer`] rather than serializing it
/// directly, so a column added to the billing query is not published to the
/// internet by accident.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPlan {
    pub plan: String,
    pub display_name: String,
    pub included_ops: i64,
    pub hard_stop: bool,
    /// List price in US cents. `0` on enterprise means negotiated, not free.
    pub monthly_cents: i32,
    pub features: serde_json::Value,
}

impl From<PlanOffer> for PublicPlan {
    fn from(p: PlanOffer) -> Self {
        Self {
            plan: p.plan.as_str().to_string(),
            display_name: p.display_name,
            included_ops: p.included_ops,
            hard_stop: p.hard_stop,
            monthly_cents: p.monthly_cents,
            features: p.features,
        }
    }
}

/// `GET /api/plans` — every tier, cheapest first.
pub async fn list(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let mut tx = state.db.begin_unpinned().await?;
    let plans = list_plans(&mut tx).await?;
    tx.commit().await?;
    Ok((
        [(http::header::CACHE_CONTROL, CACHE_CONTROL)],
        Json(PlansResponse {
            plans: plans.into_iter().map(PublicPlan::from).collect(),
        }),
    ))
}
