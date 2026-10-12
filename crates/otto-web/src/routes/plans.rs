//! The public plan catalog.
//!
//! What the marketing site's pricing page reads, so the prices a visitor sees
//! are the prices the `plans` table bills against rather than a copy in page
//! source that drifts the first time an operator changes a tier. Plans are
//! operator-maintained reference data with no `org_id`, not tenant data, which
//! is why this needs no credential and reads on an unpinned transaction.
//!
//! **Cached twice, because it is anonymous.** Anyone on the internet can call
//! this, and production runs on Fly with no CDN in front, so a
//! `Cache-Control` header alone protects nothing: a caller that ignores it
//! would reach the database on every request. The assembled answer is
//! therefore held in-process for [`CACHE_TTL`] ([`PlansCache`]), so the
//! database sees at most one catalog read per instance per minute however hard
//! the endpoint is hit. `Cache-Control: public, max-age=300` is the second
//! layer, for browsers and any shared cache that does honour it. Together they
//! bound how stale a price change may look at about six minutes; a tier
//! changes a few times a year.
//!
//! **Features are allowlisted, not passed through.** See
//! [`ADVERTISED_FEATURES`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Json, State};
use axum::response::IntoResponse;
use otto_billing::plans::{list_plans, PlanOffer};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::error::ApiResult;
use crate::state::AppState;

/// `Cache-Control` on the catalog. See the module docs.
const CACHE_CONTROL: &str = "public, max-age=300";

/// How long an instance reuses the catalog it last read. The same minute the
/// resource servers' own caches use.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// The `plans.features` keys this endpoint publishes. Everything else is
/// dropped.
///
/// Migration 0016 makes the features object opaque to the platform: its keys
/// belong to the services that read them, and a service adds one with an
/// `UPDATE` rather than a schema change. Passing the object through would turn
/// every such key — an internal gate, a capability not yet announced — into
/// public information the moment it is written, without anyone deciding to
/// publish it. An allowlist makes publishing a deliberate act: a service that
/// wants a capability advertised on the pricing page adds its key here.
pub const ADVERTISED_FEATURES: &[&str] = &["auto_rollback"];

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
    /// Only the [`ADVERTISED_FEATURES`] keys of `plans.features`.
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
            features: advertised(p.features),
        }
    }
}

/// Keep only the [`ADVERTISED_FEATURES`] keys. A value that is not an object
/// (the column's CHECK forbids it, but this is the public edge) publishes as
/// an empty one rather than as whatever it was.
fn advertised(features: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut all) = features else {
        return serde_json::Value::Object(Default::default());
    };
    all.retain(|key, _| ADVERTISED_FEATURES.contains(&key.as_str()));
    serde_json::Value::Object(all)
}

/// The last catalog this instance read, and when.
///
/// A `tokio` `RwLock` rather than a `std` one because a miss holds the write
/// lock across the database read. That is what stops a stampede: when the
/// entry expires under load, the first caller refills it while every other
/// caller waits on the lock, then finds it fresh and reads it, instead of each
/// one issuing its own query. A failed read caches nothing, so the next caller
/// simply tries again.
#[derive(Debug, Default)]
pub struct PlansCache {
    entry: RwLock<Option<(Instant, Arc<PlansResponse>)>>,
}

impl PlansCache {
    fn fresh(entry: &Option<(Instant, Arc<PlansResponse>)>) -> Option<Arc<PlansResponse>> {
        entry
            .as_ref()
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, plans)| Arc::clone(plans))
    }
}

/// `GET /api/plans` — every tier, cheapest first.
pub async fn list(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let plans = catalog(&state).await?;
    // A clone of four short rows per request, so the cache can hand out an
    // `Arc` without needing serde's `rc` feature workspace-wide.
    Ok((
        [(http::header::CACHE_CONTROL, CACHE_CONTROL)],
        Json(PlansResponse::clone(&plans)),
    ))
}

async fn catalog(state: &AppState) -> ApiResult<Arc<PlansResponse>> {
    if let Some(plans) = PlansCache::fresh(&*state.plans.entry.read().await) {
        return Ok(plans);
    }

    let mut entry = state.plans.entry.write().await;
    // Re-checked under the write lock: whoever held it before us may have
    // just refilled it.
    if let Some(plans) = PlansCache::fresh(&entry) {
        return Ok(plans);
    }

    let mut tx = state.db.begin_unpinned().await?;
    let rows = list_plans(&mut tx).await?;
    tx.commit().await?;

    let plans = Arc::new(PlansResponse {
        plans: rows.into_iter().map(PublicPlan::from).collect(),
    });
    *entry = Some((Instant::now(), Arc::clone(&plans)));
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_advertised_features_are_published() {
        assert_eq!(
            advertised(json!({ "auto_rollback": true, "secret_gate": true })),
            json!({ "auto_rollback": true })
        );
        assert_eq!(advertised(json!({})), json!({}));
        assert_eq!(advertised(json!(null)), json!({}));
    }
}
