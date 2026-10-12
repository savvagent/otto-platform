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
//! would reach the database on every request. The serialized answer is
//! therefore held in-process for [`CACHE_TTL`] ([`PlansCache`]), so the
//! database sees at most one catalog read per instance per minute however hard
//! the endpoint is hit. `Cache-Control: public, max-age=300` is the second
//! layer, for browsers and any shared cache that does honour it. Together they
//! bound how stale a price change may look at about six minutes; a tier
//! changes a few times a year.
//!
//! **Features are allowlisted, not passed through.** See
//! [`ADVERTISED_FEATURES`].

use std::future::Future;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::IntoResponse;
use otto_billing::plans::{list_plans, PlanOffer};
use serde::Serialize;
use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// `Cache-Control` on the catalog. See the module docs.
const CACHE_CONTROL: &str = "public, max-age=300";

/// How long an instance reuses the catalog it last read. The same minute the
/// resource servers' own caches use.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// The longest one refresh may take before the caller is told to retry. See
/// [`PlansCache`] for why it has to be short.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

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
const ADVERTISED_FEATURES: &[&str] = &["auto_rollback"];

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
    /// Only the [`ADVERTISED_FEATURES`] keys of `plans.features`, and only
    /// where their value is a boolean.
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

/// Keep only the [`ADVERTISED_FEATURES`] keys, and of those only the ones
/// whose value is a JSON boolean.
///
/// Booleans only because a capability is on exactly where its value is `true`
/// (migration 0016), so on/off is all a pricing page needs, and anything
/// richer a service stores under an advertised key — a limit, a config
/// object — is that service's business, not the public's. A value that is not
/// an object (the column's CHECK forbids it, but this is the public edge)
/// publishes as an empty object rather than as whatever it was.
fn advertised(features: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut all) = features else {
        return serde_json::Value::Object(Default::default());
    };
    all.retain(|key, value| ADVERTISED_FEATURES.contains(&key.as_str()) && value.is_boolean());
    serde_json::Value::Object(all)
}

/// The last catalog this instance read, already serialized, and when.
///
/// Holds the response body rather than the [`PlansResponse`] so a hit costs a
/// reference-count bump, not a clone and a re-serialization.
///
/// **No stampede.** A `tokio` `RwLock` rather than a `std` one because a miss
/// holds the write lock across the database read: when the entry expires
/// under load, the first caller refills it while every other caller waits on
/// the lock, then finds it fresh and serves it, instead of each one issuing
/// its own query.
///
/// **Bounded refreshes.** A failed refresh caches nothing, so the next caller
/// in line tries again, which during a database outage means the waiting
/// callers retry one after another under the lock. Each attempt is therefore
/// cut off at [`REFRESH_TIMEOUT`] and answered `503 temporarily_unavailable`,
/// so a caller's wait is bounded by the timeout times the callers ahead of it
/// rather than by however long a connection attempt to a dead database hangs.
///
/// Timed with `tokio::time::Instant` so tests can pause and advance the clock.
#[derive(Debug)]
pub struct PlansCache {
    entry: RwLock<Option<(Instant, Bytes)>>,
    ttl: Duration,
    refresh_timeout: Duration,
}

impl Default for PlansCache {
    fn default() -> Self {
        Self {
            entry: RwLock::new(None),
            ttl: CACHE_TTL,
            refresh_timeout: REFRESH_TIMEOUT,
        }
    }
}

impl PlansCache {
    fn fresh(&self, entry: &Option<(Instant, Bytes)>) -> Option<Bytes> {
        entry
            .as_ref()
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, body)| body.clone())
    }

    /// The cached body, or `load`'s, which is then cached. See the type docs.
    async fn get_or_load<F, Fut>(&self, load: F) -> ApiResult<Bytes>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ApiResult<Bytes>>,
    {
        if let Some(body) = self.fresh(&*self.entry.read().await) {
            return Ok(body);
        }

        let mut entry = self.entry.write().await;
        // Re-checked under the write lock: whoever held it before us may have
        // just refilled it.
        if let Some(body) = self.fresh(&entry) {
            return Ok(body);
        }

        let body = tokio::time::timeout(self.refresh_timeout, load())
            .await
            .map_err(|_| {
                ApiError::unavailable(
                    "plan catalog",
                    format!("refresh exceeded {:?}", self.refresh_timeout),
                )
            })??;
        *entry = Some((Instant::now(), body.clone()));
        Ok(body)
    }
}

/// `GET /api/plans` — every tier, cheapest first.
pub async fn list(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let body = state.plans.get_or_load(|| load(&state)).await?;
    Ok((
        [
            (http::header::CONTENT_TYPE, "application/json"),
            (http::header::CACHE_CONTROL, CACHE_CONTROL),
        ],
        body,
    ))
}

async fn load(state: &AppState) -> ApiResult<Bytes> {
    let mut tx = state.db.begin_unpinned().await?;
    let rows = list_plans(&mut tx).await?;
    tx.commit().await?;

    let response = PlansResponse {
        plans: rows.into_iter().map(PublicPlan::from).collect(),
    };
    serde_json::to_vec(&response)
        .map(Bytes::from)
        .map_err(|e| ApiError::internal("plan catalog", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn only_advertised_boolean_features_are_published() {
        assert_eq!(
            advertised(json!({ "auto_rollback": true, "secret_gate": true })),
            json!({ "auto_rollback": true })
        );
        assert_eq!(
            advertised(json!({ "auto_rollback": { "max_steps": 3 } })),
            json!({}),
            "a non-boolean value under an advertised key is not published"
        );
        assert_eq!(advertised(json!({})), json!({}));
        assert_eq!(advertised(json!(null)), json!({}));
    }

    /// A loader that counts its calls and answers with the call number.
    async fn counting(calls: &AtomicUsize) -> ApiResult<Bytes> {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Bytes::from(n.to_string()))
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_entry_is_reused_and_an_expired_one_refills() {
        let cache = PlansCache::default();
        let calls = AtomicUsize::new(0);

        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");
        tokio::time::advance(CACHE_TTL - Duration::from_secs(1)).await;
        assert_eq!(
            cache.get_or_load(|| counting(&calls)).await.unwrap(),
            "1",
            "within the TTL the database is not asked again"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_is_not_cached() {
        let cache = PlansCache::default();

        let failed = cache
            .get_or_load(|| async { Err(ApiError::internal("test", "boom")) })
            .await;
        assert!(failed.is_err());

        let calls = AtomicUsize::new(0);
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_refresh_times_out_as_unavailable_and_is_not_cached() {
        let cache = PlansCache::default();

        let err = cache
            .get_or_load(std::future::pending::<ApiResult<Bytes>>)
            .await
            .unwrap_err();
        assert_eq!(err.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "temporarily_unavailable");

        let calls = AtomicUsize::new(0);
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");
    }
}
