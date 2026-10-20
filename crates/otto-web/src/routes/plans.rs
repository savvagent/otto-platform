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
//! **An outage serves the last good catalog.** A failed or timed-out refresh
//! is remembered for a few seconds, and meanwhile callers get the last
//! catalog this instance read, or `503` with `Retry-After` if it has none,
//! without each making its own attempt. See [`PlansCache`].
//!
//! **Features are allowlisted, not passed through.** See
//! [`ADVERTISED_FEATURES`].
//!
//! **Plans buy features, not usage.** A plan is a name, a list price and the
//! capabilities it unlocks; usage is priced per value meter, the same on every
//! plan, by the price book in effect this month (`otto_billing::pricebook`),
//! listed once alongside the plans as `meters`. Only meters with a price in
//! effect are listed: an unpriced meter is not on offer yet. Because of the two
//! caches, a new month's prices can take up to about six minutes after 00:00
//! UTC on the first to appear.

use std::future::Future;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::IntoResponse;
use otto_billing::plans::{list_plans, PlanOffer};
use otto_billing::pricebook::{self, book_in_effect, current_month, PricedMeter};
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
    /// Every metered price in effect this month, by meter key. The same for
    /// every plan.
    pub meters: Vec<PublicMeter>,
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
            monthly_cents: p.monthly_cents,
            features: advertised(p.features),
        }
    }
}

/// One metered price, as a pricing page shows it. Mapped field by field from
/// [`PricedMeter`], like [`PublicPlan`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicMeter {
    /// The service slug, e.g. `otto-flags`.
    pub service: String,
    /// The meter's name within the service, e.g. `evaluations`.
    pub meter: String,
    pub display_name: String,
    /// What one unit is, e.g. `evaluation`.
    pub unit: String,
    /// Graduated tiers, in order; the last is unbounded.
    pub tiers: Vec<PublicTier>,
}

/// One graduated tier.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTier {
    /// The last unit of the month this tier prices; `null` on the last tier.
    pub up_to: Option<i64>,
    /// Price per unit, in millionths of a US cent.
    pub unit_amount_ucents: i64,
}

impl From<PricedMeter> for PublicMeter {
    fn from(p: PricedMeter) -> Self {
        Self {
            service: p.meter.service,
            meter: p.meter.meter,
            display_name: p.meter.display_name,
            unit: p.meter.unit,
            tiers: p
                .version
                .tiers
                .as_slice()
                .iter()
                .map(|t| PublicTier {
                    up_to: t.up_to,
                    unit_amount_ucents: t.unit_amount_ucents,
                })
                .collect(),
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

/// How long a failed refresh is remembered. While it is, callers get the last
/// good catalog (or, with none, a `503`) at once instead of each making their
/// own [`REFRESH_TIMEOUT`] attempt against a database that just failed.
const FAILURE_BACKOFF: Duration = Duration::from_secs(5);

/// What [`PlansCache`] holds.
#[derive(Debug, Default)]
struct Entry {
    /// The last catalog read successfully, already serialized, and when.
    good: Option<(Instant, Bytes)>,
    /// When the last refresh failed, if it failed more recently than `good`
    /// was read. Cleared by the next successful refresh.
    failed_at: Option<Instant>,
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
/// **Bounded refreshes.** Each refresh is cut off at [`REFRESH_TIMEOUT`], so
/// a refresh against a dead database cannot hang for as long as a connection
/// attempt does.
///
/// **A failure is remembered, not retried by every waiter.** When a refresh
/// fails or times out, the failure is held for [`FAILURE_BACKOFF`]. Callers
/// queued behind the failed refresh, and callers arriving during the backoff,
/// do not make attempts of their own; they are answered from what is held:
///
/// - **With a last good catalog**, they get it, stale or not, and the failed
///   refresh is logged with `tracing::warn!`. A tier changes a few times a
///   year, so a catalog older than [`CACHE_TTL`] is a far better answer than
///   an error page during an outage.
/// - **With none** (the instance has never read the catalog), they get
///   `503 temporarily_unavailable` with `Retry-After`.
///
/// So during a database outage the database sees at most one attempt per
/// instance per [`FAILURE_BACKOFF`], and no caller waits longer than one
/// [`REFRESH_TIMEOUT`] however many are queued.
///
/// Timed with `tokio::time::Instant` so tests can pause and advance the clock.
#[derive(Debug)]
pub struct PlansCache {
    entry: RwLock<Entry>,
    ttl: Duration,
    refresh_timeout: Duration,
    failure_backoff: Duration,
}

impl Default for PlansCache {
    fn default() -> Self {
        Self {
            entry: RwLock::new(Entry::default()),
            ttl: CACHE_TTL,
            refresh_timeout: REFRESH_TIMEOUT,
            failure_backoff: FAILURE_BACKOFF,
        }
    }
}

/// The catalog could not be read. `503` with `Retry-After`, because it is a
/// "try again" condition. Built directly rather than through
/// [`ApiError::unavailable`], which logs: the failure it reports was already
/// logged when it happened.
fn catalog_unavailable(retry_after: Duration) -> ApiError {
    let mut e = ApiError::new(
        http::StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "could not reach the database right now; retry shortly",
    );
    e.retry_after = Some(retry_after.as_secs().max(1) as i64);
    e
}

impl PlansCache {
    /// The answer `entry` already gives without a refresh, if any: a fresh
    /// catalog, or, while a recent failure is held, the last good catalog or
    /// a `503`.
    fn cached(&self, entry: &Entry) -> Option<ApiResult<Bytes>> {
        if let Some((at, body)) = &entry.good {
            if at.elapsed() < self.ttl {
                return Some(Ok(body.clone()));
            }
        }
        let failed_at = entry.failed_at?;
        let since = failed_at.elapsed();
        if since >= self.failure_backoff {
            return None;
        }
        Some(match &entry.good {
            Some((_, body)) => Ok(body.clone()),
            None => Err(catalog_unavailable(self.failure_backoff - since)),
        })
    }

    /// The cached body, or `load`'s, which is then cached. On a failed
    /// refresh, the last good body if there is one. See the type docs.
    async fn get_or_load<F, Fut>(&self, load: F) -> ApiResult<Bytes>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ApiResult<Bytes>>,
    {
        if let Some(answer) = self.cached(&*self.entry.read().await) {
            return answer;
        }

        let mut entry = self.entry.write().await;
        // Re-checked under the write lock: whoever held it before us may have
        // just refilled it, or just failed to.
        if let Some(answer) = self.cached(&entry) {
            return answer;
        }

        let loaded = match tokio::time::timeout(self.refresh_timeout, load()).await {
            Ok(loaded) => loaded,
            Err(_) => {
                tracing::warn!(
                    timeout = ?self.refresh_timeout,
                    "plan catalog refresh timed out"
                );
                Err(catalog_unavailable(self.failure_backoff))
            }
        };

        match loaded {
            Ok(body) => {
                *entry = Entry {
                    good: Some((Instant::now(), body.clone())),
                    failed_at: None,
                };
                Ok(body)
            }
            Err(mut e) => {
                entry.failed_at = Some(Instant::now());
                if let Some((at, body)) = &entry.good {
                    tracing::warn!(
                        status = %e.status,
                        code = e.code,
                        age = ?at.elapsed(),
                        "plan catalog refresh failed; serving the last good catalog"
                    );
                    return Ok(body.clone());
                }
                if e.status == http::StatusCode::SERVICE_UNAVAILABLE && e.retry_after.is_none() {
                    e.retry_after = Some(self.failure_backoff.as_secs().max(1) as i64);
                }
                Err(e)
            }
        }
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

/// A database failure is `503 temporarily_unavailable`, not the `500` the
/// generic conversions give it: the catalog is public and its failure must
/// read as "retry", and it is what lets [`PlansCache`] attach `Retry-After`.
fn tenant_error(e: otto_tenant::Error) -> ApiError {
    match e {
        otto_tenant::Error::Db(inner) => ApiError::unavailable("plan catalog", inner),
        other => ApiError::from(other),
    }
}

/// See [`tenant_error`].
fn core_error(e: otto_core::Error) -> ApiError {
    match e {
        otto_core::Error::Db(inner) => ApiError::unavailable("plan catalog", inner),
        otto_core::Error::Tenant(inner) => tenant_error(inner),
        other => ApiError::from(other),
    }
}

/// See [`tenant_error`]. A malformed stored price is the operator's to fix,
/// so it is a `500`, logged, not something the caller can act on.
fn pricebook_error(e: pricebook::Error) -> ApiError {
    match e {
        pricebook::Error::Db(inner) => ApiError::unavailable("plan catalog", inner),
        other => ApiError::internal("plan catalog", other),
    }
}

async fn load(state: &AppState) -> ApiResult<Bytes> {
    let mut tx = state.db.begin_unpinned().await.map_err(tenant_error)?;
    let rows = list_plans(&mut tx).await.map_err(core_error)?;
    // The database's month, the clock `pricebook set` judges the future by.
    let month = current_month(tx.conn()).await.map_err(pricebook_error)?;
    let book = book_in_effect(tx.conn(), month)
        .await
        .map_err(pricebook_error)?;
    tx.commit().await.map_err(tenant_error)?;

    if rows.is_empty() {
        // Not an error — the pricing page has an empty state — but the
        // seeded tiers are gone, which an operator should hear about.
        tracing::warn!("plan catalog is empty");
    }
    let response = PlansResponse {
        plans: rows.into_iter().map(PublicPlan::from).collect(),
        meters: book.into_iter().map(PublicMeter::from).collect(),
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
    use std::sync::Arc;

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

    #[test]
    fn a_meter_publishes_its_tiers_and_nothing_else() {
        use otto_billing::meters::Meter;
        use otto_billing::pricebook::{PriceVersion, Tier, Tiers};

        let now = chrono::Utc::now();
        let priced = PricedMeter {
            meter: Meter {
                key: "otto-flags/evaluations".into(),
                service: "otto-flags".into(),
                meter: "evaluations".into(),
                display_name: "Flag evaluations".into(),
                unit: "evaluation".into(),
                created_at: now,
                updated_at: now,
            },
            version: PriceVersion {
                id: uuid::Uuid::new_v4(),
                meter: "otto-flags/evaluations".into(),
                effective_month: "2026-11".parse().unwrap(),
                created_at: now,
                tiers: Tiers::new(vec![
                    Tier {
                        up_to: Some(1_000),
                        unit_amount_ucents: 0,
                    },
                    Tier {
                        up_to: None,
                        unit_amount_ucents: 7,
                    },
                ])
                .unwrap(),
            },
        };
        assert_eq!(
            serde_json::to_value(PublicMeter::from(priced)).unwrap(),
            json!({
                "service": "otto-flags",
                "meter": "evaluations",
                "displayName": "Flag evaluations",
                "unit": "evaluation",
                "tiers": [
                    { "upTo": 1000, "unitAmountUcents": 0 },
                    { "upTo": null, "unitAmountUcents": 7 },
                ],
            }),
            "the unbounded tier is an explicit null; ids and dates stay private"
        );
    }

    #[test]
    fn a_malformed_price_is_an_internal_error() {
        let err = pricebook_error(pricebook::Error::Corrupt {
            version: uuid::Uuid::nil(),
            reason: "x".into(),
        });
        assert_eq!(err.status, http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn a_database_failure_in_the_loader_is_unavailable() {
        let db = || sqlx::Error::PoolTimedOut;
        for err in [
            tenant_error(otto_tenant::Error::Db(db())),
            core_error(otto_core::Error::Db(db())),
            core_error(otto_core::Error::Tenant(otto_tenant::Error::Db(db()))),
            pricebook_error(pricebook::Error::Db(db())),
        ] {
            assert_eq!(err.status, http::StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(err.code, "temporarily_unavailable");
        }
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

    /// A loader that counts its calls and fails with a database outage.
    async fn failing(calls: &AtomicUsize) -> ApiResult<Bytes> {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(ApiError::unavailable("test", "connection refused"))
    }

    fn assert_unavailable(err: &ApiError) {
        assert_eq!(err.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "temporarily_unavailable");
        assert!(
            err.retry_after.is_some_and(|s| s >= 1),
            "a 503 without Retry-After leaves a client guessing"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_good_body_a_failure_is_held_briefly_then_retried() {
        let cache = PlansCache::default();
        let calls = AtomicUsize::new(0);

        assert_unavailable(&cache.get_or_load(|| failing(&calls)).await.unwrap_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(FAILURE_BACKOFF - Duration::from_secs(1)).await;
        let held = cache.get_or_load(|| failing(&calls)).await.unwrap_err();
        assert_unavailable(&held);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "during the backoff a caller is answered without a new attempt"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        let ok = AtomicUsize::new(0);
        assert_eq!(cache.get_or_load(|| counting(&ok)).await.unwrap(), "1");
        assert_eq!(ok.load(Ordering::SeqCst), 1, "after the backoff it retries");
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_refresh_times_out_as_unavailable_and_is_held_briefly() {
        let cache = PlansCache::default();

        let err = cache
            .get_or_load(std::future::pending::<ApiResult<Bytes>>)
            .await
            .unwrap_err();
        assert_unavailable(&err);

        let calls = AtomicUsize::new(0);
        assert_unavailable(&cache.get_or_load(|| counting(&calls)).await.unwrap_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        tokio::time::advance(FAILURE_BACKOFF).await;
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_serves_the_last_good_body() {
        let cache = PlansCache::default();
        let calls = AtomicUsize::new(0);
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");

        tokio::time::advance(CACHE_TTL).await;
        let failures = AtomicUsize::new(0);
        assert_eq!(
            cache.get_or_load(|| failing(&failures)).await.unwrap(),
            "1",
            "a stale catalog beats an error page"
        );
        assert_eq!(cache.get_or_load(|| failing(&failures)).await.unwrap(), "1");
        assert_eq!(
            failures.load(Ordering::SeqCst),
            1,
            "during the backoff the stale body is served without a new attempt"
        );

        tokio::time::advance(FAILURE_BACKOFF).await;
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "2");
        tokio::time::advance(CACHE_TTL - Duration::from_secs(1)).await;
        assert_eq!(
            cache.get_or_load(|| failing(&failures)).await.unwrap(),
            "2",
            "a successful refresh clears the failure and restarts the TTL"
        );
        assert_eq!(failures.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_refresh_serves_the_last_good_body() {
        let cache = PlansCache::default();
        let calls = AtomicUsize::new(0);
        assert_eq!(cache.get_or_load(|| counting(&calls)).await.unwrap(), "1");

        tokio::time::advance(CACHE_TTL).await;
        assert_eq!(
            cache
                .get_or_load(std::future::pending::<ApiResult<Bytes>>)
                .await
                .unwrap(),
            "1"
        );
    }

    /// Runs `n` concurrent `get_or_load` calls whose loader takes a second.
    async fn concurrent(
        cache: &Arc<PlansCache>,
        n: usize,
        fail: bool,
    ) -> (usize, Vec<ApiResult<Bytes>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..n {
            let cache = Arc::clone(cache);
            let calls = Arc::clone(&calls);
            set.spawn(async move {
                cache
                    .get_or_load(|| async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if fail {
                            failing(&calls).await
                        } else {
                            counting(&calls).await
                        }
                    })
                    .await
            });
        }
        let results = set.join_all().await;
        (calls.load(Ordering::SeqCst), results)
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_misses_make_one_load_and_share_its_body() {
        let cache = Arc::new(PlansCache::default());
        let (calls, results) = concurrent(&cache, 10, false).await;

        assert_eq!(calls, 1, "one database read however many callers miss");
        assert_eq!(results.len(), 10);
        for r in results {
            assert_eq!(r.unwrap(), "1");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_behind_a_failed_load_do_not_retry() {
        let cache = Arc::new(PlansCache::default());
        let started = Instant::now();
        let (calls, results) = concurrent(&cache, 10, true).await;

        assert_eq!(calls, 1, "the queued callers get the held failure");
        for r in &results {
            assert_unavailable(r.as_ref().unwrap_err());
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "no caller waits for more than the one attempt"
        );
    }
}
