//! `/healthz` and `/readyz` against the real router, no socket bound.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use otto_tenant::Db;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;

async fn get(db: Db, path: &str) -> (StatusCode, serde_json::Value) {
    let res = otto_platform_server::router(db)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// A pool that can never connect: nothing listens on port 1.
fn unreachable_db() -> Db {
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    Db::from_pool(pool)
}

#[sqlx::test(migrations = false)]
async fn readyz_is_ready_with_a_reachable_database(pool: PgPool) {
    let (status, body) = get(Db::from_pool(pool), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn readyz_is_unready_without_a_database() {
    let (status, body) = get(unreachable_db(), "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "unready");
}

/// Liveness must not depend on the database (see `health.rs`).
#[tokio::test]
async fn healthz_is_ok_without_a_database() {
    let (status, body) = get(unreachable_db(), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}
