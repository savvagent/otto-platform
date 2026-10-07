//! The assembled application: health and the identity surface behind one router.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use otto_platform_server::{app, Config};
use otto_tenant::Db;
use sqlx::PgPool;
use tower::ServiceExt;

fn config() -> Config {
    Config {
        database_url: "unused".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: "https://otto.test".into(),
        encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        client_ip_header: None,
        enforce_quotas: false,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
    }
}

async fn get(pool: PgPool, path: &str) -> (StatusCode, serde_json::Value) {
    let router = app(Db::from_pool(pool), &config()).expect("app");
    let res = router
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or_default())
}

/// Health and the identity surface are served by the same router, and the
/// discovery document is built from the configured public URL.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn health_and_discovery_share_one_router(pool: PgPool) {
    let (status, body) = get(pool.clone(), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");

    let (status, body) = get(pool.clone(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], "https://otto.test");

    // Passkeys are bound to the public URL's host, and published for the console.
    let (status, body) = get(pool, "/api/auth/webauthn").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rpId"], "otto.test");
}
