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
        static_dir: None,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
        email: None,
        stripe: None,
        usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
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

/// Served directly, with the console mounted and no edge in front: the CSRF
/// guard still holds same-origin, API paths keep their JSON 404s rather than
/// falling into the SPA shell, and only console routes get the shell
/// (`200.html`, marked `X-Robots-Tag: noindex`).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_console_served_directly_keeps_csrf_and_json_404s(pool: PgPool) {
    let dir = std::env::temp_dir().join(format!("otto-app-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("200.html"), "<html>shell</html>").unwrap();
    let mut cfg = config();
    cfg.static_dir = Some(dir);
    let call = |req: Request<Body>| {
        let router = app(Db::from_pool(pool.clone()), &cfg).expect("app");
        async move {
            let res = router.oneshot(req).await.unwrap();
            let status = res.status();
            let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    };
    let cookie = ("cookie", "__Host-otto_session=otto_ss_unknown");
    let logout = |origin: Option<&str>| {
        let mut b = Request::post("/api/auth/logout").header(cookie.0, cookie.1);
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        b.body(Body::empty()).unwrap()
    };

    // Same-origin write: the browser's Origin is the public URL itself.
    let (status, _) = call(logout(Some("https://otto.test"))).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "same-origin must pass the guard"
    );
    // Foreign origin, and no origin at all, are refused.
    let (status, body) = call(logout(Some("https://evil.test"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("cross_site_request"), "{body}");
    let (status, _) = call(logout(None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // API-shaped unknown paths are JSON 404s, never the shell.
    for path in ["/api/no/such", "/oauth/nope", "/internal/nope", "/sso/nope"] {
        let (status, body) = call(Request::get(path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(
            body.contains("\"not_found\"") && !body.contains("shell"),
            "{path}: {body}"
        );
    }
    // Console routes get the shell; real server routes are untouched.
    let (status, body) = call(Request::get("/o/acme/members").body(Body::empty()).unwrap()).await;
    assert_eq!((status, body.contains("shell")), (StatusCode::OK, true));
    // ...and the shell is never indexed: it is the same page for every route.
    let res = app(Db::from_pool(pool.clone()), &cfg)
        .expect("app")
        .oneshot(Request::get("/o/acme/members").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        res.headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok()),
        Some("noindex, nofollow")
    );
    let (status, _) = call(Request::get("/readyz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let _ = std::fs::remove_dir_all(cfg.static_dir.as_ref().expect("set above"));
}

/// With no Stripe secrets the whole application still boots and serves, and
/// the Stripe webhook, mounted in the assembled router, says billing is off
/// rather than 404ing or failing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn without_stripe_secrets_billing_is_reported_disabled(pool: PgPool) {
    let router = app(Db::from_pool(pool), &config()).expect("app boots without Stripe");
    let res = router
        .oneshot(
            Request::post("/api/stripe/webhook")
                .header("stripe-signature", "t=1,v1=00")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "billing_disabled");
}
