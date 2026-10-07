//! `otto-platform-server` as a library, so its router can be exercised in
//! integration tests without binding a socket. The binary in `main.rs` owns
//! configuration, startup checks, and serving.
//!
//! Routes:
//!
//! ```text
//!   /healthz /readyz          health      no database on the liveness path
//!   POST /oauth/introspect    introspect  RFC 7662, resource-server credential
//!   /internal/*               internal    usage ingest and identity lookups,
//!                                         resource-server credential
//!   /api/…  /oauth/…          otto-web    session cookies, the account/org API, the AS
//!   /sso/callback             otto-web    the enterprise IdP's redirect back
//!   /.well-known/…            otto-web    AS discovery, open by necessity
//!   everything else           web/build   the console SPA, index.html fallback;
//!                                         only with OTTO_STATIC_DIR set
//! ```
//!
//! The resource-server-facing endpoints authenticate with the resource
//! server's own credential ([`api::CallingResourceServer`]), not a session
//! cookie, and are outside `otto-web`'s CSRF guard, which only wraps its own
//! router. Lifecycle webhooks are delivered by [`webhooks::run`], a background
//! task the binary starts; `otto-platform-server resource ...` provisions
//! resource servers ([`resource_cmd`]). The console bundle is a separate piece
//! in `web/`, and is served from here only for self-hosters
//! (`OTTO_STATIC_DIR`); the hosted deployment serves it from a Cloudflare Worker.
//!
//! Assembly is a library function rather than something buried in `main` so a
//! test can build the whole router: axum panics on a route registered twice,
//! and a panic at startup is only a good failure if something other than a
//! deployment reaches it first.

pub mod api;
pub mod config;
pub mod health;
pub mod internal;
pub mod introspect;
pub mod resource_cmd;
pub mod webhooks;

use std::convert::Infallible;
use std::path::Path;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use otto_tenant::Db;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub use config::{Config, LogFormat};

/// The routes that need nothing but a database handle: health and the
/// resource-server API.
pub fn router(db: Db) -> Router {
    health::router(db.clone())
        .merge(introspect::router(db.clone()))
        .merge(internal::router(db))
}

/// Build the whole application: health, the resource-server API, and the
/// identity HTTP surface.
///
/// Fallible because the encryption key is only a `String` until something tries
/// to use it, and a `Config` assembled by hand — a test, a future binary — need
/// not have come from the environment at all. Returning the error keeps this
/// crate's rule that a bad value is a named failure and never a panic.
pub fn app(db: Db, config: &Config) -> Result<Router> {
    let web = otto_web::router(web_state(db.clone(), config)?);

    let app = router(db).merge(web);
    // Either way an unmatched path answers JSON, never an empty body: a client
    // that guessed a route needs something it can parse.
    let app = match &config.static_dir {
        Some(dir) => app.fallback_service(console(dir)),
        None => app.fallback(|uri: axum::http::Uri| async move { not_found(uri.path()) }),
    };

    Ok(app
        // Request spans, without headers. `DefaultMakeSpan::include_headers`
        // would put `Authorization` and `Cookie` into the logs — every bearer
        // token and every session cookie, in plaintext, in whatever the log
        // aggregator retains. Do not turn it on.
        .layer(TraceLayer::new_for_http()))
}

/// Path prefixes that belong to an API rather than to the console's routing.
///
/// Everything else falls through to the single-page app, which is what makes a
/// hard refresh of `/o/acme/members` work. An unmatched path under one of these
/// must not: a client that `GET`s `/api/orgs/nope` needs a `404` it can parse,
/// and `200 text/html` is the shape that makes a client retry forever against a
/// route that will never exist.
///
/// **`web/worker/index.ts` keeps the matching list for the Cloudflare
/// deployment** (`ORIGIN_PREFIXES` plus `NEVER_PROXIED`) and must not drift from
/// this one. `/healthz` and `/readyz` are not here because they are real routes
/// mounted ahead of the fallback.
const API_PREFIXES: [&str; 5] = ["/api", "/oauth", "/sso", "/.well-known", "/internal"];

fn is_api_path(path: &str) -> bool {
    API_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// The console bundle, or a JSON `404` for anything API-shaped.
///
/// `ServeDir` falls back to `index.html` for any path it has no file for, which
/// is what `adapter-static` produces and what client-side routing needs. That
/// fallback is exactly why the API prefixes are checked first.
fn console(
    static_dir: &Path,
) -> impl tower::Service<Request<Body>, Response = Response, Error = Infallible, Future = impl Send>
       + Clone
       + Send
       + 'static {
    let assets = ServeDir::new(static_dir)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(static_dir.join("index.html")));

    tower::service_fn(move |req: Request<Body>| {
        let assets = assets.clone();
        async move {
            if is_api_path(req.uri().path()) {
                return Ok(not_found(req.uri().path()));
            }
            Ok(assets
                .oneshot(req)
                .await
                .map(|res| res.map(Body::new))
                .into_response())
        }
    })
}

fn not_found(path: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "error": "not_found",
            "error_description":
                format!("no route serves {path}. See /api/openapi.json for the API."),
        })),
    )
        .into_response()
}

/// `otto-web`'s state, with the settings that are this deployment's to decide.
fn web_state(db: Db, config: &Config) -> Result<otto_web::AppState> {
    let cipher = otto_tenant::crypto::Cipher::from_base64_key(&config.encryption_key)
        .context("OTTO_ENCRYPTION_KEY is not a valid 32-byte base64 key")?;

    let web_config = web_config(config);
    // Built here and once: `rp_id` is what every passkey is bound to, so a bad
    // value must stop the process rather than surface as a browser error on
    // somebody's first sign-in.
    let webauthn = otto_web::relying_party(&web_config)
        .context("could not build the WebAuthn relying party from OTTO_PUBLIC_URL")?;

    Ok(otto_web::AppState::new(db, cipher, webauthn, web_config))
}

/// Every setting `otto-web` takes from this deployment, in one place so it can
/// be tested without a database.
///
/// Split out because the failure mode is silence: a field added to
/// `otto_web::Config` that nothing here assigns keeps its default, and the
/// console then reports that default as fact. `enforce_quotas` reached exactly
/// that state once already in otto-factory.
fn web_config(config: &Config) -> otto_web::Config {
    let mut web = otto_web::Config::new(&config.public_url);
    web.client_ip_header = config.client_ip_header.clone();
    web.enforce_quotas = config.enforce_quotas;
    web
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn every_deployment_setting_reaches_otto_web() {
        let mut config = Config::for_test();
        config.client_ip_header = Some("fly-client-ip".into());
        config.enforce_quotas = true;

        let web = web_config(&config);

        assert_eq!(web.client_ip_header.as_deref(), Some("fly-client-ip"));
        assert!(
            web.enforce_quotas,
            "the console would report `enforced: false` while resource servers refuse calls"
        );
        assert_eq!(web.public_url, config.public_url);
    }

    /// The WebAuthn relying party is the public URL's host, never a constant:
    /// production is `otto.savvagent.com`, and a staging host must not share
    /// (or be able to replay) its passkeys.
    #[test]
    fn the_relying_party_follows_the_public_url() {
        let mut config = Config::for_test();
        assert_eq!(
            web_config(&config).rp_id().as_deref(),
            Some("otto.example.com")
        );

        config.public_url = "https://staging.otto.example.org:8443".into();
        assert_eq!(
            web_config(&config).rp_id().as_deref(),
            Some("staging.otto.example.org")
        );
    }

    #[tokio::test]
    async fn a_malformed_encryption_key_is_a_named_error() {
        let mut config = Config::for_test();
        config.encryption_key = "not-base64!".into();
        let db = Db::from_pool(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/does-not-exist")
                .expect("lazy pool"),
        );
        let err = app(db, &config).expect_err("a bad key must not build an app");
        assert!(
            format!("{err:#}").contains("OTTO_ENCRYPTION_KEY"),
            "{err:#}"
        );
    }

    fn bundle() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("otto-console-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("_app")).expect("mkdir");
        std::fs::write(dir.join("index.html"), "<html>console</html>").expect("index");
        std::fs::write(dir.join("_app/app.js"), "console.log(1)").expect("asset");
        dir
    }

    async fn status_and_body(app: Router, path: &str) -> (StatusCode, String) {
        let res = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn lazy_db() -> Db {
        Db::from_pool(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/does-not-exist")
                .expect("lazy pool"),
        )
    }

    /// With `OTTO_STATIC_DIR` the server also serves the console: real files
    /// as themselves, any other page route as the SPA shell, and anything
    /// API-shaped as a JSON `404` rather than HTML with a `200`.
    #[tokio::test]
    async fn the_console_is_served_only_when_a_bundle_is_configured() {
        let mut config = Config::for_test();
        config.static_dir = Some(bundle());
        let make = || app(lazy_db(), &config).expect("app assembles");

        let (status, body) = status_and_body(make(), "/o/acme/members").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("console"), "{body}");

        let (status, body) = status_and_body(make(), "/_app/app.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log(1)");

        // `/apiary` is a legal org slug: a page, not an API path.
        let (status, body) = status_and_body(make(), "/apiary").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("console"), "{body}");

        for path in [
            "/api/no/such/thing",
            "/oauth/nope",
            "/sso/nope",
            "/.well-known/nope",
            "/internal/nope",
        ] {
            let (status, body) = status_and_body(make(), path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(body.contains("\"not_found\""), "{path}: {body}");
        }

        // No bundle configured: the hosted shape. Nothing answers for pages,
        // and the refusal is still JSON.
        let api_only = app(lazy_db(), &Config::for_test()).expect("app assembles");
        let (status, body) = status_and_body(api_only, "/o/acme/members").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("\"not_found\""), "{body}");
    }

    /// The whole application assembles — health and web together — which is
    /// where a route registered twice would panic.
    #[tokio::test]
    async fn the_whole_application_assembles() {
        let db = Db::from_pool(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/does-not-exist")
                .expect("lazy pool"),
        );
        let _router = app(db, &Config::for_test()).expect("app assembles");
    }
}
