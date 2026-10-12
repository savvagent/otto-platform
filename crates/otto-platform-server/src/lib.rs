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
//!   everything else           web/build   prerendered pages, then the SPA shell
//!                                         (200.html, noindex) for client routes;
//!                                         only with OTTO_STATIC_DIR set
//! ```
//!
//! The resource-server-facing endpoints authenticate with the resource
//! server's own credential ([`api::CallingResourceServer`]), not a session
//! cookie, and are outside `otto-web`'s CSRF guard, which only wraps its own
//! router. Lifecycle webhooks are delivered by [`webhooks::run`], a background
//! task the binary starts; `otto-platform-server resource ...` provisions
//! resource servers ([`resource_cmd`]) and `otto-platform-server client ...`
//! registers first-party OAuth clients ([`client_cmd`]). The console bundle is
//! a separate piece in `web/`, served from here when `OTTO_STATIC_DIR` is set,
//! which is how the hosted Fly deployment runs.
//!
//! Assembly is a library function rather than something buried in `main` so a
//! test can build the whole router: axum panics on a route registered twice,
//! and a panic at startup is only a good failure if something other than a
//! deployment reaches it first.

pub mod api;
pub mod client_cmd;
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
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use otto_tenant::Db;
use tower::ServiceExt;
use tower_http::services::fs::ServeFileSystemResponseBody;
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
/// The bundle is two things in one directory: prerendered marketing pages
/// (`index.html` is the landing page at `/`, other pages are `<route>.html`
/// because adapter-static runs with `trailingSlash: 'never'`) and the SPA
/// shell at `200.html`, which client-side routing needs for every path that
/// has no file. Order matters, and each step is here because the one after it
/// gets that case wrong:
///
/// 1. API-shaped paths answer a JSON `404` before anything can answer HTML.
/// 2. `/index.html` (and `/index`) is `308`'d to `/`, so the landing page
///    has one URL.
/// 3. `/200` and `/200.html` are the shell with its header, never a page.
/// 4. An extensionless path tries `<path>.html` with directory appending
///    *off*. It runs before step 5 because `es/` is a directory as well as
///    `es.html` a file, and a directory-appending lookup answers `/es` with a
///    `307` to `/es/` that then finds no `es/index.html`.
/// 5. The path as given, which serves `/` and the assets.
/// 6. What is left: an extensionless `GET`/`HEAD` gets the shell, and
///    anything with an extension keeps its `404`. A missing `/_app/x.js`
///    answered with HTML is a syntax error in the browser, and the shell
///    answered with a `404` is a client route a crawler drops.
///
/// Every file goes through `ServeDir`/`ServeFile`, so path sanitisation stays
/// tower-http's; nothing here joins a request path onto the directory.
///
/// The shell carries `X-Robots-Tag: noindex, nofollow` wherever it answers.
/// It is the same HTML for every route it stands in for, and an indexed shell
/// is a search result for `/o/acme/members` that renders a login prompt.
fn console(
    static_dir: &Path,
) -> impl tower::Service<Request<Body>, Response = Response, Error = Infallible, Future = impl Send>
       + Clone
       + Send
       + 'static {
    // No fallbacks on either: each step decides for itself what a miss means.
    let pages = ServeDir::new(static_dir).append_index_html_on_directories(false);
    let files = ServeDir::new(static_dir).append_index_html_on_directories(true);
    let shell = ServeFile::new(static_dir.join("200.html"));

    tower::service_fn(move |req: Request<Body>| {
        let (pages, files, shell) = (pages.clone(), files.clone(), shell.clone());
        async move {
            let path = req.uri().path().to_owned();
            if is_api_path(&path) {
                return Ok(not_found(&path));
            }
            // Trailing slashes trimmed because step 4 would otherwise turn
            // `/200/` into `200.html` served as a page, header and all missing,
            // and `/index` into a second URL for the landing page.
            let bare = path.trim_end_matches('/');
            if bare == "/index.html" || bare == "/index" {
                let location = match req.uri().query() {
                    Some(q) => format!("/?{q}"),
                    None => "/".to_owned(),
                };
                return Ok(Redirect::permanent(&location).into_response());
            }
            if bare == "/200" || bare == "/200.html" {
                return Ok(noindex(serve(shell, req).await));
            }

            let extensionless = !path.rsplit('/').next().unwrap_or("").contains('.');
            if extensionless && path != "/" {
                let html = format!("{}.html", path.strip_suffix('/').unwrap_or(&path));
                let uri = match req.uri().query() {
                    Some(q) => format!("{html}?{q}"),
                    None => html,
                };
                if let Ok(uri) = uri.parse::<Uri>() {
                    let res = serve(pages, with_uri(&req, uri)).await;
                    let status = res.status();
                    if status.is_success() || status == StatusCode::NOT_MODIFIED {
                        return Ok(res);
                    }
                }
            }

            let page_route =
                extensionless && (req.method() == Method::GET || req.method() == Method::HEAD);
            let res = serve(files, with_uri(&req, req.uri().clone())).await;
            if res.status().is_success() || res.status().is_redirection() || !page_route {
                return Ok(res);
            }
            Ok(noindex(serve(shell, req).await))
        }
    })
}

/// A body-less copy of `req` at `uri`. Safe because only `GET` and `HEAD`
/// are ever answered from the bundle, and neither carries a body that matters;
/// it lets one request be tried against several lookups in turn.
fn with_uri(req: &Request<Body>, uri: Uri) -> Request<Body> {
    let mut copy = Request::new(Body::empty());
    *copy.method_mut() = req.method().clone();
    *copy.uri_mut() = uri;
    *copy.version_mut() = req.version();
    *copy.headers_mut() = req.headers().clone();
    copy
}

/// `ServeDir` and `ServeFile` answer with the same body type and cannot fail.
async fn serve<S>(service: S, req: Request<Body>) -> Response
where
    S: tower::Service<
        Request<Body>,
        Response = axum::http::Response<ServeFileSystemResponseBody>,
        Error = Infallible,
    >,
{
    match service.oneshot(req).await {
        Ok(res) => res.map(Body::new),
        Err(never) => match never {},
    }
}

fn noindex(mut res: Response) -> Response {
    res.headers_mut().insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    res
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

    /// A bundle shaped like adapter-static's output once the marketing pages
    /// are prerendered: the landing page at `index.html`, other pages as
    /// `<route>.html` (trailingSlash `never`), and the SPA shell at `200.html`.
    /// `es/` is a directory *and* `es.html` a file, the shape that a
    /// directory-appending lookup gets wrong. Every file says something
    /// different, so a test can tell which one answered. One directory per
    /// test: tests in one binary share a pid and run concurrently.
    fn bundle(test: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("otto-console-test-{}-{test}", std::process::id()));
        for sub in ["_app", "es", "products"] {
            std::fs::create_dir_all(dir.join(sub)).expect("mkdir");
        }
        for (file, body) in [
            ("200.html", "<html>shell</html>"),
            ("index.html", "<html>landing</html>"),
            ("pricing.html", "<html>pricing</html>"),
            ("es.html", "<html>es landing</html>"),
            ("es/pricing.html", "<html>es pricing</html>"),
            ("products/factory.html", "<html>factory</html>"),
            ("_app/app.js", "console.log(1)"),
        ] {
            std::fs::write(dir.join(file), body).expect(file);
        }
        dir
    }

    async fn get(app: Router, path: &str) -> Response {
        app.oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
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
        config.static_dir = Some(bundle("only-when-configured"));
        let make = || app(lazy_db(), &config).expect("app assembles");

        // `/apiary` is a legal org slug: a page, not an API path.
        for path in ["/o/acme/members", "/apiary"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), Some("noindex, nofollow"), "{path}");
            assert_eq!(body(res).await, "<html>shell</html>", "{path}");
        }

        let (status, body) = status_and_body(make(), "/_app/app.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log(1)");

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

    /// Prerendered pages answer as themselves and are indexable; only the
    /// shell, wherever it stands in for a page that does not exist, carries
    /// `noindex`.
    #[tokio::test]
    async fn prerendered_pages_are_served_without_the_shell() {
        let mut config = Config::for_test();
        config.static_dir = Some(bundle("prerendered"));
        let make = || app(lazy_db(), &config).expect("app assembles");

        for (path, expected) in [
            ("/", "<html>landing</html>"),
            ("/pricing", "<html>pricing</html>"),
            ("/pricing?ref=nav", "<html>pricing</html>"),
            // `es/` is also a directory; a directory lookup would redirect to
            // `/es/` and then find no `es/index.html`.
            ("/es", "<html>es landing</html>"),
            ("/es/pricing", "<html>es pricing</html>"),
            ("/products/factory", "<html>factory</html>"),
        ] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), None, "{path}");
            assert_eq!(body(res).await, expected, "{path}");
        }
    }

    /// The shell's own names, the landing page's file name, and a missing
    /// asset: each has one right answer, and none of them is a page.
    #[tokio::test]
    async fn the_shell_and_index_names_are_not_pages() {
        let mut config = Config::for_test();
        config.static_dir = Some(bundle("names"));
        let make = || app(lazy_db(), &config).expect("app assembles");

        for path in ["/index.html", "/index"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(
                res.headers().get("location").and_then(|v| v.to_str().ok()),
                Some("/"),
                "{path}"
            );
        }

        for path in ["/200", "/200.html", "/200/"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), Some("noindex, nofollow"), "{path}");
            assert_eq!(body(res).await, "<html>shell</html>", "{path}");
        }

        // A missing script answered with HTML is a syntax error in the
        // browser and a cache entry nobody can explain. It stays a 404.
        let res = get(make(), "/_app/missing.js").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(robots(&res), None);
        assert!(!body(res).await.contains("shell"));
    }

    fn robots(res: &Response) -> Option<&str> {
        res.headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok())
    }

    async fn body(res: Response) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
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
