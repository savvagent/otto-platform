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
//! router. Lifecycle webhooks are delivered by [`webhooks::run`], and
//! notification email by [`email::run`] when SMTP is configured, and Stripe
//! sync by [`stripe_cmd::run_loop`] and metered usage to Stripe meter events
//! by [`stripe_shipper::run`] when billing is enabled, background tasks the
//! binary starts; `otto-platform-server resource ...` provisions
//! resource servers ([`resource_cmd`]), `otto-platform-server client ...`
//! registers first-party OAuth clients ([`client_cmd`]),
//! `otto-platform-server pricebook ...` sets what each value meter costs
//! ([`pricebook_cmd`]), and `otto-platform-server stripe sync` makes Stripe
//! match the price book ([`stripe_cmd`]). The console bundle is
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
pub mod email;
pub mod health;
pub mod internal;
pub mod introspect;
pub mod pricebook_cmd;
pub mod resource_cmd;
pub mod stripe_cmd;
pub mod stripe_shipper;
pub mod usage_cmd;
pub mod webhooks;

use std::convert::Infallible;
use std::path::Path;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use otto_tenant::Db;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use tower::ServiceExt;
use tower_http::services::fs::ServeFileSystemResponseBody;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub use config::{Config, EmailConfig, LogFormat, StripeConfig};
pub use internal::Billing;

/// The routes that need only a database handle and whether billing is
/// enabled: health and the resource-server API.
pub fn router(db: Db, billing: Billing) -> Router {
    health::router(db.clone())
        .merge(introspect::router(db.clone()))
        .merge(internal::router(db, billing))
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

    let app = health::router(db.clone())
        .merge(introspect::router(db.clone()))
        .merge(internal::router_with_hold_threshold(
            db,
            internal::billing_of(config),
            config.usage_hold_threshold,
        ))
        .merge(web);
    // Either way an unmatched API-shaped or undecodable path answers JSON: a
    // client that guessed a route needs something it can parse. The exception
    // is a miss under the bundle that is not a page route, such as a missing
    // `/_app/x.js` or a `POST` to a page: that keeps tower-http's own answer,
    // an empty-bodied `404` or `405` (see `route`, step 10).
    let app = match &config.static_dir {
        Some(dir) => app.fallback_service(console(dir)?),
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
/// Everything else goes to the console bundle (a prerendered page, or else the
/// SPA shell), which is what makes a hard refresh of `/o/acme/members` work.
/// It is matched on the decoded, slash-collapsed path, the way the Worker's
/// `belongsToOrigin` matches. An unmatched path under one of these must not: a
/// client that `GET`s `/api/orgs/nope` needs a `404` it can parse, and
/// `200 text/html` is the shape that makes a client retry forever against a
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
/// has no file. [`route`] decides which answers.
///
/// Refuses to build without a readable `200.html`. Every client route is
/// served from it, so a bundle without one is a console whose every deep link
/// is a `404`, and that is a failure to name at startup, not to discover from
/// a user.
///
/// **Readable, not just present**, because tower-http answers a file it may
/// not open (`PermissionDenied`) with `404`, exactly as if it were missing
/// (documented on `ServeDir::try_call`). For a prerendered page that means an
/// unreadable `pricing.html` is a miss, and the visitor gets the noindex shell
/// in its place: a deploy-time permissions mistake that degrades the page
/// rather than breaking it. For the shell there is nothing behind it, so
/// opening it here is the guard; [`serve_shell`] logs if it fails later.
fn console(
    static_dir: &Path,
) -> Result<
    impl tower::Service<Request<Body>, Response = Response, Error = Infallible, Future = impl Send>
        + Clone
        + Send
        + 'static,
> {
    let shell_path = static_dir.join(SHELL);
    // Opened, not just stat'ed: see the doc comment. `File::open` succeeds on
    // a directory, hence the metadata check as well.
    let readable = std::fs::File::open(&shell_path).and_then(|f| f.metadata());
    anyhow::ensure!(
        readable.as_ref().is_ok_and(|meta| meta.is_file()),
        "OTTO_STATIC_DIR is {}, which has no readable {SHELL} ({}): the console bundle must \
         carry the SPA shell there (adapter-static `fallback: '{SHELL}'`), readable by this \
         process",
        static_dir.display(),
        match &readable {
            Ok(_) => "not a file".to_owned(),
            Err(err) => err.to_string(),
        }
    );
    // Directory appending off, and no fallback: a directory is not a page
    // (`/_app` is not a `307` to `/_app/`, which the trailing-slash rule would
    // send straight back), and each step in `route` decides what a miss means.
    let files = ServeDir::new(static_dir).append_index_html_on_directories(false);
    let shell = ServeFile::new(shell_path);

    Ok(tower::service_fn(move |req: Request<Body>| {
        let (files, shell) = (files.clone(), shell.clone());
        async move { Ok(route(&files, shell, req).await) }
    }))
}

/// Where adapter-static writes the SPA shell.
const SHELL: &str = "200.html";

/// One console request. Order matters, and each step is here because the one
/// after it gets that case wrong.
///
/// Every decision is made on the *decoded* path, because that is what
/// `ServeDir` looks up: deciding on the raw one lets `/%32%30%30` reach
/// `200.html` without its header, `/%69ndex.html` skip the redirect, and
/// `/_app/missing%2Ejs` look extensionless and get HTML. The lookups
/// themselves get the raw path and leave decoding and sanitisation to
/// tower-http; nothing here joins a request path onto the directory.
///
/// 1. A path that does not decode (a malformed escape such as `%zz`, or bytes
///    that are not UTF-8) names no file and no route: a JSON `404`, as the
///    Worker answers it.
/// 2. So does a path with a `.` or `..` segment. hyper does not normalise
///    them and tower-http skips `.`, so `/./200.html` would otherwise be
///    `200.html` served as an asset, without its header, and `/./index.html`
///    would skip step 4. A browser never sends one: URL parsing removes them.
/// 3. API-shaped paths answer a JSON `404` before anything can answer HTML.
/// 4. `/index.html` (and `/index`) is `308`'d to `/`: one URL for the landing
///    page.
/// 5. `/200` and `/200.html` are the shell with its header, for any method.
/// 6. A trailing slash is `308`'d away (`/pricing/` → `/pricing`, `///` →
///    `/`), as Cloudflare's `auto-trailing-slash` and SvelteKit's
///    `trailingSlash: 'never'` both do.
/// 7. An extensionless path is a page: `<path>.html`, or `index.html` for
///    `/`. This runs before the plain lookup because `es/` is a directory as
///    well as `es.html` a file.
/// 8. A request for a page's own file, `/pricing.html`, is `308`'d to
///    `/pricing`, as the Cloudflare binding does: one URL per page.
/// 9. The path as given: the assets.
/// 10. What is left: an extensionless `GET`/`HEAD` gets the shell, and
///     anything else keeps its answer. A missing `/_app/x.js` answered with
///     HTML is a syntax error in the browser.
///
/// Only a `404` moves on to the next step. A `412`, `416` or `500` from a
/// lookup is that file's real answer, and replacing it with the shell would
/// hide it.
async fn route(files: &ServeDir, shell: ServeFile, req: Request<Body>) -> Response {
    let original = req.uri().path();
    let raw = collapse_slashes(original);
    let Some(decoded) = strict_decode(&raw) else {
        return not_found(&raw);
    };
    // Again after decoding: `%2F` is a slash to the file system too.
    let path = collapse_slashes(&decoded);
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return not_found(&raw);
    }
    if is_api_path(&path) {
        return not_found(&path);
    }

    let query = req.uri().query();
    let bare = path.trim_end_matches('/');
    if bare == "/index.html" || bare == "/index" {
        return landing_redirect(query);
    }
    if bare == "/200" || bare == "/200.html" {
        return serve_shell(shell, req).await;
    }

    let page_method = req.method() == Method::GET || req.method() == Method::HEAD;
    // On the path as sent, so `///` redirects as it does at the edge rather
    // than collapsing silently into `/`.
    if page_method && original != "/" && original.ends_with('/') {
        return redirect_on_site(bare, query);
    }

    let last = path.rsplit('/').next().unwrap_or("");
    let extensionless = !last.contains('.');
    if extensionless {
        let page = if path == "/" {
            "/index.html".to_owned()
        } else {
            format!("{raw}.html")
        };
        let res = lookup(files, &req, &page).await;
        if res.status() != StatusCode::NOT_FOUND {
            return res;
        }
    }

    let res = lookup(files, &req, &raw).await;
    if page_method && last.ends_with(".html") && res.status() != StatusCode::NOT_FOUND {
        if let Some(page) = path.strip_suffix(".html") {
            return redirect_on_site(page, query);
        }
    }
    if res.status() != StatusCode::NOT_FOUND || !(extensionless && page_method) {
        return res;
    }
    serve_shell(shell, req).await
}

/// Percent-decoding that refuses what `percent_decode_str` lets through: a
/// `%` not followed by two hex digits, and bytes that are not UTF-8. The
/// Worker's `decodeURIComponent` throws on both, and the two sides must agree
/// on what a path is.
fn strict_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let well_formed = bytes.iter().enumerate().all(|(i, &b)| {
        b != b'%'
            || (bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    });
    if !well_formed {
        return None;
    }
    percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .map(|decoded| decoded.into_owned())
}

/// `/index.html` → `/`, keeping the query. The target is a constant, so this
/// cannot be steered off-site.
fn landing_redirect(query: Option<&str>) -> Response {
    let location = match query {
        Some(q) => format!("/?{q}"),
        None => "/".to_owned(),
    };
    Redirect::permanent(&location).into_response()
}

/// What must be escaped to put a decoded path back into a `Location`: the
/// characters a URI path cannot carry, plus `%` (so a decoded `%` stays
/// literal) and `\` (which browsers read as `/`).
const LOCATION_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// A `308` to the decoded, slash-collapsed `path` on this site, keeping the
/// query. Leading slashes are stripped and exactly one put back, and `\` is
/// escaped, so the `Location` can never be `//host` (or `/\host`, which
/// browsers read the same way): a redirect built from the request path must
/// not be an open redirect.
fn redirect_on_site(path: &str, query: Option<&str>) -> Response {
    let encoded = utf8_percent_encode(path.trim_start_matches('/'), LOCATION_PATH);
    let location = match query {
        Some(q) => format!("/{encoded}?{q}"),
        None => format!("/{encoded}"),
    };
    Redirect::permanent(&location).into_response()
}

/// One file from the bundle, by (still encoded) path and nothing else: the
/// query means nothing to a file lookup.
///
/// Not an `async fn`: the request copy is built before the returned future
/// exists, because a `Request<Body>` is not `Sync`, and a reference to one
/// held across an `await` would make the whole service's future not `Send`.
fn lookup(
    files: &ServeDir,
    req: &Request<Body>,
    path: &str,
) -> impl std::future::Future<Output = Response> + Send + 'static {
    let copy = path
        .parse::<Uri>()
        .map(|uri| with_uri(req, uri))
        .map_err(|err| {
            // Built from a path that was already a valid URI plus `.html`, so
            // this should not happen; if it does, it is a miss, said out loud.
            tracing::warn!(%err, path, "console lookup path is not a valid URI");
            not_found(path)
        });
    let files = files.clone();
    async move {
        match copy {
            Ok(copy) => serve(files, copy).await,
            Err(res) => res,
        }
    }
}

/// The shell, marked `X-Robots-Tag: noindex, nofollow` wherever it answers.
/// It is the same HTML for every route it stands in for, and an indexed shell
/// is a search result for `/o/acme/members` that renders a login prompt.
/// Prerendered pages are the ones meant to be found, and go without it.
///
/// A `404` or `5xx` here means the shell checked at startup has since gone
/// missing or become unreadable (tower-http reports `PermissionDenied` as
/// `404`), so every client route is now broken: logged as an error. Other
/// non-`2xx` answers are the request's own doing (`304` for a conditional
/// `GET`, `405` for a `POST` to `/200`, `412`, `416`) and are not.
async fn serve_shell(shell: ServeFile, req: Request<Body>) -> Response {
    let path = req.uri().path().to_owned();
    let res = serve(shell, req).await;
    let status = res.status();
    if status == StatusCode::NOT_FOUND || status.is_server_error() {
        tracing::error!(
            %status,
            path,
            "the SPA shell ({SHELL}) could not be served; every client route is failing"
        );
    }
    noindex(res)
}

fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if !(c == '/' && out.ends_with('/')) {
            out.push(c);
        }
    }
    out
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

    Ok(otto_web::AppState::new(db, cipher, webauthn, web_config).with_stripe(stripe(config)?))
}

/// Billing's Stripe client and webhook secret, or `None` when billing is
/// disabled. Production Stripe: there is no setting for another base URL, and
/// tests build their client against a local mock directly.
pub fn stripe(config: &Config) -> Result<Option<otto_billing::billing::Stripe>> {
    config
        .stripe
        .as_ref()
        .map(|s| {
            Ok(otto_billing::billing::Stripe {
                client: otto_billing::stripe::Client::new(s.secret_key.clone())
                    .context("could not build the Stripe client")?,
                webhook_secret: s.webhook_secret.clone(),
            })
        })
        .transpose()
}

/// Refuse a Stripe key whose mode (live or test) differs from the one this
/// database's Stripe objects were made in, recording the mode the first time
/// ([`otto_billing::billing::check_key_mode`]). Nothing to check with billing
/// disabled. Called at boot, before anything talks to Stripe.
pub async fn verify_stripe_mode(db: &Db, config: &Config) -> Result<()> {
    let Some(stripe) = &config.stripe else {
        return Ok(());
    };
    let mode = otto_billing::billing::check_key_mode(db, &stripe.secret_key)
        .await
        .context("refusing to start: the Stripe key does not fit this database")?;
    tracing::info!(stripe_mode = %mode, "Stripe key mode matches this database");
    Ok(())
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
    fn billing_follows_the_stripe_secrets() {
        let mut config = Config::for_test();
        assert!(stripe(&config).unwrap().is_none());
        config.stripe =
            config::parse_stripe(Some("sk_test_x".into()), Some("whsec_x".into())).unwrap();
        assert!(stripe(&config).unwrap().is_some());
    }

    #[test]
    fn billing_mode_follows_the_stripe_secrets() {
        let mut config = Config::for_test();
        assert_eq!(internal::billing_of(&config), Billing::Disabled);
        config.stripe =
            config::parse_stripe(Some("sk_test_x".into()), Some("whsec_x".into())).unwrap();
        assert_eq!(internal::billing_of(&config), Billing::Enabled);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_stripe_key_of_the_other_mode_is_refused_at_boot(pool: sqlx::PgPool) {
        let db = Db::from_pool(pool);
        let mut config = Config::for_test();
        // Billing off: nothing to check, nothing recorded.
        verify_stripe_mode(&db, &config).await.unwrap();
        config.stripe =
            config::parse_stripe(Some("sk_test_supersecret".into()), Some("whsec_x".into()))
                .unwrap();
        verify_stripe_mode(&db, &config).await.unwrap();
        verify_stripe_mode(&db, &config).await.unwrap();
        config.stripe =
            config::parse_stripe(Some("rk_live_supersecret".into()), Some("whsec_x".into()))
                .unwrap();
        let err = format!("{:#}", verify_stripe_mode(&db, &config).await.unwrap_err());
        assert!(err.contains("refusing to start"), "{err}");
        assert!(err.contains("live-mode key"), "{err}");
        assert!(err.contains("test mode"), "{err}");
        assert!(!err.contains("supersecret"), "{err}");
    }

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
    /// different, so a test can tell which one answered.
    ///
    /// One directory per test, because tests in one binary share a pid and run
    /// concurrently, and removed on drop. (No `tempfile` in the workspace.)
    struct Bundle(std::path::PathBuf);

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn bundle(test: &str) -> Bundle {
        let dir =
            std::env::temp_dir().join(format!("otto-console-test-{}-{test}", std::process::id()));
        for sub in ["_app", "es", "products"] {
            std::fs::create_dir_all(dir.join(sub)).expect("mkdir");
        }
        for (file, body) in [
            ("200.html", SHELL_HTML),
            ("index.html", "<html>landing</html>"),
            ("pricing.html", "<html>pricing</html>"),
            ("es.html", "<html>es landing</html>"),
            ("es/pricing.html", "<html>es pricing</html>"),
            ("products/factory.html", "<html>factory</html>"),
            ("_app/app.js", "console.log(1)"),
        ] {
            std::fs::write(dir.join(file), body).expect(file);
        }
        Bundle(dir)
    }

    const SHELL_HTML: &str = "<html>shell</html>";

    /// A router over a fresh bundle; the bundle must outlive the router.
    fn console_app(bundle: &Bundle) -> Router {
        let mut config = Config::for_test();
        config.static_dir = Some(bundle.0.clone());
        app(lazy_db(), &config).expect("app assembles")
    }

    async fn send(app: Router, req: Request<Body>) -> Response {
        app.oneshot(req).await.unwrap()
    }

    fn location(res: &Response) -> Option<&str> {
        res.headers().get("location").and_then(|v| v.to_str().ok())
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
        let bundle = bundle("only-when-configured");
        let make = || console_app(&bundle);

        // `/apiary` is a legal org slug: a page, not an API path.
        for path in ["/o/acme/members", "/apiary"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), Some("noindex, nofollow"), "{path}");
            assert_eq!(body(res).await, SHELL_HTML, "{path}");
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
        let bundle = bundle("prerendered");
        let make = || console_app(&bundle);

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
        let bundle = bundle("names");
        let make = || console_app(&bundle);

        for (path, to) in [
            ("/index.html", "/"),
            ("/index", "/"),
            ("/index.html?a=1", "/?a=1"),
        ] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(location(&res), Some(to), "{path}");
        }

        // Not the landing page's name, and not a redirect anywhere: a path
        // under a directory called `evil.com` that does not exist.
        let res = get(make(), "//evil.com/index.html").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(location(&res), None);

        for path in ["/200", "/200.html", "/200/"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), Some("noindex, nofollow"), "{path}");
            assert_eq!(body(res).await, SHELL_HTML, "{path}");
        }

        // A missing script answered with HTML is a syntax error in the
        // browser and a cache entry nobody can explain. It stays a 404.
        let res = get(make(), "/_app/missing.js").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(robots(&res), None);
        assert!(!body(res).await.contains("shell"));
    }

    /// Decisions are made on the decoded path, the one `ServeDir` looks up.
    /// On the raw one, an encoded name reaches the shell without its header,
    /// skips the landing redirect, or turns a missing asset into HTML.
    #[tokio::test]
    async fn percent_encoding_does_not_change_the_answer() {
        let bundle = bundle("encoded");
        let make = || console_app(&bundle);

        for path in ["/%32%30%30", "/200%2Ehtml", "/200%2ehtml"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(robots(&res), Some("noindex, nofollow"), "{path}");
            assert_eq!(body(res).await, SHELL_HTML, "{path}");
        }

        for path in ["/%69ndex.html", "/index%2Ehtml", "/%69ndex"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(location(&res), Some("/"), "{path}");
        }

        for path in ["/x%2Ejs", "/_app/missing%2Ejs"] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(robots(&res), None, "{path}");
            assert!(!body(res).await.contains("shell"), "{path}");
        }

        // An encoded API prefix is still the API's, as at the edge.
        let (status, body) = status_and_body(make(), "/%61pi/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("\"not_found\""), "{body}");

        // Not UTF-8 once decoded, or not an escape at all: no file, no
        // route, and the same JSON 404 the Worker gives.
        for path in ["/%FF", "/%zz", "/o/acme/%E0%A4%A", "/trailing%"] {
            let (status, body) = status_and_body(make(), path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(body.contains("\"not_found\""), "{path}: {body}");
        }

        // Dot segments, raw or encoded. hyper keeps them and tower-http skips
        // `.`, so each of these would otherwise reach a file by a name the
        // decisions above never saw.
        for path in [
            "/./200",
            "/./200.html",
            "/%2e/200",
            "/./index.html",
            "/a/../200",
            "/a%2F..%2F200",
        ] {
            let (status, body) = status_and_body(make(), path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(body.contains("\"not_found\""), "{path}: {body}");
        }
    }

    /// A trailing slash is redirected away, as Cloudflare and SvelteKit do,
    /// and the redirect is built so it can never leave the site.
    #[tokio::test]
    async fn a_trailing_slash_is_redirected_on_site() {
        let bundle = bundle("slash");
        let make = || console_app(&bundle);

        for (path, to) in [
            ("/pricing/", "/pricing"),
            ("/pricing/?a=1", "/pricing?a=1"),
            ("/es/", "/es"),
            ("/o/acme/", "/o/acme"),
            ("//evil.com/", "/evil.com"),
            ("///evil.com//", "/evil.com"),
            ("//", "/"),
            ("///", "/"),
        ] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(location(&res), Some(to), "{path}");
        }

        // A directory is not a page and not a 307 to itself with a slash,
        // which the rule above would send straight back. With no file of its
        // own it is a client route like any other.
        let res = get(make(), "/_app").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(robots(&res), Some("noindex, nofollow"));
    }

    /// Characters that decode to something meaningful in a URL are escaped
    /// again in the `Location`, so the redirect lands on the path that was
    /// asked for and never off the site: a decoded `\` would make `/\host`,
    /// which browsers read as `//host`.
    #[tokio::test]
    async fn a_redirect_escapes_what_the_path_decoded_to() {
        let bundle = bundle("escape");
        let make = || console_app(&bundle);

        for (path, to) in [
            ("/%5Cevil.com/", "/%5Cevil.com"),
            ("/%2F%2Fevil.com/", "/evil.com"),
            ("/a%3Fb/", "/a%3Fb"),
            ("/a%25b/", "/a%25b"),
        ] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(location(&res), Some(to), "{path}");
        }

        // A page whose name starts with a backslash, so the `<page>.html`
        // redirect is taken rather than missed. Unix only: elsewhere `\\` is
        // a separator, which is also what the lint is about.
        #[cfg(unix)]
        {
            #[allow(clippy::join_absolute_paths)]
            let page = bundle.0.join("\\evil.com.html");
            std::fs::write(page, "<html>evil</html>").expect("write");
            let res = get(make(), "/%5Cevil.com.html").await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(location(&res), Some("/%5Cevil.com"));
        }

        // Whatever these answer, a redirect among them stays on the site.
        for path in [
            "/%5Cevil.com.html",
            "/%5C%5Cevil.com.html",
            "/%2F%5Cevil.com.html",
        ] {
            let res = get(make(), path).await;
            if let Some(to) = location(&res) {
                assert!(
                    to.starts_with('/') && !to.starts_with("//") && !to.starts_with("/\\"),
                    "{path} redirected off-site to {to}"
                );
            }
        }
    }

    /// A page's own file is a second URL for it; the binding at the edge
    /// redirects it, and so does the server.
    #[tokio::test]
    async fn a_page_file_redirects_to_its_page() {
        let bundle = bundle("page-file");
        let make = || console_app(&bundle);

        for (path, to) in [
            ("/pricing.html", "/pricing"),
            ("/pricing.html?a=1", "/pricing?a=1"),
            ("/pricing%2Ehtml", "/pricing"),
            ("/es/pricing.html", "/es/pricing"),
            ("/es.html", "/es"),
        ] {
            let res = get(make(), path).await;
            assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(location(&res), Some(to), "{path}");
        }

        // No such page: a missing file, not a redirect to a client route.
        let res = get(make(), "/nope.html").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(location(&res), None);
    }

    /// Only a `404` falls through to the shell. Any other answer from a file
    /// lookup is that file's, and the shell would hide it.
    #[tokio::test]
    async fn only_a_miss_falls_through_to_the_shell() {
        let bundle = bundle("fallthrough");
        let make = || console_app(&bundle);

        let res = send(
            make(),
            Request::get("/pricing")
                .header("if-unmodified-since", "Thu, 01 Jan 1970 00:00:00 GMT")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(robots(&res), None);

        let res = send(
            make(),
            Request::get("/pricing")
                .header("range", "bytes=9999-")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(robots(&res), None);

        // A write to a page route is not a page view: no shell.
        let res = send(
            make(),
            Request::post("/o/acme/members")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(!body(res).await.contains("shell"));
    }

    /// `HEAD` on a client route is the shell's headers and no body.
    #[tokio::test]
    async fn head_on_a_client_route_is_the_shell_without_a_body() {
        let bundle = bundle("head");
        let res = send(
            console_app(&bundle),
            Request::head("/o/acme/members")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(robots(&res), Some("noindex, nofollow"));
        assert_eq!(
            res.headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some(SHELL_HTML.len().to_string().as_str())
        );
        assert_eq!(body(res).await, "");
    }

    /// A bundle without `200.html` would 404 every deep link. It is refused
    /// when the app is built, by name, not discovered from a user.
    #[tokio::test]
    async fn a_bundle_without_the_shell_is_refused_at_startup() {
        let bundle = bundle("no-shell");
        std::fs::remove_file(bundle.0.join("200.html")).expect("rm");
        let mut config = Config::for_test();
        config.static_dir = Some(bundle.0.clone());
        let err = app(lazy_db(), &config).expect_err("no shell, no app");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OTTO_STATIC_DIR") && msg.contains("200.html"),
            "{msg}"
        );
    }

    /// A shell that exists but cannot be read would be a `404` on every
    /// client route (tower-http reports `PermissionDenied` as a miss), so it
    /// is refused at startup like a missing one.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_shell_is_refused_at_startup() {
        use std::os::unix::fs::PermissionsExt;

        let bundle = bundle("unreadable-shell");
        let shell = bundle.0.join("200.html");
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::File::open(&shell).is_ok() {
            // Running as root, which reads it anyway: nothing to test.
            return;
        }
        let mut config = Config::for_test();
        config.static_dir = Some(bundle.0.clone());
        let err = app(lazy_db(), &config).expect_err("unreadable shell, no app");
        let msg = format!("{err:#}");
        assert!(msg.contains("readable 200.html"), "{msg}");
    }

    /// A directory named `200.html` opens, but is not a shell.
    #[tokio::test]
    async fn a_shell_that_is_a_directory_is_refused_at_startup() {
        let bundle = bundle("dir-shell");
        let shell = bundle.0.join("200.html");
        std::fs::remove_file(&shell).expect("rm");
        std::fs::create_dir(&shell).expect("mkdir");
        let mut config = Config::for_test();
        config.static_dir = Some(bundle.0.clone());
        assert!(app(lazy_db(), &config).is_err());
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
