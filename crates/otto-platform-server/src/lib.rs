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
//! ```
//!
//! The resource-server-facing endpoints authenticate with the resource
//! server's own credential ([`api::CallingResourceServer`]), not a session
//! cookie, and are outside `otto-web`'s CSRF guard, which only wraps its own
//! router. Lifecycle webhooks are delivered by [`webhooks::run`], a background
//! task the binary starts; `otto-platform-server resource ...` provisions
//! resource servers ([`resource_cmd`]). The console bundle is a separate piece
//! of Phase 4 of `docs/plans/2026-10-06-platform-cutover.md`.
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

use anyhow::{Context, Result};
use axum::Router;
use otto_tenant::Db;
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

    Ok(router(db)
        .merge(web)
        // Request spans, without headers. `DefaultMakeSpan::include_headers`
        // would put `Authorization` and `Cookie` into the logs — every bearer
        // token and every session cookie, in plaintext, in whatever the log
        // aggregator retains. Do not turn it on.
        .layer(TraceLayer::new_for_http()))
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
