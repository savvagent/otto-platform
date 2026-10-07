//! `otto-web` — the identity HTTP surface: the OAuth authorization server, the
//! sign-in and account APIs, and the org console's API.
//!
//! Everything a human touches, and the one place a human and an agent meet.
//! Resource servers (otto-factory's MCP endpoint, otto-flags, …) serve agents
//! over bearer tokens; this crate serves people over session cookies, and hosts
//! the consent screen where a signed-in human grants an agent a token for one
//! of them.
//!
//! ```text
//!   Browser ──► /api/…            session cookie ──► CurrentUser / OrgCtx ──► otto-core
//!           └─► /oauth/authorize  session cookie ──► consent ──► authorization code
//!   Agent   ──► /oauth/token      PKCE verifier  ──► access + refresh tokens
//! ```
//!
//! ## What holds across the whole crate
//!
//! **No SQL.** Every statement is an `otto-core`, `otto-auth` or `otto-billing`
//! method, because a query written here would bypass the tenant-pinned
//! transaction that isolation's second guard depends on.
//!
//! **Authorization is decided by an extractor, not by a handler.**
//! [`session::OrgCtx`] resolves the caller, the org in the path, and their role
//! before a handler body runs, and a handler that needs more than membership
//! says so in one line. A handler that forgets is a handler that serves another
//! tenant's data, and a type is a better place for that than a review checklist.
//!
//! **An org you are not in is `404`.** Answering `403` on a real slug and `404`
//! on a fake one turns any signed-in account into a directory of who uses the
//! product.
//!
//! **The router and the OpenAPI document come from one list.** See
//! [`catalog`] — routes and their descriptions are the same declaration, so
//! they cannot drift apart.
//!
//! **No resource server is special.** Nothing here knows what otto-factory or
//! otto-flags do. A token's audience and scopes come from the
//! `resource_servers` registry (`otto_auth::resources`), and a resource
//! server's own domain routes live in its own service.

pub mod catalog;
pub mod csrf;
pub mod error;
pub mod i18n;
pub mod oauth;
pub mod openapi;
pub mod routes;
pub mod session;
pub mod state;

use axum::Router;

pub use error::{ApiError, ApiResult};
pub use state::{AppState, Config};

/// Build the WebAuthn relying party this deployment signs with.
///
/// Fails loudly at startup rather than at somebody's first sign-in: an rp_id
/// that is not a registrable suffix of the origin produces ceremonies that no
/// browser will complete, and the error a user sees for that looks like their
/// device is broken.
pub fn relying_party(
    config: &Config,
) -> anyhow::Result<std::sync::Arc<otto_auth::passkeys::Webauthn>> {
    let rp_id = config.rp_id().ok_or_else(|| {
        anyhow::anyhow!(
            "OTTO_PUBLIC_URL ({}) has no host, so there is nothing to bind passkeys to",
            config.public_url
        )
    })?;
    let webauthn = otto_auth::passkeys::relying_party(&rp_id, &config.public_url)?;
    Ok(std::sync::Arc::new(webauthn))
}

/// Build the console surface, ready to be merged into `otto-platform-server`'s router.
///
/// Every route comes from [`catalog::catalog`]. Grouping by path before
/// mounting is not cosmetic: `Router::route` panics when the same path is
/// registered twice, so several methods on one path have to arrive as a single
/// merged `MethodRouter`.
pub fn router(state: AppState) -> Router {
    let mut by_path: Vec<(&'static str, axum::routing::MethodRouter<AppState>)> = Vec::new();

    for endpoint in catalog::catalog() {
        match by_path.iter_mut().find(|(path, _)| *path == endpoint.path) {
            Some((_, existing)) => {
                let merged = std::mem::replace(existing, axum::routing::MethodRouter::new());
                *existing = merged.merge(endpoint.route);
            }
            None => by_path.push((endpoint.path, endpoint.route)),
        }
    }

    by_path
        .into_iter()
        .fold(Router::new(), |router, (path, methods)| {
            router.route(path, methods)
        })
        .layer(axum::middleware::from_fn_with_state(
            csrf::allowed_origin(&state.config),
            csrf::check,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The router is built by merging method routers per path. If that merge is
    /// ever replaced with repeated `route` calls, axum panics at startup — which
    /// is a better failure than a silent one, but only if something builds the
    /// router before a deployment does.
    #[tokio::test]
    async fn the_router_assembles() {
        let db = otto_tenant::Db::from_pool(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                // Not connected — `connect_lazy` builds a pool without touching
                // the network, which is all this test needs.
                .connect_lazy("postgres://localhost/does-not-exist")
                .expect("lazy pool"),
        );

        let config = Config::new("https://otto.test");
        let state = AppState::new(
            db,
            otto_tenant::crypto::Cipher::from_base64_key(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .expect("test key"),
            relying_party(&config).expect("test relying party"),
            config,
        );

        let _router = router(state);
    }
}
