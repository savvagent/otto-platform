//! Personal access tokens — the compatibility path for clients whose OAuth
//! support is partial or absent.
//!
//! A PAT is not a weaker credential. It lands in the same table as an OAuth
//! access token, carries the same audience, the same scope model, and the same
//! per-request introspection, so nothing downstream can tell which kind it
//! received. That equivalence is the point: agent-agnosticism must not mean a
//! weaker security model for the awkward clients, or the awkward clients become
//! the way in.
//!
//! Three rules hold here.
//!
//! **A token is shown exactly once.** Only the SHA-256 hash is stored, so there
//! is no second chance by construction — the console has to make the user copy
//! it now.
//!
//! **You mint your own.** An admin cannot mint a token for another member. A
//! credential that acts as someone else, created by someone else, makes the
//! audit trail a work of fiction; an admin who needs an agent running in the
//! org can mint one as themselves.
//!
//! **Scopes cannot exceed what the resource server defines.** The request names
//! a resource server and scopes, and they are validated against that server's
//! registry row — the same one the authorization server uses — so a PAT can
//! never carry a scope an OAuth token could not.

use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use otto_auth::tokens::{self, TokenSummary};
use otto_tenant::audit::{action, Entry};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::oauth::{resolve_resource, ADMIN_SCOPE};
use crate::session::OrgCtx;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintTokenRequest {
    /// What this token is for — "laptop", "CI runner". Shown in the list, and
    /// the only thing a user has to go on when deciding what to revoke.
    pub name: String,
    /// The resource server the token is for, by its RFC 8707 resource URI.
    /// May be omitted only while exactly one is registered, the same rule the
    /// authorization endpoint applies to a client that names none; see
    /// [`crate::oauth::resolve_resource`].
    #[serde(default)]
    pub resource: Option<String>,
    /// Defaults to the resource server's default scopes, matching the
    /// authorization server's behaviour for a client that asks for nothing in
    /// particular.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Days until expiry. Clamped to 1–365 by `otto-auth`; defaults to 90.
    #[serde(default)]
    pub ttl_days: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintedToken {
    /// **Shown once.** Only its hash is stored.
    pub token: String,
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    /// The resource this token is audienced for — the endpoint to paste it
    /// against. Returned so the console can render a complete, copyable client
    /// configuration rather than half of one.
    pub resource: String,
}

/// `GET /api/orgs/{org}/tokens` — the caller's live tokens in this org.
///
/// Yours only, OAuth tokens included, so a person can see every agent connected
/// as them and cut off any of them.
pub async fn list_tokens(
    State(state): State<AppState>,
    ctx: OrgCtx,
) -> ApiResult<Json<Vec<TokenSummary>>> {
    Ok(Json(
        tokens::list_tokens(&state.db, ctx.user.id, ctx.org.id).await?,
    ))
}

/// `POST /api/orgs/{org}/tokens` — mint a PAT.
pub async fn mint_token(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Json(req): Json<MintTokenRequest>,
) -> ApiResult<Response> {
    // Validated against the named resource server's registry row, so an unknown
    // scope is refused here exactly as it would be at `/oauth/authorize`
    // — and an empty request gets the same default scopes. `mint_pat`
    // checks the registry again; resolving it here is what gives the
    // `org:admin` check below, and the response, the effective scopes.
    let resource = resolve_resource(&state.db, req.resource.as_deref()).await?;
    let scopes = resource.grant_scopes(&req.scopes)?;

    // `org:admin` is a real capability, not a label: it must not be mintable by
    // someone who does not have it.
    if scopes.iter().any(|s| s == ADMIN_SCOPE) {
        ctx.require_admin().map_err(|_| {
            ApiError::forbidden(
                "the org:admin scope needs an owner or admin of this org; \
                 mint the token without it, or ask an admin",
            )
        })?;
    }

    let (token, id) = tokens::mint_pat(
        &state.db,
        ctx.user.id,
        ctx.org.id,
        &req.name,
        &scopes,
        &resource.resource_uri,
        req.ttl_days,
    )
    .await?;

    let _ = state
        .db
        .audit_for_org(
            ctx.org.id,
            Entry::new(action::PAT_MINTED)
                .actor(ctx.user.id)
                .target("token", id.to_string())
                .detail(serde_json::json!({ "name": req.name, "scopes": scopes })),
        )
        .await;

    Ok((
        http::StatusCode::CREATED,
        Json(MintedToken {
            token,
            id,
            name: req.name.trim().to_string(),
            scopes,
            resource: resource.resource_uri,
        }),
    )
        .into_response())
}

/// `DELETE /api/orgs/{org}/tokens/{id}` — revoke one of your tokens.
///
/// Takes effect when the resource server next introspects the token — the
/// agent's next call, or the end of the resource server's short positive-cache
/// window — rather than at some later expiry.
pub async fn revoke_token(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, id)): Path<(String, Uuid)>,
) -> ApiResult<Response> {
    // Scoped to the caller inside `otto-auth`, so this cannot revoke another
    // member's token even with their id.
    let revoked = tokens::revoke_by_id(&state.db, ctx.user.id, ctx.org.id, id).await?;

    if !revoked {
        return Err(ApiError::not_found(
            "no live token of yours with that id in this org",
        ));
    }

    let _ = state
        .db
        .audit_for_org(
            ctx.org.id,
            Entry::new(action::PAT_REVOKED)
                .actor(ctx.user.id)
                .target("token", id.to_string()),
        )
        .await;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}
