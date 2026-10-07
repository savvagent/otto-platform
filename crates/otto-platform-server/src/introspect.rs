//! `POST /oauth/introspect` — RFC 7662 token introspection for resource
//! servers.
//!
//! A resource server presents an opaque bearer token it received and asks
//! whether it is good *for it*. The audience rule is the point: a resource
//! server is told about tokens minted for its own `resource_uri` and nothing
//! else. A token minted for another resource server comes back
//! `{"active": false}`, indistinguishable from one that never existed, so a
//! compromised or curious resource server cannot learn anything about, or
//! replay, tokens meant for a sibling.
//!
//! Beyond the token's own validity (not revoked, not expired), active also
//! means the user is *still* a member of the token's org, the org still
//! exists, and the account is not disabled. The token is fixed to an org at
//! issuance but membership is not, and without this a removed member's token
//! would work until it expired. The `role` returned is the role today.
//!
//! Every inactive outcome is a 200 with `{"active": false}` (RFC 7662 §2.2).
//! Only a bad resource-server credential is an error: 401.

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use otto_auth::tokens::{self, TokenKind};
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_resource::IntrospectionResponse;
use otto_tenant::Db;
use serde::Deserialize;

use crate::api::{wire_role, ApiError, CallingResourceServer};

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/oauth/introspect", post(introspect))
        .with_state(db)
}

#[derive(Deserialize)]
struct IntrospectForm {
    token: Option<String>,
    // Accepted and ignored (RFC 7662 §2.1: a hint is optional and the server
    // must still look in the other places if it is wrong). Tokens here are
    // looked up by hash in one table either way.
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

async fn introspect(
    State(db): State<Db>,
    CallingResourceServer(rs): CallingResourceServer,
    Form(form): Form<IntrospectForm>,
) -> Result<Response, ApiError> {
    let token = form.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest("`token` is required".into()));
    }

    let body = match tokens::introspect(&db, token, &rs.resource_uri).await {
        Ok(p) => match db.active_member_role(p.org_id, p.user_id).await? {
            Some(role) => active(&rs.resource_uri, p, role),
            None => IntrospectionResponse::inactive(),
        },
        // Unknown, revoked, expired, and wrong-audience are one answer.
        Err(AuthError::Revoked | AuthError::Expired | AuthError::WrongAudience) => {
            IntrospectionResponse::inactive()
        }
        Err(e) => return Err(ApiError::internal(e)),
    };

    // RFC 7662 §4: the response is sensitive and must not be cached.
    let mut res = Json(body).into_response();
    res.headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
    res.headers_mut()
        .insert(PRAGMA, "no-cache".parse().expect("static header"));
    Ok(res)
}

fn active(resource_uri: &str, p: tokens::Principal, role: Role) -> IntrospectionResponse {
    IntrospectionResponse {
        active: true,
        sub: Some(p.user_id.as_uuid()),
        org_id: Some(p.org_id.as_uuid()),
        role: Some(wire_role(role)),
        scope: Some(p.scopes.join(" ")),
        aud: Some(resource_uri.to_owned()),
        exp: Some(p.expires_at.timestamp()),
        client_id: p.client_id,
        token_type: Some("Bearer".into()),
        token_kind: Some(match p.kind {
            TokenKind::Oauth => otto_resource::TokenKind::Oauth,
            TokenKind::Pat => otto_resource::TokenKind::Pat,
        }),
        jti: Some(p.token_id),
    }
}
