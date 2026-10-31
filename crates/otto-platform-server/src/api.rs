//! What the resource-server endpoints (`/oauth/introspect`, `/internal/*`)
//! share: the error envelope and authentication of the calling resource
//! server.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use otto_auth::resources::{self, ResourceServer};
use otto_auth::AuthError;
use otto_tenant::Db;
use percent_encoding::percent_decode_str;

/// A failed request, rendered as `{"error": "<code>", "error_description": "..."}`.
#[derive(Debug)]
pub enum ApiError {
    /// Missing or wrong resource-server credential.
    Unauthorized,
    BadRequest(String),
    NotFound,
    TooLarge(String),
    /// Refused for now, nothing changed, and the same request should succeed
    /// on a retry: a 503 with `Retry-After`, which the client treats as
    /// retriable.
    Unavailable(String),
    /// Anything the caller cannot fix. Logged here, never shown.
    Internal,
}

/// How long a [`ApiError::Unavailable`] caller is asked to wait.
pub const RETRY_AFTER_SECS: u32 = 5;

impl ApiError {
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "resource-server API request failed");
        ApiError::Internal
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(e)
    }
}
impl From<otto_tenant::Error> for ApiError {
    fn from(e: otto_tenant::Error) -> Self {
        Self::internal(e)
    }
}
impl From<otto_core::Error> for ApiError {
    fn from(e: otto_core::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = matches!(self, ApiError::Unavailable(_));
        let (status, code, description) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "resource server authentication failed".to_owned(),
            ),
            ApiError::BadRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            ApiError::TooLarge(d) => (StatusCode::PAYLOAD_TOO_LARGE, "too_large", d),
            ApiError::Unavailable(d) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                d,
            ),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error".to_owned(),
            ),
        };
        let mut res = (
            status,
            Json(serde_json::json!({ "error": code, "error_description": description })),
        )
            .into_response();
        res.headers_mut()
            .insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
        if retry_after {
            // Seconds, as otto-web's 503s say it.
            res.headers_mut()
                .insert(RETRY_AFTER, RETRY_AFTER_SECS.into());
        }
        if status == StatusCode::UNAUTHORIZED {
            res.headers_mut().insert(
                WWW_AUTHENTICATE,
                "Basic realm=\"savvagent\", charset=\"UTF-8\""
                    .parse()
                    .expect("static header"),
            );
        }
        res
    }
}

/// The authenticated calling resource server.
///
/// Two forms are accepted, both carrying the credential issued by
/// `otto-platform-server resource rotate-secret`:
///
/// - `Authorization: Basic base64(client_id:secret)`, with `client_id` the
///   resource server's `resource_uri`, percent-encoded as RFC 6749 §2.3.1
///   says (a URI contains `:`, which would otherwise end the username).
/// - `Authorization: Bearer <secret>`. The secret is unique and identifies the
///   server by itself.
///
/// With Basic, the client id may also be a live alias of the server's
/// canonical URI (`resource rename`), so a server still configured with its
/// old URI keeps working until the alias's sunset.
///
/// Every failure is the same 401, so the endpoints cannot be used to learn
/// which resource servers exist.
pub struct CallingResourceServer {
    /// The canonical row, whichever URI the caller named. Usage ingest, dedupe
    /// and the token audience check key on `server.resource_uri`.
    pub server: ResourceServer,
    /// The URI the caller authenticated as. Introspection's `aud`, and
    /// nothing else.
    pub audience: AuthenticatedAudience,
}

/// The URI a resource server authenticated as: the Basic client id (its
/// canonical URI or a live alias), or its canonical URI on the Bearer path,
/// which names none.
///
/// **For introspection's `aud` only.** It may be an alias, so never store,
/// key or compare anything by it; that is what `server.resource_uri` is for.
/// A type of its own, built only here and readable only as a string, so it
/// cannot be passed where a resource URI is expected by accident.
#[derive(Debug, Clone)]
pub struct AuthenticatedAudience(String);

impl AuthenticatedAudience {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S> FromRequestParts<S> for CallingResourceServer
where
    Db: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let db = &Db::from_ref(state);
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let (scheme, rest) = header.split_once(' ').ok_or(ApiError::Unauthorized)?;
        let rest = rest.trim();

        let result = if scheme.eq_ignore_ascii_case("basic") {
            let decoded = B64.decode(rest).map_err(|_| ApiError::Unauthorized)?;
            let decoded = String::from_utf8(decoded).map_err(|_| ApiError::Unauthorized)?;
            let (user, secret) = decoded.split_once(':').ok_or(ApiError::Unauthorized)?;
            let resource_uri = percent_decode_str(user)
                .decode_utf8()
                .map_err(|_| ApiError::Unauthorized)?;
            resources::authenticate_introspection(db, &resource_uri, secret)
                .await
                .map(|r| Self {
                    server: r.server,
                    audience: AuthenticatedAudience(r.named_as),
                })
        } else if scheme.eq_ignore_ascii_case("bearer") {
            resources::authenticate_secret(db, rest)
                .await
                .map(|rs| Self {
                    audience: AuthenticatedAudience(rs.resource_uri.clone()),
                    server: rs,
                })
        } else {
            return Err(ApiError::Unauthorized);
        };

        match result {
            Ok(caller) => Ok(caller),
            Err(AuthError::InvalidClient(_)) => Err(ApiError::Unauthorized),
            Err(e) => Err(ApiError::internal(e)),
        }
    }
}

/// The wire form of a role.
pub fn wire_role(role: otto_core::orgs::Role) -> otto_resource::Role {
    use otto_core::orgs::Role;
    match role {
        Role::Owner => otto_resource::Role::Owner,
        Role::Admin => otto_resource::Role::Admin,
        Role::Member => otto_resource::Role::Member,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_a_503_with_retry_after() {
        let res = ApiError::Unavailable("later".into()).into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(RETRY_AFTER).unwrap(), "5");
        let res = ApiError::Internal.into_response();
        assert!(res.headers().get(RETRY_AFTER).is_none());
    }
}
