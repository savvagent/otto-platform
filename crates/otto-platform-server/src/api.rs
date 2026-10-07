//! What the resource-server endpoints (`/oauth/introspect`, `/internal/*`)
//! share: the error envelope and authentication of the calling resource
//! server.

use axum::extract::FromRequestParts;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, WWW_AUTHENTICATE};
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
    /// Anything the caller cannot fix. Logged here, never shown.
    Internal,
}

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
        let (status, code, description) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "resource server authentication failed".to_owned(),
            ),
            ApiError::BadRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            ApiError::TooLarge(d) => (StatusCode::PAYLOAD_TOO_LARGE, "too_large", d),
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
        if status == StatusCode::UNAUTHORIZED {
            res.headers_mut().insert(
                WWW_AUTHENTICATE,
                "Basic realm=\"otto-platform\", charset=\"UTF-8\""
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
/// Every failure is the same 401, so the endpoints cannot be used to learn
/// which resource servers exist.
pub struct CallingResourceServer(pub ResourceServer);

impl FromRequestParts<Db> for CallingResourceServer {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, db: &Db) -> Result<Self, ApiError> {
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
            resources::authenticate_introspection(db, &resource_uri, secret).await
        } else if scheme.eq_ignore_ascii_case("bearer") {
            resources::authenticate_secret(db, rest).await
        } else {
            return Err(ApiError::Unauthorized);
        };

        match result {
            Ok(rs) => Ok(Self(rs)),
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
