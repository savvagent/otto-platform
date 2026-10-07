//! The console API's error envelope.
//!
//! Every failure leaves here as `{"error": {"code": …, "message": …}}` with a
//! status that matches. `code` is the stable branch point a UI switches on;
//! `message` is what it shows a human. That is the same split `otto_core::Error`
//! already makes for agents, and it is deliberately the same envelope shape, so
//! a person debugging the console and a person debugging an agent are reading
//! the same thing.
//!
//! **Two rules about what goes in `message`.**
//!
//! A database error is never one of them. `otto_core::Error::Db` carries table
//! and constraint names, which tell an attacker about a schema they cannot
//! otherwise see and tell a user nothing they can act on. It is logged in full
//! and reported as a flat internal error.
//!
//! An *identity* failure gets [`AuthError::public`] and nothing else. The full
//! variant distinguishes "no such user" from "wrong code" from "replayed code";
//! the caller must not be able to. That distinction is the account enumeration
//! oracle `otto-auth` spends a whole module avoiding, and it would be
//! reintroduced here by one careless `to_string()`.
//!
//! The exception is an OAuth *protocol* error — `invalid_scope`,
//! `invalid_request`, `invalid_grant`. Those describe the caller's own request
//! rather than anyone's identity, so RFC 6749 §5.2 returns them verbatim and so
//! do we: there is nothing to enumerate, and "invalid_scope" with no further
//! word leaves an integrator with nothing to fix. `unknown scope "orgs:destroy";
//! supported scopes are …` is the whole difference between a five-second fix
//! and an afternoon.

use axum::response::{IntoResponse, Response};
use axum::Json;
use http::{header, HeaderValue, StatusCode};
use otto_auth::AuthError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Seconds until a throttled caller may retry, rendered as `Retry-After`.
    pub retry_after: Option<i64>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    /// No usable session. The console reads this and sends the user to sign in.
    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "sign in to continue",
        )
    }

    /// Signed in, but not allowed to do this.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// An unexpected failure. The detail is logged, never sent.
    pub fn internal(context: &str, e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, context, "console request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "something went wrong on our side; try again shortly",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({
                "error": { "code": self.code, "message": self.message },
            })),
        )
            .into_response();

        if let Some(secs) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }

        response
    }
}

impl ApiError {
    /// The database could not answer. `503`, not `500`: it is a "try again"
    /// condition, and a client that treats it as a server bug or an auth
    /// failure will do the wrong thing. The detail is logged, never sent.
    pub fn unavailable(context: &str, e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, context, "database unavailable");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "could not reach the database right now; retry shortly",
        )
    }

    /// Like `From<AuthError>`, but a database outage is `503`. For the open
    /// discovery documents, whose failure must read as "retry", not "broken".
    pub fn from_auth_or_unavailable(context: &str, e: AuthError) -> Self {
        if is_db_outage(&e) {
            Self::unavailable(context, e)
        } else {
            Self::from(e)
        }
    }
}

/// Whether `e` means the database could not answer, at any wrapping depth.
/// Mirrors the resource servers' `is_outage` check.
pub fn is_db_outage(e: &AuthError) -> bool {
    fn tenant(e: &otto_tenant::Error) -> bool {
        matches!(e, otto_tenant::Error::Db(_))
    }
    match e {
        AuthError::Db(_) => true,
        AuthError::Tenant(t) => tenant(t),
        AuthError::Core(otto_core::Error::Db(_)) => true,
        AuthError::Core(otto_core::Error::Tenant(t)) => tenant(t),
        _ => false,
    }
}

/// Identity-domain failures (`otto-core`): orgs, teams, invites, SSO guards.
impl From<otto_core::Error> for ApiError {
    fn from(e: otto_core::Error) -> Self {
        use otto_core::Error::*;

        let e = match e {
            Tenant(inner) => return ApiError::from(inner),
            other => other,
        };
        if let Db(inner) = &e {
            return ApiError::internal("otto-core", inner);
        }

        let status = match &e {
            TeamNotFound { .. } | OrgNotFound(_) => StatusCode::NOT_FOUND,

            TeamSlugTaken(_) | AlreadyAMember { .. } | DomainAlreadyClaimed => StatusCode::CONFLICT,

            // Gone, not Not Found: the link was real, and saying so is what
            // tells the holder to ask for a new one rather than re-check the URL.
            InviteInvalid => StatusCode::GONE,

            InviteWrongAccount { .. } => StatusCode::FORBIDDEN,

            // enterprise OIDC federation (spec §5): every lockout guard
            // (`set_enforce_sso`'s enable path, `idp::delete_connection`,
            // `domains::delete`) refuses with 400, naming the reason, so the
            // admin who tripped it knows what to fix before retrying.
            Invalid(_) | NotAMember(_) | SsoLockout { .. } => StatusCode::BAD_REQUEST,

            Db(_) | Tenant(_) => unreachable!("returned above"),
        };

        ApiError::new(status, e.code(), e.to_string())
    }
}

/// Tenant-substrate failures (`otto-tenant`).
///
/// `IsolationNotEnforced` is a startup assertion, so arriving here at all would
/// mean a server that promised to refuse to serve is serving. It is logged in
/// full and answered vaguely: its message names database roles and tables,
/// which is infrastructure detail no HTTP client should be handed.
/// `Config`/`Crypto` carry the same shape of risk -- key-material and
/// ciphertext diagnostics, never an HTTP client's business.
impl From<otto_tenant::Error> for ApiError {
    fn from(e: otto_tenant::Error) -> Self {
        use otto_tenant::Error::*;

        match &e {
            Db(inner) => ApiError::internal("otto-tenant", inner),
            IsolationNotEnforced { .. } | Config(_) | Crypto(_) => {
                ApiError::internal("otto-tenant", &e)
            }
            Invalid(_) => ApiError::new(StatusCode::BAD_REQUEST, e.code(), e.to_string()),
            OrgNotFound(_) => ApiError::new(StatusCode::NOT_FOUND, e.code(), e.to_string()),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        // Identity failures get the vague public string; protocol errors get
        // their own words. See the module docs for why the line falls there.
        let message = match e.oauth_code() {
            Some(_) => e.to_string(),
            None => e.public().to_string(),
        };
        let (status, code) = (
            StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            auth_code(&e),
        );

        if matches!(
            e,
            AuthError::Config(_) | AuthError::Crypto(_) | AuthError::Db(_)
        ) {
            return ApiError::internal("otto-auth", e);
        }
        match e {
            AuthError::Core(inner) => return ApiError::from(inner),
            AuthError::Tenant(inner) => return ApiError::from(inner),
            _ => {}
        }

        // Unlike Config/Crypto/Db above, these keep their own status/message
        // (502 for an upstream failure, 400 for a refused URL — see
        // AuthError::status()'s own comment) rather than collapsing to a
        // generic 500, because the message itself is operator-facing
        // diagnostic text an admin binding a connection or verifying a
        // domain can act on. That's exactly why they still need a log line:
        // a silent-failure review found none of the four had one at all,
        // unlike every other admin-facing failure path in this crate —
        // "the response tells the admin something specific" was mistaken
        // for "so nothing needs to be logged," and the two are independent.
        if matches!(
            e,
            AuthError::OidcHttp { .. }
                | AuthError::OidcApi { .. }
                | AuthError::DnsResolverFailure(_)
                | AuthError::OidcUnsafeUrl { .. }
        ) {
            tracing::warn!(error = %e, "SSO admin-configuration request failed");
        }

        let retry_after = match e {
            AuthError::RateLimited { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };

        ApiError {
            status,
            code,
            message,
            retry_after,
        }
    }
}

/// A stable code per auth failure, coarser than the variant on purpose: the
/// credential failures collapse to one code for the same reason they collapse
/// to one message.
fn auth_code(e: &AuthError) -> &'static str {
    match e {
        AuthError::UnknownUser
        | AuthError::NoPasskey
        | AuthError::InvalidCredentials
        | AuthError::Disabled => "invalid_credentials",

        // Separate codes, because these say *what to do* rather than whether an
        // account exists: start the ceremony again, use a different
        // authenticator, register another key first.
        AuthError::CeremonyExpired => "ceremony_expired",
        AuthError::CredentialAlreadyRegistered => "credential_already_registered",
        AuthError::UnknownCredential => "unknown_credential",
        AuthError::LastPasskey => "last_passkey",
        AuthError::CeremonyAccountMismatch { .. } => "ceremony_account_mismatch",

        AuthError::Expired | AuthError::AlreadyConsumed | AuthError::Revoked => {
            "credential_expired"
        }

        AuthError::WrongAudience => "wrong_audience",
        AuthError::NotAMember => "not_a_member",
        AuthError::SsoRequired => "sso_required",
        AuthError::RateLimited { .. } => "rate_limited",

        AuthError::InvalidRequest(_) => "invalid_request",
        AuthError::InvalidClient(_) => "invalid_client",
        AuthError::InvalidGrant(_) => "invalid_grant",
        AuthError::UnsupportedGrantType(_) => "unsupported_grant_type",
        AuthError::InvalidScope(_) => "invalid_scope",
        AuthError::InvalidTarget(_) => "invalid_target",

        AuthError::Config(_)
        | AuthError::Crypto(_)
        | AuthError::Core(_)
        | AuthError::Tenant(_)
        | AuthError::Db(_)
        | AuthError::OidcHttp { .. }
        | AuthError::OidcApi { .. }
        | AuthError::DnsResolverFailure(_) => "internal_error",

        // enterprise OIDC federation (spec §4): a discovery document missing
        // a required endpoint, or an id_token that fails verification —
        // separate codes because, unlike the credential failures above,
        // these say something specific an admin/operator can act on.
        AuthError::OidcDiscoveryField(_) => "oidc_discovery_incomplete",
        AuthError::IdTokenInvalid(_) => "id_token_invalid",
        AuthError::OidcUnsafeUrl { .. } => "oidc_unsafe_url",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one regression this file exists to prevent. A `Db` error carries
    /// constraint and column names; if it ever reaches a response body, an
    /// attacker gets a free schema dump and the user gets nothing useful.
    #[test]
    fn database_errors_never_reach_the_caller() {
        let leaky = otto_core::Error::Db(sqlx::Error::Protocol(
            "duplicate key value violates unique constraint \"org_invites_token_key\"".into(),
        ));
        let api = ApiError::from(leaky);

        assert_eq!(api.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api.code, "internal_error");
        assert!(
            !api.message.contains("org_invites"),
            "the schema leaked into the response: {}",
            api.message
        );
    }

    /// Every credential failure that names an account must be
    /// indistinguishable from the outside.
    ///
    /// Narrower than it was, and for a good reason: with a discoverable
    /// credential there is no address to leak, so sign-in has far less to hide.
    /// What it still hides is everything downstream of resolving the account —
    /// an unknown user, an account with no keys, a bad signature, and a disabled
    /// account are one answer, because the differences would tell an attacker
    /// holding a stolen device which part to work on.
    ///
    /// `UnknownCredential` is deliberately outside this set. It is answered
    /// before any account is resolved, so it distinguishes no user, address, or
    /// org; a credential ID is unguessable and never disclosed cross-origin, so
    /// the caller asking already holds it. Telling it apart is what lets the
    /// console signal a deleted passkey to the browser's vault without evicting
    /// a good one. See `passkeys::finish_authentication`.
    #[test]
    fn credential_failures_are_one_answer() {
        let seen: Vec<(u16, &str, String)> = [
            AuthError::UnknownUser,
            AuthError::NoPasskey,
            AuthError::InvalidCredentials,
            AuthError::Disabled,
        ]
        .into_iter()
        .map(|e| {
            let a = ApiError::from(e);
            (a.status.as_u16(), a.code, a.message)
        })
        .collect();

        assert!(
            seen.windows(2).all(|w| w[0] == w[1]),
            "login failures are distinguishable, which is an enumeration oracle: {seen:?}"
        );
        assert_eq!(seen[0].1, "invalid_credentials");
    }

    /// A protocol error describes the request, not the requester. Collapsing it
    /// to its bare code leaves an integrator with nothing to act on, and there
    /// is nothing to enumerate — the caller already knows what they sent.
    #[test]
    fn a_protocol_error_keeps_the_detail_that_makes_it_fixable() {
        let api = ApiError::from(AuthError::InvalidScope(
            r#"unknown scope "orgs:destroy"; supported scopes are orgs:read orgs:write"#.into(),
        ));

        assert_eq!(api.code, "invalid_scope");
        assert!(
            api.message.contains("orgs:read"),
            "the supported scopes were dropped: {}",
            api.message
        );
    }

    #[test]
    fn a_throttled_caller_is_told_when_to_come_back() {
        let api = ApiError::from(AuthError::RateLimited {
            retry_after_secs: 60,
        });
        assert_eq!(api.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(api.retry_after, Some(60));

        let response = api.into_response();
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).unwrap(),
            "60",
            "a 429 without Retry-After leaves a client guessing"
        );
    }

    /// An invitation that has been spent is Gone, not Not Found: the difference
    /// is what tells the holder to ask for a new one rather than re-check the
    /// URL they were sent.
    #[test]
    fn a_spent_invitation_is_gone_and_a_taken_slug_is_a_conflict() {
        assert_eq!(
            ApiError::from(otto_core::Error::InviteInvalid).status,
            StatusCode::GONE
        );
        assert_eq!(
            ApiError::from(otto_core::Error::TeamSlugTaken("platform".into())).status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::from(otto_core::Error::TeamNotFound {
                slug: "nope".into(),
                known: "platform".into(),
            })
            .status,
            StatusCode::NOT_FOUND
        );
    }
}
