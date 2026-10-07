//! Authentication errors.
//!
//! Two audiences, and they must not see the same thing:
//!
//! - **The caller** gets [`AuthError::public`] — a deliberately vague string.
//!   Login failures are constant-shape whether the address is unknown, the
//!   account has no passkey, or the passkey ceremony failed. Any distinction
//!   between those is an account-enumeration oracle.
//! - **The log and the audit trail** get the full variant, which says exactly
//!   what happened, because an operator debugging a failed login should not
//!   have to guess.

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    // ---- credential failures: all of these are "invalid credentials" outside.
    #[error("no such user")]
    UnknownUser,

    #[error("account has no registered passkey")]
    NoPasskey,

    /// Every WebAuthn failure collapses here. The library distinguishes "wrong
    /// origin" from "user verification not performed" from "bad signature", and
    /// all of that is useful in a log and none of it is safe to hand back — it
    /// tells an attacker which part of a forgery to fix next.
    #[error("the authenticator's response was not accepted")]
    InvalidCredentials,

    /// The challenge is gone: expired, already spent, or never issued by this
    /// server. Single-use is what stops a captured ceremony being replayed.
    #[error("that sign-in attempt has expired; start again")]
    CeremonyExpired,

    #[error("that authenticator is already registered")]
    CredentialAlreadyRegistered,

    #[error("no such passkey on this account")]
    UnknownCredential,

    /// Removing the last passkey would lock the account out permanently: there
    /// is no email to recover through, and the click looks like tidying up.
    #[error("that is the only passkey on this account — register another before removing it")]
    LastPasskey,

    #[error("account is disabled")]
    Disabled,

    #[error("credential expired")]
    Expired,

    #[error("credential was already consumed")]
    AlreadyConsumed,

    #[error("credential revoked")]
    Revoked,

    #[error("token is not valid for this resource")]
    WrongAudience,

    #[error("user is not a member of that org")]
    NotAMember,

    #[error("this org requires single sign-on")]
    SsoRequired,

    /// The ceremony's stored account does not match what the caller expected,
    /// meaning a substituted or hijacked ceremony (see
    /// [`crate::passkeys::finish_registration_tx`]'s `expected` parameter).
    /// Checked before anything the completed ceremony would write, so a
    /// mismatch fails before the credential insert and its audit row exist at
    /// all, not just before they commit.
    ///
    /// Carries both accounts rather than being a unit variant: nothing else
    /// records which two accounts a hijack attempt named, so
    /// `finish_registration` uses these fields to write a best-effort trace of
    /// the attempt on a connection independent of the transaction this error
    /// rolls back.
    #[error("that ceremony belongs to a different account")]
    CeremonyAccountMismatch {
        /// The account the ceremony actually belongs to, the one a successful
        /// attach would have added a credential to.
        ceremony_account: otto_tenant::ids::UserId,
        /// Who the caller expected to be finishing it.
        caller_account: otto_tenant::ids::UserId,
    },

    // ---- rate limiting
    #[error("too many attempts; retry in {retry_after_secs}s")]
    RateLimited { retry_after_secs: i64 },

    // ---- OAuth protocol errors: these ARE returned verbatim, per RFC 6749 §5.2.
    // They describe the client's request, not the user's identity, so there is
    // no enumeration risk and a vague message would make integration impossible.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    #[error("invalid_client: {0}")]
    InvalidClient(String),

    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),

    #[error("invalid_scope: {0}")]
    InvalidScope(String),

    /// RFC 8707 §2: the requested resource is not one this AS issues tokens
    /// for (unregistered, or disabled).
    #[error("invalid_target: {0}")]
    InvalidTarget(String),

    // ---- operational
    #[error("configuration error: {0}")]
    Config(String),

    #[error("cryptographic failure: {0}")]
    Crypto(String),

    /// An error from the identity domain (`otto-core`) — an org or user lookup,
    /// say. Distinct from [`Self::Tenant`] because otto-core's `Error`
    /// already wraps `otto_tenant::Error` itself; the two are separate
    /// variants here rather than one, because `?` performs exactly one `From`
    /// conversion and otto-auth's call sites produce both types directly (a
    /// raw `Db::begin_unpinned` failure is an `otto_tenant::Error`; a
    /// `db.get_user(...)` failure, via `otto_core`'s extension traits, is an
    /// `otto_core::Error`).
    #[error(transparent)]
    Core(#[from] otto_core::Error),

    /// An error from the tenant-isolation substrate (`otto-tenant`) itself —
    /// see [`Self::Core`] for why this is a separate variant.
    #[error(transparent)]
    Tenant(#[from] otto_tenant::Error),

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    // ---- OIDC federation client (crate::oidc) and DNS verification
    // (crate::dns) — see otto-factory's docs/specs/2026-09-16-oidc-federation-design.md §4.
    /// A network call to the IdP itself failed (discovery, token exchange, or
    /// fetching its JWKS document) — distinct from the IdP answering with a
    /// non-2xx status, which is [`AuthError::OidcApi`].
    #[error("IdP request failed while {action}: {source}")]
    OidcHttp {
        action: &'static str,
        #[source]
        source: reqwest::Error,
    },

    /// The IdP answered, but not with 2xx — the body is truncated, since it's
    /// operator-facing diagnostic text, not something to echo back whole.
    #[error("IdP returned HTTP {status} while {action}: {body}")]
    OidcApi {
        action: &'static str,
        status: u16,
        body: String,
    },

    /// The cached `idp_connections.discovery` document is missing (or has a
    /// non-string) required field. Surfaced at bind time
    /// (`PUT .../sso/connection`), never silently deferred to first login.
    #[error("the identity provider's discovery document is missing or has an invalid {0:?} field")]
    OidcDiscoveryField(&'static str),

    /// Every `id_token` verification failure collapses here — bad signature,
    /// wrong `iss`/`aud`, expired, or a `nonce` that doesn't match this
    /// ceremony. the HTTP layer's `/sso/callback` handler answers all of these with
    /// the same generic error page (see the design spec's Assumptions on why
    /// the four callback failure classes are not distinguished to the
    /// caller); the detail here is for the log, not the browser.
    #[error("id_token verification failed: {0}")]
    IdTokenInvalid(String),

    /// A genuine DNS resolver/transport failure — never returned for
    /// NXDOMAIN, a timeout, or "no records": those are "not verified yet"
    /// and come back as `Ok(false)` from [`crate::dns::verify_txt_record`],
    /// not as this error. This is the resolver itself being unreachable, an
    /// operator-facing problem, not the domain's.
    #[error("DNS resolver failure while checking domain verification: {0}")]
    DnsResolverFailure(String),

    /// A URL this server was about to fetch — the admin-supplied `issuer`,
    /// or a `token_endpoint`/`jwks_uri` read back out of a stored discovery
    /// document — is not `https`, or resolves to a loopback/link-local/
    /// private/reserved address. Every one of these three URLs is either
    /// typed by an org admin or served by a third party this server does
    /// not control, so each is checked immediately before the connection
    /// that would use it, not only once at bind time — an admin-configured
    /// SSRF primitive against this server's own network would otherwise be
    /// one `issuer` field away.
    #[error("refusing to fetch {field} ({reason}) — it must be an https URL that does not resolve to a private, loopback, or link-local address")]
    OidcUnsafeUrl { field: &'static str, reason: String },
}

impl AuthError {
    /// What the caller is told.
    ///
    /// Every failure an unauthenticated caller can reach that concerns *who
    /// holds an account* collapses to one string — including `UnknownUser`,
    /// which resolved none. This
    /// is the enumeration defense: an attacker probing addresses must not be
    /// able to tell "no such user" from "wrong code", and a user who has lost
    /// their phone must not be told whether the address is registered.
    ///
    /// The arms below are exceptions for **two different reasons**, and the
    /// distinction matters when adding a third: most of them say *what to do*
    /// rather than whether an account exists, and are only reachable behind a
    /// resolved session or token anyway. `UnknownCredential` is the one that is
    /// not — [`crate::passkeys::finish_authentication`] returns it to an
    /// unauthenticated caller, and it is safe for a narrower reason of its
    /// own: it is decided from `passkeys` alone, before any `users` row is
    /// read, so it says a credential is not stored here without saying whose
    /// it would have been.
    pub fn public(&self) -> &'static str {
        match self {
            AuthError::UnknownUser
            | AuthError::NoPasskey
            | AuthError::InvalidCredentials
            | AuthError::Disabled => "invalid credentials",

            // Not folded into "invalid credentials": these say *what to do*
            // rather than whether an account exists, and a user who has to
            // start the ceremony again needs to be told so.
            AuthError::CeremonyExpired => "that sign-in attempt expired; try again",
            AuthError::CredentialAlreadyRegistered => "that authenticator is already registered",
            AuthError::UnknownCredential => "no such passkey",
            AuthError::LastPasskey => {
                "that is the only passkey on this account — register another first"
            }

            AuthError::Expired | AuthError::AlreadyConsumed | AuthError::Revoked => {
                "credential is no longer valid"
            }

            AuthError::WrongAudience => "token is not valid for this resource",
            AuthError::CeremonyAccountMismatch { .. } => {
                "that ceremony belongs to a different account"
            }
            AuthError::NotAMember => "not a member of that organization",
            AuthError::SsoRequired => "this organization requires single sign-on",
            AuthError::RateLimited { .. } => "too many attempts",

            AuthError::InvalidRequest(_) => "invalid_request",
            AuthError::InvalidClient(_) => "invalid_client",
            AuthError::InvalidGrant(_) => "invalid_grant",
            AuthError::UnsupportedGrantType(_) => "unsupported_grant_type",
            AuthError::InvalidScope(_) => "invalid_scope",
            AuthError::InvalidTarget(_) => "invalid_target",

            AuthError::OidcDiscoveryField(_) => {
                "the identity provider's configuration is incomplete"
            }
            AuthError::IdTokenInvalid(_) => {
                "the identity provider's response could not be verified"
            }
            AuthError::OidcUnsafeUrl { .. } => {
                "the identity provider's configuration points at a URL this server will not fetch"
            }
            AuthError::OidcHttp { .. }
            | AuthError::OidcApi { .. }
            | AuthError::DnsResolverFailure(_) => "internal error",

            AuthError::Config(_)
            | AuthError::Crypto(_)
            | AuthError::Core(_)
            | AuthError::Tenant(_)
            | AuthError::Db(_) => "internal error",
        }
    }

    /// The RFC 6749 §5.2 error code for the token endpoint, or `None` when this
    /// is not an OAuth protocol error.
    pub fn oauth_code(&self) -> Option<&'static str> {
        match self {
            AuthError::InvalidRequest(_) => Some("invalid_request"),
            AuthError::InvalidClient(_) => Some("invalid_client"),
            AuthError::InvalidGrant(_) => Some("invalid_grant"),
            AuthError::UnsupportedGrantType(_) => Some("unsupported_grant_type"),
            AuthError::InvalidScope(_) => Some("invalid_scope"),
            AuthError::InvalidTarget(_) => Some("invalid_target"),
            _ => None,
        }
    }

    /// HTTP status for this failure.
    pub fn status(&self) -> u16 {
        match self {
            AuthError::RateLimited { .. } => 429,
            AuthError::NotAMember
            | AuthError::SsoRequired
            | AuthError::CeremonyAccountMismatch { .. } => 403,
            AuthError::Config(_)
            | AuthError::Crypto(_)
            | AuthError::Core(_)
            | AuthError::Tenant(_)
            | AuthError::Db(_) => 500,
            AuthError::InvalidClient(_) => 401,
            // The IdP or the DNS resolver failed to answer: this server's own
            // request was fine, so it is a gateway failure, not a bad request
            // from our caller.
            AuthError::OidcHttp { .. }
            | AuthError::OidcApi { .. }
            | AuthError::DnsResolverFailure(_) => 502,
            _ => 400,
        }
    }
}
