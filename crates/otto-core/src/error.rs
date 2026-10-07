//! Domain errors for the identity model: orgs, users, teams, invites.
//!
//! These are written to be readable by an LLM tool caller that has never seen
//! the docs: a failure says what went wrong, what the valid options were, and
//! what to call next.

use otto_tenant::ids::{OrgId, UserId};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),

    #[error("org {0} not found")]
    OrgNotFound(OrgId),

    #[error("no team {slug:?} in this org. Teams: {known}")]
    TeamNotFound { slug: String, known: String },

    #[error("team slug {0:?} is already taken in this org")]
    TeamSlugTaken(String),

    #[error("user {0} is not a member of this org")]
    NotAMember(UserId),

    #[error("{email} is already a member of this org, as {role}")]
    AlreadyAMember { email: String, role: String },

    /// Unknown, already accepted, and expired collapse into one answer — which
    /// of the three it was is not something the holder of a failing token
    /// should be able to determine.
    #[error("this invitation is no longer valid. Ask an admin of the org to send a new one.")]
    InviteInvalid,

    #[error(
        "this invitation was sent to {invited}, but you are signed in as {signed_in_as}. \
         Sign in as {invited} to accept it."
    )]
    InviteWrongAccount {
        invited: String,
        signed_in_as: String,
    },

    /// Another org has already *verified* this domain (only one verified
    /// claim per domain is allowed; pending claims do not conflict). Deliberately generic: a domain
    /// claim is a full account/organization identity, so nothing beyond "you
    /// were refused" is confirmed here, not even which org holds it.
    #[error("this domain is already claimed by another organization")]
    DomainAlreadyClaimed,

    /// A change to an org's SSO configuration was refused because it would
    /// leave (or already leaves) the org with `enforce_sso = true` and no
    /// working IdP sign-in path: no bound connection, no verified domain, or
    /// (for a domain delete) no verified domain left once this one is gone.
    /// Raised by `orgs::set_enforce_sso`'s enable path, `idp::delete_connection`,
    /// and `domains::delete`/`domains::claim`, each behind
    /// `orgs::lock_for_sso_guard` so the check this error reports on cannot be
    /// raced by a concurrent admin action. `reason` names which piece is
    /// missing: an admin fixing this needs to know whether to bind a
    /// connection, verify a domain, or turn enforcement off first.
    #[error("{reason}")]
    SsoLockout { reason: String },

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    #[error(transparent)]
    Tenant(#[from] otto_tenant::Error),
}

impl Error {
    /// A stable, machine-readable code for an API error envelope. Agents
    /// branch on this; humans read the message.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "invalid_argument",
            Error::OrgNotFound(_) => "org_not_found",
            Error::TeamNotFound { .. } => "team_not_found",
            Error::TeamSlugTaken(_) => "team_slug_taken",
            Error::NotAMember(_) => "not_a_member",
            Error::AlreadyAMember { .. } => "already_a_member",
            Error::InviteInvalid => "invite_invalid",
            Error::InviteWrongAccount { .. } => "invite_wrong_account",
            Error::DomainAlreadyClaimed => "domain_already_claimed",
            Error::SsoLockout { .. } => "sso_lockout",
            Error::Db(_) => "internal_error",
            Error::Tenant(e) => e.code(),
        }
    }
}
