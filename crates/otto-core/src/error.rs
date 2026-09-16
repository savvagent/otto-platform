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
            Error::Db(_) => "internal_error",
            Error::Tenant(e) => e.code(),
        }
    }
}
