//! Errors from the tenant-isolation substrate: the pinned transaction, the
//! isolation proof, and the audit trail.
//!
//! This is a deliberately small enum. It covers only what [`crate::db`],
//! [`crate::isolation`], and [`crate::audit`] themselves produce — a domain
//! crate built on top of [`crate::Tx`] (`otto-core`'s orgs/teams/invites, say)
//! defines its own richer error type and wraps this one with `#[from]`, the
//! same layering `of-core`'s original single `Error` enum collapsed together.

use crate::ids::OrgId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),

    /// The database cannot enforce tenant isolation as configured. Raised only
    /// by [`crate::Db::verify_tenant_isolation`] at startup, never by a request:
    /// by the time a tool call is in flight it is far too late to discover that
    /// one org can read another's rows. Carries the specific findings because
    /// "isolation is broken" without naming the table or the role is not
    /// something an operator can act on at 3am.
    #[error(
        "the database cannot enforce tenant isolation, so one org could read \
         another's data: {problems}"
    )]
    IsolationNotEnforced { problems: String },

    /// An org id that does not resolve to a row in `orgs`.
    #[error("org {0} not found")]
    OrgNotFound(OrgId),

    /// Misconfiguration detected while building a component, e.g. an
    /// encryption key that is not valid base64 or the wrong length.
    #[error("{0}")]
    Config(String),

    /// A seal/open failure in [`crate::crypto::Cipher`].
    #[error("{0}")]
    Crypto(String),

    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl Error {
    /// A stable, machine-readable code for an API error envelope.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "invalid_argument",
            Error::IsolationNotEnforced { .. } => "isolation_not_enforced",
            Error::OrgNotFound(_) => "org_not_found",
            Error::Config(_) => "internal_error",
            Error::Crypto(_) => "internal_error",
            Error::Db(_) => "internal_error",
        }
    }
}
