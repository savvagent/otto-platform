//! `otto-core` — the identity domain shared by every otto-* service: users,
//! orgs, org membership, teams, and org invitations.
//!
//! Built on [`otto_tenant`], which owns the pinned transaction and the
//! row-level-security guarantee; this crate owns the SQL and the domain
//! types for "who is this, which org are they acting in, and what may they
//! do there". It knows nothing about HTTP, MCP, or authentication — that is
//! `otto-auth`, one layer up.
//!
//! Because [`otto_tenant::Db`] and [`otto_tenant::Tx`] are defined in a crate
//! this one depends on rather than owns, Rust's orphan rules mean the
//! query methods below are added as **extension traits**
//! ([`orgs::OrgsExt`], [`orgs::OrgsTxExt`], [`teams::TeamsExt`],
//! [`invites::InvitesExt`], [`invites::AccountClaimsExt`]) rather than
//! inherent `impl Db { ... }` / `impl Tx<'_> { ... }` blocks the way
//! otto-factory's original single `of-core` crate could write them. Import
//! the trait alongside `Db`/`Tx` to call its methods — e.g.
//! `use otto_core::orgs::OrgsExt;` for `db.get_user(...)`.

pub mod error;
pub mod i18n;
pub mod invites;
pub mod labels;
pub mod orgs;
pub mod teams;

pub use error::{Error, Result};
