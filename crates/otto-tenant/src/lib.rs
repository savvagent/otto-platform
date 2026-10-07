//! `otto-tenant` — the tenant-isolation substrate shared by every otto-*
//! service: typed ids, the pinned-transaction connection pool, the row-level-
//! security isolation proof, and the audit-events pattern.
//!
//! This crate owns no domain model at all — no users, no orgs, no billing.
//! [`otto_core`](https://docs.rs/otto-core) (not a dependency of this crate;
//! see that crate's own docs) builds the identity domain on top of it, and any
//! other otto-* service's own domain database is expected to depend on this
//! crate directly and run the same RLS pattern against its own tables, per
//! `docs/specs/2026-09-15-otto-flags-design.md` §3 in the otto-flags repo.
//!
//! Two rules hold throughout, and both exist to make cross-tenant leakage
//! structurally impossible rather than merely unlikely:
//!
//! 1. **Every tenant-scoped operation takes an [`OrgId`]** — usually by being a
//!    method on [`Tx`], which cannot be constructed without one.
//! 2. **Every tenant transaction runs pinned.** [`Db::begin`] issues
//!    `SET LOCAL ROLE otto_app` (configurable with [`Db::with_tenant_role`]) and
//!    `SET LOCAL app.org_id`, so Postgres
//!    row-level security applies even when the connecting user owns the
//!    tables. A query that forgets its `org_id` predicate returns nothing
//!    instead of leaking. Where `otto_app` cannot exist — managed Postgres
//!    does not hand out the cluster privilege to create it — `FORCE ROW LEVEL
//!    SECURITY` carries the same guarantee, and [`Db::verify_tenant_isolation`]
//!    proves at startup that one of the two is genuinely in force. See
//!    [`isolation`].

pub mod audit;
pub mod crypto;
pub mod db;
pub mod error;
pub mod ids;
pub mod isolation;

pub use db::{Db, Tx, Unpinned};
pub use error::{Error, Result};
pub use ids::{OrgId, TeamId, UserId};
