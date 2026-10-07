//! `otto-platform-server` as a library, so its router can be exercised in
//! integration tests without binding a socket. The binary in `main.rs` owns
//! configuration, startup checks, and serving.
//!
//! Routes today:
//!
//! ```text
//!   /healthz /readyz          health      no database on the liveness path
//! ```
//!
//! The OAuth authorization server, sign-in, and console routes arrive in
//! Phase 4 of `docs/plans/2026-10-06-platform-cutover.md`.

pub mod health;

use axum::Router;
use otto_tenant::Db;

pub fn router(db: Db) -> Router {
    health::router(db)
}
