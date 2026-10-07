//! Enterprise OIDC federation — the state held between "redirect to the IdP"
//! and "the IdP redirects back".
//!
//! `sso_ceremonies` carries no RLS policy (see `0006_sso.sql`'s own
//! comment) — it must be readable by `state_hash` alone, before any org or
//! session exists. Every write still carries an explicit predicate (guard 1).

use crate::error::Result;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use serde::Serialize;
use sqlx::FromRow;

const CEREMONY_COLS: &str = "id, org_id, idp_connection_id, user_id, state_hash, \
                             binding_hash, nonce, expires_at, consumed_at, created_at";

#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SsoCeremony {
    pub id: uuid::Uuid,
    pub org_id: OrgId,
    pub idp_connection_id: uuid::Uuid,
    /// Set only by the authenticated "link my SSO identity" path; `None` for
    /// the anonymous "sign in with SSO" path. See the module doc comment and
    /// otto-factory's OIDC federation design spec's Assumptions for what each kind means at callback
    /// time.
    pub user_id: Option<UserId>,
    #[serde(skip)]
    pub state_hash: Vec<u8>,
    #[serde(skip)]
    pub binding_hash: Vec<u8>,
    pub nonce: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub consumed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Mint a new ceremony row.
///
/// Unscoped `&Db` insert — there is no `Tx` to pin this to in the anonymous
/// case (no session, and the org is only known because the caller already
/// resolved it via `idp::resolve_for_domain`). `org_id` is denormalized onto
/// the row rather than re-derived from the domain a second time at callback,
/// so a domain reassigned mid-flow can't retarget an in-flight ceremony —
/// the callback trusts this stored value, not a fresh lookup.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    db: &Db,
    org_id: OrgId,
    idp_connection_id: uuid::Uuid,
    user_id: Option<UserId>,
    state_hash: &[u8],
    binding_hash: &[u8],
    nonce: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<SsoCeremony> {
    let ceremony = sqlx::query_as(&format!(
        "INSERT INTO sso_ceremonies \
         (org_id, idp_connection_id, user_id, state_hash, binding_hash, nonce, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {CEREMONY_COLS}"
    ))
    .bind(org_id)
    .bind(idp_connection_id)
    .bind(user_id)
    .bind(state_hash)
    .bind(binding_hash)
    .bind(nonce)
    .bind(expires_at)
    .fetch_one(db.pool())
    .await?;

    Ok(ceremony)
}

/// Resolve a ceremony by its hashed `state` and burn it in the same step.
///
/// **The row is marked consumed whether or not the caller's subsequent
/// binding-cookie check passes.** This function's job ends at "resolve and
/// burn the ceremony, atomically" — it is not "decide if the whole callback
/// succeeds". The `__Host-otto_sso_binding` cookie check happens in `the HTTP layer (Phase 4)`,
/// *after* this function has already returned and committed, per that spec's §5
/// ("marks the ceremony consumed in the same step regardless of outcome").
/// That ordering is deliberate: a captured-and-replayed callback URL that
/// fails the binding check must not be retryable against the same ceremony
/// either, so the burn cannot wait on a check that happens one layer up.
///
/// Opens its own short transaction internally (`Db::begin_unpinned` — this
/// table has no RLS, so there is no org to pin a tenant `Tx` to, and none is
/// needed): `SELECT ... FOR UPDATE WHERE state_hash = $1 AND consumed_at IS
/// NULL AND expires_at > now()` locks the row first, so a second concurrent
/// call for the same `state_hash` blocks until this transaction commits, then
/// re-evaluates the same `WHERE` against the row this transaction left
/// behind — `consumed_at` is no longer `NULL`, so the second caller's
/// `SELECT` returns nothing and this function answers `None`, never the same
/// row twice. Only after a row is found does the `UPDATE` burn it; both
/// statements commit together.
pub async fn consume_by_state_hash(db: &Db, state_hash: &[u8]) -> Result<Option<SsoCeremony>> {
    let mut unpinned = db.begin_unpinned().await?;

    let row: Option<SsoCeremony> = sqlx::query_as(&format!(
        "SELECT {CEREMONY_COLS} FROM sso_ceremonies \
         WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
         FOR UPDATE"
    ))
    .bind(state_hash)
    .fetch_optional(unpinned.conn())
    .await?;

    let ceremony = match row {
        Some(mut ceremony) => {
            let consumed_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
                "UPDATE sso_ceremonies SET consumed_at = now() WHERE id = $1 \
                 RETURNING consumed_at",
            )
            .bind(ceremony.id)
            .fetch_one(unpinned.conn())
            .await?;
            ceremony.consumed_at = Some(consumed_at);
            Some(ceremony)
        }
        None => None,
    };

    unpinned.commit().await?;
    Ok(ceremony)
}
