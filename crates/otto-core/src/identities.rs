//! Enterprise OIDC federation — pinning an IdP subject to a user.
//!
//! `user_identities` carries no `org_id` column at all (it is keyed through
//! `idp_connection_id`, which is itself org-scoped) — there is no tenant
//! boundary to pin a `Tx` to here in the first place, so every accessor in
//! this module is unscoped (`&Db`), the same bootstrap class as
//! `idp::resolve_for_domain`.
//!
//! **The email-linking invariant lives here, and it is absolute: a federated
//! identity is never linked to a pre-existing `users` row by email match,
//! under any circumstance.** See [`create_user_for_federation`]'s doc comment
//! for the account-takeover shape this closes, and the design spec's
//! Assumptions for the full threat model. Only two paths ever create a
//! `user_identities` row: a brand-new user (via `create_user_for_federation`,
//! when no existing row holds the verified email) or an already-authenticated
//! session's explicit link action (the HTTP layer, Phase 4) — never a fresh email
//! lookup used to pick a link target.

use crate::error::Result;
use otto_tenant::ids::UserId;
use otto_tenant::{Db, Tx};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    pub id: uuid::Uuid,
    pub user_id: UserId,
    pub idp_connection_id: uuid::Uuid,
    pub subject: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Resolve a federated identity that has already been linked once.
///
/// Unscoped, same bootstrap class as [`crate::idp::resolve_for_domain`] —
/// `user_identities` carries no `org_id` at all. Used on every OIDC callback,
/// first thing: a returning federated user (this `(idp_connection_id,
/// subject)` pair already linked) always takes this path, regardless of
/// which ceremony kind (anonymous sign-in or authenticated link) they came
/// through.
pub async fn resolve_user(
    db: &Db,
    idp_connection_id: uuid::Uuid,
    subject: &str,
) -> Result<Option<UserId>> {
    let user_id = sqlx::query_scalar(
        "SELECT user_id FROM user_identities WHERE idp_connection_id = $1 AND subject = $2",
    )
    .bind(idp_connection_id)
    .bind(subject)
    .fetch_optional(db.pool())
    .await?;

    Ok(user_id)
}

/// Whether a verified email already belongs to some existing account.
///
/// Unscoped, used **only** by the anonymous-ceremony callback path to decide
/// "create a new user" (`None`) vs. "refuse, this email already belongs to
/// someone" (`Some(_)`). **Never used to choose whom to link an identity
/// to** — the one caller of this function treats `Some(_)` strictly as a
/// refusal signal, never as a target to link an identity onto. See
/// [`create_user_for_federation`]'s doc comment for why.
pub async fn resolve_by_email(db: &Db, email: &str) -> Result<Option<UserId>> {
    let user_id = sqlx::query_scalar("SELECT id FROM users WHERE lower(email) = lower($1)")
        .bind(email)
        .fetch_optional(db.pool())
        .await?;

    Ok(user_id)
}

/// Whether `user_id` already has a federated identity linked for
/// `idp_connection_id` — used by [`crate::orgs::set_enforce_sso`]'s
/// enable-path guard to require that the admin turning enforcement on has
/// already proven they can sign back in through it (see that function's doc
/// comment for the lockout this closes).
///
/// Takes `&mut Tx<'_>`, unlike this module's other accessors, because its
/// one caller already holds a `Tx` (from [`lock_for_sso_guard`]) and has no
/// separate `Db` handle to reach for — `user_identities` still has no
/// `org_id` to scope, so this applies no org predicate any more than
/// [`resolve_user`] does; it simply runs on whichever connection the caller
/// already has open rather than acquiring a second one from the pool.
pub(crate) async fn is_linked(
    tx: &mut Tx<'_>,
    user_id: UserId,
    idp_connection_id: uuid::Uuid,
) -> Result<bool> {
    let linked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_identities WHERE user_id = $1 AND idp_connection_id = $2)",
    )
    .bind(user_id)
    .bind(idp_connection_id)
    .fetch_one(tx.conn())
    .await?;

    Ok(linked)
}

/// First-use pinning of an IdP subject to a user.
///
/// `ON CONFLICT (idp_connection_id, subject) DO NOTHING` then re-read: a
/// duplicate callback for the same ceremony, or a race between two tabs,
/// converges rather than errors — the same tolerance otto-factory's `jobs::create_from_ticket`
/// already uses for the analogous webhook-redelivery case. Called with a
/// `user_id` the caller already resolved through one of the two sanctioned
/// paths (a brand-new row from [`create_user_for_federation`], or an
/// authenticated session's own `user_id`) — `link` itself does no email
/// resolution and trusts the caller's `user_id` outright.
pub async fn link(
    db: &Db,
    user_id: UserId,
    idp_connection_id: uuid::Uuid,
    subject: &str,
) -> Result<UserIdentity> {
    let inserted: Option<UserIdentity> = sqlx::query_as(
        "INSERT INTO user_identities (user_id, idp_connection_id, subject) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (idp_connection_id, subject) DO NOTHING \
         RETURNING id, user_id, idp_connection_id, subject, created_at",
    )
    .bind(user_id)
    .bind(idp_connection_id)
    .bind(subject)
    .fetch_optional(db.pool())
    .await?;

    if let Some(identity) = inserted {
        return Ok(identity);
    }

    let existing = sqlx::query_as(
        "SELECT id, user_id, idp_connection_id, subject, created_at \
         FROM user_identities WHERE idp_connection_id = $1 AND subject = $2",
    )
    .bind(idp_connection_id)
    .bind(subject)
    .fetch_one(db.pool())
    .await?;

    Ok(existing)
}

/// Create a brand-new user for a verified federated email — and *only* a
/// brand-new one. `INSERT INTO users (email, label) VALUES ($1, $2) ON
/// CONFLICT (lower(email)) DO NOTHING RETURNING id`. Returns `Ok(None)` when
/// the conflict fires — someone else's row already holds this email,
/// including a row that appeared in the race window between the caller's
/// `resolve_by_email` check and this insert — and the caller must treat that
/// as a refusal, never falling back to that row.
///
/// **Never replace this with `Db::upsert_user`** — that function's `DO
/// UPDATE` hands back a pre-existing row on purpose, which is the exact
/// account-takeover shape spec review round 3 closed for federated sign-in.
/// `Db::upsert_user` stays correct for its own callers (admin-driven invite
/// flows, where converging onto an existing account is the intended
/// behavior); this function's contract is the opposite: a conflict here is
/// proof someone else got there first, and the caller must treat that as a
/// refusal, not a success.
///
/// The concrete attack this closes: `PATCH /api/me` lets any signed-in
/// passkey account set its own `users.email` to an arbitrary address with
/// zero ownership proof (there is no mail-based verification anywhere in
/// this product). An attacker registers a passkey account, sets its email to
/// `alice@acme.com` before Acme ever binds SSO, and waits. When Acme later
/// federates and the real Alice authenticates through Acme's IdP with a
/// genuinely verified `alice@acme.com`, resolving by email match would find
/// the attacker's row and grant *the attacker's own passkey-controlled
/// account* membership in Acme's org under Alice's name — full
/// impersonation, and the attacker never touches the IdP at all. `DO
/// UPDATE ... RETURNING` would silently converge onto that row exactly the
/// way `Db::upsert_user` is built to; `DO NOTHING` refuses instead.
pub async fn create_user_for_federation(db: &Db, email: &str) -> Result<Option<UserId>> {
    let user_id: Option<UserId> = sqlx::query_scalar(
        "INSERT INTO users (email, label) VALUES ($1, $2) \
         ON CONFLICT (lower(email)) DO NOTHING \
         RETURNING id",
    )
    .bind(email)
    .bind(crate::labels::generate())
    .fetch_optional(db.pool())
    .await?;

    Ok(user_id)
}
