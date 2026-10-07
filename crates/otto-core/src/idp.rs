//! Enterprise OIDC federation — bound IdP connections.
//!
//! One `idp_connections` row per org (`UNIQUE (org_id)` — binding a second IdP
//! replaces the first, matching `tracker_connections`' one-per-provider
//! precedent). `idp_connections` carries no `org_id`-based RLS policy —
//! `0004_rls.sql` leaves it out alongside `claimed_domains` because
//! authentication must be able to resolve it before an org is known — so
//! every statement here still carries an explicit `org_id = $1` predicate
//! (guard 1) even where a `Tx` is used for its pinned `org()` accessor.

use crate::error::Result;
use otto_tenant::crypto::Sealed;
use otto_tenant::ids::OrgId;
use otto_tenant::{Db, Tx};
use serde::Serialize;
use sqlx::FromRow;

const CONNECTION_COLS: &str = "id, org_id, issuer, client_id, discovery, created_at";

/// A bound IdP connection, minus its secret.
///
/// `client_secret_ct`/`client_secret_nonce` are deliberately absent from this
/// struct — they never leave `otto-core` as plaintext-adjacent bytes. Only
/// [`get_connection_secret`] returns the sealed pair, to the one caller (the
/// OIDC token-exchange step) that needs to open it.
#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdpConnection {
    pub id: uuid::Uuid,
    pub org_id: OrgId,
    pub issuer: String,
    pub client_id: String,
    pub discovery: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Bind (or replace) this org's IdP connection.
///
/// `ON CONFLICT (org_id) DO UPDATE` — an admin rebinding an IdP always
/// replaces the existing one wholesale, the same "one connection per org"
/// shape `tracker_connections` already uses for "one connection per
/// provider". `secret` is written straight into the two `bytea` columns with
/// no concatenation step: `idp_connections` already has two columns for it,
/// unlike `tracker_connections`' single-`TEXT` `encode_sealed` convention,
/// which exists only because that table has one column to work with.
///
/// A rebind that changes `issuer` or `client_id` also clears every
/// `user_identities` row pinned to this connection — [`delete_connection`]'s
/// doc comment states the underlying principle ("the org no longer vouches
/// for that IdP") and this is the same fact under a different SQL statement:
/// `ON CONFLICT ... DO UPDATE` preserves `idp_connections.id`, so without
/// this, every existing pin would silently survive a switch to a completely
/// different IdP. `sub` is only unique *within* an issuer, so a principal at
/// the new IdP whose `sub` collides with a stale pin from the old one would
/// otherwise resolve straight onto that account.
pub async fn upsert_connection(
    tx: &mut Tx<'_>,
    issuer: &str,
    client_id: &str,
    secret: Sealed,
    discovery: serde_json::Value,
) -> Result<IdpConnection> {
    let org_id = tx.org();

    let existing: Option<(uuid::Uuid, String, String)> =
        sqlx::query_as("SELECT id, issuer, client_id FROM idp_connections WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(tx.conn())
            .await?;

    let connection: IdpConnection = sqlx::query_as(&format!(
        "INSERT INTO idp_connections \
         (org_id, issuer, client_id, client_secret_ct, client_secret_nonce, discovery) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (org_id) DO UPDATE SET \
           issuer = EXCLUDED.issuer, \
           client_id = EXCLUDED.client_id, \
           client_secret_ct = EXCLUDED.client_secret_ct, \
           client_secret_nonce = EXCLUDED.client_secret_nonce, \
           discovery = EXCLUDED.discovery \
         RETURNING {CONNECTION_COLS}"
    ))
    .bind(org_id)
    .bind(issuer)
    .bind(client_id)
    .bind(&secret.ciphertext)
    .bind(&secret.nonce)
    .bind(discovery)
    .fetch_one(tx.conn())
    .await?;

    if let Some((id, old_issuer, old_client_id)) = existing {
        if old_issuer != issuer || old_client_id != client_id {
            sqlx::query("DELETE FROM user_identities WHERE idp_connection_id = $1")
                .bind(id)
                .execute(tx.conn())
                .await?;
        }
    }

    Ok(connection)
}

pub async fn get_connection(tx: &mut Tx<'_>) -> Result<Option<IdpConnection>> {
    let connection = sqlx::query_as(&format!(
        "SELECT {CONNECTION_COLS} FROM idp_connections WHERE org_id = $1"
    ))
    .bind(tx.org())
    .fetch_optional(tx.conn())
    .await?;

    Ok(connection)
}

/// The sealed client secret for this org's IdP connection.
///
/// The one function in this module that returns `client_secret_ct`/
/// `client_secret_nonce` — used only by the OIDC token-exchange step, which
/// opens it with `Cipher::open` for the duration of one outbound HTTP call
/// and never logs or persists the plaintext.
pub async fn get_connection_secret(tx: &mut Tx<'_>) -> Result<Option<Sealed>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT client_secret_ct, client_secret_nonce FROM idp_connections WHERE org_id = $1",
    )
    .bind(tx.org())
    .fetch_optional(tx.conn())
    .await?;

    Ok(row.map(|(ciphertext, nonce)| Sealed { ciphertext, nonce }))
}

/// Remove this org's IdP connection.
///
/// Cascades `sso_ceremonies` and, via `user_identities.idp_connection_id ON
/// DELETE CASCADE`, existing identity pins — a removed connection's users
/// fall back to needing a fresh federated sign-in (once the org re-binds one)
/// or a passkey, which is correct: the org no longer vouches for that IdP.
///
/// Refused while `enforce_sso` is on: removing the org's only IdP connection
/// while every member's passkey login is refused would lock everyone out,
/// including the admin issuing this call, with no path back in.
/// `orgs::lock_for_sso_guard` is called first — a cross-module call within
/// `otto-core`, which is ordinary, but worth calling out explicitly here since
/// getting the ordering wrong (checking `enforce_sso` before locking the org
/// row) reopens the concurrent-admin-action race that guard exists to close.
/// See `orgs::lock_for_sso_guard`'s own doc comment for the race.
pub async fn delete_connection(tx: &mut Tx<'_>) -> Result<()> {
    crate::orgs::lock_for_sso_guard(tx).await?;
    if crate::orgs::enforce_sso_flag(tx).await? {
        return Err(crate::error::Error::SsoLockout {
            reason: "cannot remove this org's IdP connection while enforce_sso is on — \
                     every member's passkey login is refused, and removing the only \
                     working SSO path would lock everyone out with no way back in. \
                     Turn off enforce_sso first."
                .to_string(),
        });
    }

    sqlx::query("DELETE FROM idp_connections WHERE org_id = $1")
        .bind(tx.org())
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// Resolve which org's IdP a claimed-and-verified email domain routes to.
///
/// **The one unscoped accessor for `idp_connections`.** Analogous to
/// otto-factory's `trackers::resolve_connection_org`: this is the one place a lookup must
/// run before an [`OrgId`] is known at all — a person has just typed an email
/// address at the SSO entry point, and nothing has authenticated them yet.
/// It reads only `claimed_domains` (`verified_at IS NOT NULL`) joined to
/// `idp_connections` on `org_id`. Every other read of `idp_connections` goes
/// through an org-pinned [`Tx`]. Do not add a second unscoped accessor for
/// this table without revisiting the OIDC federation design spec's §2.
pub async fn resolve_for_domain(db: &Db, domain: &str) -> Result<Option<(OrgId, IdpConnection)>> {
    let row: Option<IdpConnection> = sqlx::query_as(
        "SELECT ic.id, ic.org_id, ic.issuer, ic.client_id, ic.discovery, ic.created_at \
         FROM claimed_domains cd \
         JOIN idp_connections ic ON ic.org_id = cd.org_id \
         WHERE lower(cd.domain) = lower($1) AND cd.verified_at IS NOT NULL",
    )
    .bind(domain)
    .fetch_optional(db.pool())
    .await?;

    Ok(row.map(|connection| (connection.org_id, connection)))
}
