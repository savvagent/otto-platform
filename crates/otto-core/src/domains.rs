//! Enterprise OIDC federation — claimed email domains.
//!
//! A domain is globally unique, claimed by at most one org at a time
//! (`claimed_domains.domain` is the primary key). Control is proved with a
//! DNS TXT record before `verified_at` is set — an unverified claim routes
//! nobody, so claiming `gmail.com` accomplishes nothing. Like
//! `idp_connections`, this table carries no `org_id`-based RLS policy
//! (`0004_rls.sql` leaves them out: bootstrap-before-org-known), so every statement
//! here carries an explicit `org_id = $1` predicate (guard 1).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

use crate::error::{Error, Result};
use otto_tenant::ids::OrgId;
use otto_tenant::Tx;
use serde::Serialize;
use sqlx::FromRow;

const DOMAIN_COLS: &str = "org_id, domain, verification_token, verified_at, created_at";

/// A fresh verification token for a domain claim.
///
/// 24 bytes of randomness, base64url-encoded — plenty for a value an admin
/// pastes once into a DNS TXT record and this server compares back exactly.
/// Generated with the workspace `rand` crate directly, not
/// `otto_auth::crypto::generate()`: `otto-auth` depends on `otto-core`, not the
/// other way around, so reaching for that generator here would be the wrong
/// layering direction. The HTTP layer's `POST .../sso/domains` handler (Phase 4)
/// calls this before calling [`claim`].
pub fn generate_verification_token() -> String {
    let mut buf = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimedDomain {
    pub org_id: OrgId,
    pub domain: String,
    pub verification_token: String,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Domains are matched case-insensitively everywhere they're read, but stored
/// normalized too, so `list`/`delete`'s plain `domain = $2` predicates stay
/// correct without repeating `lower()` at every call site.
fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err(Error::Invalid("a domain is required".into()));
    }
    Ok(domain)
}

/// Claim a domain for this org, minting (or replacing) its verification
/// token and resetting `verified_at` to `NULL` — a re-claim always restarts
/// verification rather than trusting a stale proof.
///
/// `INSERT ... ON CONFLICT (domain) DO UPDATE ... WHERE claimed_domains.org_id
/// = $1`: the `WHERE` clause is what makes this safe for a domain already
/// held by *another* org. Postgres still finds the conflicting row (the
/// `ON CONFLICT` target matched), but the `WHERE` blocks the `DO UPDATE`, so
/// the statement acts like `DO NOTHING` for that specific conflict and
/// `RETURNING` yields zero rows — which is exactly what `fetch_optional`
/// coming back `None` means here (the same "zero rows affected" outcome
/// `rows_affected() == 0` would report on a plain `execute`, just observed
/// through `RETURNING` since a successful claim needs the row back anyway).
/// A `None` is `Error::DomainAlreadyClaimed` — a generic message that
/// deliberately does not name which org holds it: this is a full
/// account/organization identity, not a bounded disclosure like the JIRA
/// site-registration precedent, so nothing beyond "you were refused" is
/// confirmed.
///
/// Re-claiming this org's own *only verified* domain while `enforce_sso` is
/// on is refused the same way [`delete`] refuses removing it: a re-claim
/// resets `verified_at` to `NULL`, which would strand every member who isn't
/// already federated exactly as deleting the row would — same outcome, no
/// reason to guard one path and not the other. See [`delete`]'s doc comment
/// for the locking rationale, which applies identically here.
pub async fn claim(
    tx: &mut Tx<'_>,
    domain: &str,
    verification_token: &str,
) -> Result<ClaimedDomain> {
    let org_id = tx.org();
    let domain = normalize_domain(domain)?;

    crate::orgs::lock_for_sso_guard(tx).await?;

    if crate::orgs::enforce_sso_flag(tx).await? {
        let target_verified: Option<bool> = sqlx::query_scalar(
            "SELECT verified_at IS NOT NULL FROM claimed_domains \
             WHERE org_id = $1 AND domain = $2",
        )
        .bind(org_id)
        .bind(&domain)
        .fetch_optional(tx.conn())
        .await?;

        if target_verified == Some(true) {
            let other_verified: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM claimed_domains \
                 WHERE org_id = $1 AND domain <> $2 AND verified_at IS NOT NULL",
            )
            .bind(org_id)
            .bind(&domain)
            .fetch_one(tx.conn())
            .await?;

            if other_verified == 0 {
                return Err(Error::SsoLockout {
                    reason: "cannot re-claim this org's only verified domain while \
                             enforce_sso is on — re-claiming resets verification and \
                             would strand every member who isn't already federated, the \
                             same way removing it would. Turn off enforce_sso first, or \
                             verify another domain before re-claiming this one."
                        .to_string(),
                });
            }
        }
    }

    let row: Option<ClaimedDomain> = sqlx::query_as(&format!(
        "INSERT INTO claimed_domains (org_id, domain, verification_token, verified_at) \
         VALUES ($1, $2, $3, NULL) \
         ON CONFLICT (domain) DO UPDATE SET \
           verification_token = EXCLUDED.verification_token, \
           verified_at = NULL \
         WHERE claimed_domains.org_id = $1 \
         RETURNING {DOMAIN_COLS}"
    ))
    .bind(org_id)
    .bind(&domain)
    .bind(verification_token)
    .fetch_optional(tx.conn())
    .await?;

    row.ok_or(Error::DomainAlreadyClaimed)
}

pub async fn list(tx: &mut Tx<'_>) -> Result<Vec<ClaimedDomain>> {
    let rows = sqlx::query_as(&format!(
        "SELECT {DOMAIN_COLS} FROM claimed_domains WHERE org_id = $1 ORDER BY domain"
    ))
    .bind(tx.org())
    .fetch_all(tx.conn())
    .await?;

    Ok(rows)
}

/// Mark a domain verified, after the DNS TXT lookup (done outside any `Tx` —
/// see `otto_auth::dns::verify_txt_record`) has already succeeded. Called only
/// on a domain this org itself claimed; a domain this org never claimed (or
/// already released) is `Error::Invalid`, not a silent no-op.
pub async fn mark_verified(tx: &mut Tx<'_>, domain: &str) -> Result<ClaimedDomain> {
    let org_id = tx.org();
    let domain = normalize_domain(domain)?;

    let row: Option<ClaimedDomain> = sqlx::query_as(&format!(
        "UPDATE claimed_domains SET verified_at = now() \
         WHERE org_id = $1 AND domain = $2 \
         RETURNING {DOMAIN_COLS}"
    ))
    .bind(org_id)
    .bind(&domain)
    .fetch_optional(tx.conn())
    .await?;

    row.ok_or_else(|| Error::Invalid(format!("domain {domain:?} is not claimed by this org")))
}

/// Remove a claimed domain (verified or not).
///
/// Refused while `enforce_sso` is on **and** this is the org's only currently
/// *verified* domain (excluding this one) — removing the last routable
/// domain would strand every member who isn't already linked, with no way to
/// reach either the anonymous sign-in path or the authenticated link-start
/// path (the latter needs a session, which under `enforce_sso` nobody
/// not-yet-federated can obtain). Deleting a non-last verified domain, or an
/// unverified one, always proceeds — those never leave the org with zero
/// working paths.
///
/// `orgs::lock_for_sso_guard` is called first, before either the verified-
/// count check or the delete itself, and held for the rest of the
/// transaction: without it, two concurrent deletes against the org's two
/// verified domains can each read "not the last one" before either commits,
/// and both succeed — landing the org in the exact locked-out state this
/// guard exists to prevent. See `orgs::lock_for_sso_guard`'s own doc comment.
pub async fn delete(tx: &mut Tx<'_>, domain: &str) -> Result<()> {
    let org_id = tx.org();
    let domain = normalize_domain(domain)?;

    crate::orgs::lock_for_sso_guard(tx).await?;

    if crate::orgs::enforce_sso_flag(tx).await? {
        let target_verified: Option<bool> = sqlx::query_scalar(
            "SELECT verified_at IS NOT NULL FROM claimed_domains \
             WHERE org_id = $1 AND domain = $2",
        )
        .bind(org_id)
        .bind(&domain)
        .fetch_optional(tx.conn())
        .await?;

        if target_verified == Some(true) {
            let other_verified: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM claimed_domains \
                 WHERE org_id = $1 AND domain <> $2 AND verified_at IS NOT NULL",
            )
            .bind(org_id)
            .bind(&domain)
            .fetch_one(tx.conn())
            .await?;

            if other_verified == 0 {
                return Err(Error::SsoLockout {
                    reason: "cannot remove this org's only verified domain while \
                             enforce_sso is on — it is the last routable SSO path for \
                             anyone who isn't already federated. Turn off enforce_sso \
                             first, or verify another domain before removing this one."
                        .to_string(),
                });
            }
        }
    }

    let result = sqlx::query("DELETE FROM claimed_domains WHERE org_id = $1 AND domain = $2")
        .bind(org_id)
        .bind(&domain)
        .execute(tx.conn())
        .await?;

    // Mirrors mark_verified's own rule, above: a domain this org never
    // claimed (a typo, already-released, or — since `domain` is a global
    // primary key — actually owned by a different org) is a refusal, not a
    // silent no-op. Without this, a caller sees 204/success and an audit
    // row for a deletion that never happened.
    if result.rows_affected() == 0 {
        return Err(Error::Invalid(format!(
            "domain {domain:?} is not claimed by this org"
        )));
    }
    Ok(())
}
