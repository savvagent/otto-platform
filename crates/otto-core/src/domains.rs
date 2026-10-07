//! Enterprise OIDC federation — claimed email domains.
//!
//! Any number of orgs may hold a pending claim on a domain, but at most one
//! may hold a *verified* one (`claimed_domains_verified_domain_key`, migration
//! 0008). Control is proved with a DNS TXT record before `verified_at` is
//! set: an unverified claim routes nobody, so claiming `gmail.com`
//! accomplishes nothing, and it no longer blocks anyone either — the first
//! org to pass verification wins, and its verified claim then blocks every
//! other org until it is released. Like
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
/// Refused with `Error::DomainAlreadyClaimed` only when **another org has
/// verified** this domain. Another org's pending claim does not block this
/// one: a claim proves nothing until DNS verification, so letting an
/// unverified claim reserve a domain would let any org squat on any domain
/// and lock its real owner out of SSO (savvagent/otto-platform#6). The error
/// deliberately does not name which org holds the domain.
///
/// A race with another org verifying between the check and the insert is
/// harmless: this org ends up with a pending claim it can never verify while
/// the other holds the domain, which [`mark_verified`] reports.
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

    if verified_elsewhere(tx, &domain).await? {
        return Err(Error::DomainAlreadyClaimed);
    }

    let row = sqlx::query_as(&format!(
        "INSERT INTO claimed_domains (org_id, domain, verification_token, verified_at) \
         VALUES ($1, $2, $3, NULL) \
         ON CONFLICT (org_id, domain) DO UPDATE SET \
           verification_token = EXCLUDED.verification_token, \
           verified_at = NULL \
         RETURNING {DOMAIN_COLS}"
    ))
    .bind(org_id)
    .bind(&domain)
    .bind(verification_token)
    .fetch_one(tx.conn())
    .await?;

    Ok(row)
}

/// Whether an org other than this one holds a verified claim on `domain`.
///
/// The one read in this module that is not pinned to `org_id = $1`, because
/// its whole question is about other orgs. It returns a boolean and nothing
/// about who.
async fn verified_elsewhere(tx: &mut Tx<'_>, domain: &str) -> Result<bool> {
    let org_id = tx.org();
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claimed_domains \
                        WHERE domain = $1 AND org_id <> $2 AND verified_at IS NOT NULL)",
    )
    .bind(domain)
    .bind(org_id)
    .fetch_one(tx.conn())
    .await?;
    Ok(held)
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
///
/// If another org verified the domain first, this is
/// `Error::DomainAlreadyClaimed`. That is checked up front for a clean error,
/// and enforced by the `claimed_domains_verified_domain_key` unique index for
/// the race where both orgs verify at once; in that case the losing
/// statement has aborted the transaction and the caller must roll back.
///
/// Other orgs' pending claims on the domain are left in place rather than
/// deleted: every write here is pinned to this org, and a pending claim
/// becomes verifiable again if the winner later releases the domain.
pub async fn mark_verified(tx: &mut Tx<'_>, domain: &str) -> Result<ClaimedDomain> {
    let org_id = tx.org();
    let domain = normalize_domain(domain)?;

    if verified_elsewhere(tx, &domain).await? {
        return Err(Error::DomainAlreadyClaimed);
    }

    let row: Option<ClaimedDomain> = sqlx::query_as(&format!(
        "UPDATE claimed_domains SET verified_at = now() \
         WHERE org_id = $1 AND domain = $2 \
         RETURNING {DOMAIN_COLS}"
    ))
    .bind(org_id)
    .bind(&domain)
    .fetch_optional(tx.conn())
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("claimed_domains_verified_domain_key") =>
        {
            Error::DomainAlreadyClaimed
        }
        _ => Error::from(e),
    })?;

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
    // claimed (a typo, already released, or claimed only by a different org)
    // is a refusal, not a silent no-op. Without this, a caller sees 204/success and an audit
    // row for a deletion that never happened.
    if result.rows_affected() == 0 {
        return Err(Error::Invalid(format!(
            "domain {domain:?} is not claimed by this org"
        )));
    }
    Ok(())
}
