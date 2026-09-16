//! Access tokens, refresh rotation, and personal access tokens.
//!
//! Tokens are **opaque random strings stored only as SHA-256 hashes**. That
//! choice deletes a whole family of JWT failure modes — algorithm confusion,
//! `alg: none`, key confusion, unverifiable revocation — by not having a signed
//! token at all. The cost is a database read per request, which is one indexed
//! lookup on a primary key.
//!
//! Two invariants here are load-bearing and each has a dedicated test:
//!
//! 1. **Audience enforcement** (RFC 8707). A token is minted for one `resource`
//!    and [`introspect`] refuses it anywhere else. This is the confused-deputy
//!    defense that lets one identity database (otto-platform) serve every
//!    otto-* resource server: a token minted for otto-factory must not open
//!    otto-flags, and vice versa.
//! 2. **Refresh reuse detection.** Redeeming a refresh token consumes it and
//!    issues a successor. Presenting a consumed one means the token leaked, so
//!    the entire chain is revoked rather than the call merely rejected.

use chrono::{DateTime, Duration, Utc};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use serde::Serialize;
use uuid::Uuid;

use crate::crypto::{self, prefix};
use crate::error::{AuthError, Result};

/// Access token lifetime. Short, because revocation is checked at use and a
/// stolen token's window matters more than the cost of refreshing.
pub const ACCESS_TTL_MINUTES: i64 = 60;

/// Refresh token lifetime. Rotated on every use, so this is the idle timeout
/// rather than a session cap.
pub const REFRESH_TTL_DAYS: i64 = 30;

/// Authorization code lifetime. Deliberately tiny: a code is exchanged
/// immediately by a client that already has it, so anything longer is pure
/// attack surface. RFC 6749 recommends a maximum of ten minutes; sixty seconds
/// is comfortable for a redirect and hostile to anything else.
pub const AUTH_CODE_TTL_SECONDS: i64 = 60;

/// Default personal access token lifetime.
pub const PAT_TTL_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, sqlx::Type)]
#[sqlx(type_name = "token_kind", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Oauth,
    Pat,
}

/// The authenticated caller, as an otto-* resource server sees it.
///
/// `org_id` is **fixed at issuance** and carried on the token, never chosen per
/// request. A user may belong to many orgs; a token opens exactly one. That is
/// what makes a stolen token non-pivotable, and it is why a resource server
/// can pin a transaction without re-deciding authorization on every call.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Principal {
    pub token_id: Uuid,
    pub user_id: UserId,
    pub org_id: OrgId,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub kind: TokenKind,
    pub expires_at: DateTime<Utc>,
}

impl Principal {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Require a scope, or fail. Used at the top of every tool handler that
    /// mutates anything.
    pub fn require_scope(&self, scope: &str) -> Result<()> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(AuthError::InvalidScope(format!(
                "this token lacks the {scope} scope"
            )))
        }
    }
}

/// A minted token pair, handed to the caller exactly once.
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scopes: Vec<String>,
}

/// Redacting `Debug`, not a derived one.
///
/// This struct holds live bearer credentials. A derived `Debug` would put them
/// in any log line, `dbg!`, or test panic that touches the value — which is the
/// most common way credentials escape. The impl still exists because callers
/// legitimately need `Result::unwrap_err` and friends; it just refuses to print
/// the secrets. Same rule as [`crate::crypto::Secret`].
impl std::fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scopes", &self.scopes)
            .finish()
    }
}

pub struct IssueParams<'a> {
    pub user_id: UserId,
    pub org_id: OrgId,
    pub client_id: Option<&'a str>,
    pub scopes: &'a [String],
    pub resource: &'a str,
    pub with_refresh: bool,
}

/// Mint an access token, and optionally a refresh token.
pub async fn issue(db: &Db, p: IssueParams<'_>) -> Result<IssuedTokens> {
    let access = crypto::generate(prefix::ACCESS);
    let expires_at = Utc::now() + Duration::minutes(ACCESS_TTL_MINUTES);
    let scopes: Vec<String> = p.scopes.to_vec();

    let access_id: Uuid = sqlx::query_scalar(
        "INSERT INTO access_tokens \
           (token_hash, kind, user_id, org_id, client_id, scopes, resource, expires_at) \
         VALUES ($1, 'oauth', $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&access.hash)
    .bind(p.user_id)
    .bind(p.org_id)
    .bind(p.client_id)
    .bind(&scopes)
    .bind(p.resource)
    .bind(expires_at)
    .fetch_one(db.pool())
    .await?;

    let refresh_plaintext = if p.with_refresh {
        let refresh = crypto::generate(prefix::REFRESH);
        sqlx::query(
            "INSERT INTO refresh_tokens \
               (token_hash, access_token_id, user_id, org_id, client_id, scopes, resource, expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&refresh.hash)
        .bind(access_id)
        .bind(p.user_id)
        .bind(p.org_id)
        .bind(p.client_id.unwrap_or_default())
        .bind(&scopes)
        .bind(p.resource)
        .bind(Utc::now() + Duration::days(REFRESH_TTL_DAYS))
        .execute(db.pool())
        .await?;
        Some(refresh.into_plaintext())
    } else {
        None
    };

    Ok(IssuedTokens {
        access_token: access.into_plaintext(),
        refresh_token: refresh_plaintext,
        expires_in: ACCESS_TTL_MINUTES * 60,
        scopes,
    })
}

/// A row from `access_tokens`. Named rather than a tuple so the field order
/// cannot silently desynchronize from the SELECT list — `sqlx::FromRow` maps by
/// column name, which a tuple does not.
#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    user_id: UserId,
    org_id: OrgId,
    client_id: Option<String>,
    scopes: Vec<String>,
    resource: String,
    kind: TokenKind,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Resolve a presented bearer token to a [`Principal`].
///
/// `expected_resource` is the canonical URI of *this* resource server, and a
/// token minted for anything else is refused. Never make this parameter
/// optional "for convenience" — an unaudienced introspection is the confused
/// deputy the RFC exists to prevent.
pub async fn introspect(db: &Db, presented: &str, expected_resource: &str) -> Result<Principal> {
    let hash = crypto::hash(presented.trim());

    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT id, user_id, org_id, client_id, scopes, resource, kind, expires_at, revoked_at \
         FROM access_tokens WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;

    // An unknown token and a revoked one are reported identically: whether a
    // given string was ever a valid token is not something a caller should be
    // able to probe for.
    let t = row.ok_or(AuthError::Revoked)?;

    if t.revoked_at.is_some() {
        return Err(AuthError::Revoked);
    }
    if t.expires_at <= Utc::now() {
        return Err(AuthError::Expired);
    }
    // Audience check. Constant-time is unnecessary here (the resource is public
    // and not a secret), but exact match is essential — no prefix, no suffix,
    // no "starts with our host".
    if t.resource != expected_resource {
        return Err(AuthError::WrongAudience);
    }

    // Best-effort last-use stamp for the console's "active tokens" view. A
    // failure here must not fail the request.
    let _ = sqlx::query("UPDATE access_tokens SET last_used_at = now() WHERE id = $1")
        .bind(t.id)
        .execute(db.pool())
        .await;

    Ok(Principal {
        token_id: t.id,
        user_id: t.user_id,
        org_id: t.org_id,
        client_id: t.client_id,
        scopes: t.scopes,
        kind: t.kind,
        expires_at: t.expires_at,
    })
}

/// A row from `refresh_tokens`.
#[derive(sqlx::FromRow)]
struct RefreshRow {
    id: Uuid,
    user_id: UserId,
    org_id: OrgId,
    client_id: String,
    scopes: Vec<String>,
    resource: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Redeem a refresh token, rotating it.
///
/// On success the presented token is consumed and a successor is issued. On
/// **reuse** — a token that was already consumed — the whole chain is revoked
/// and [`AuthError::InvalidGrant`] is returned. That is the correct response to
/// a replay: either the client is buggy or the token leaked, and only one of
/// those is safe to ignore, so we assume the other.
pub async fn redeem_refresh(
    db: &Db,
    presented: &str,
    client_id: &str,
    expected_resource: &str,
) -> Result<(IssuedTokens, UserId, OrgId, bool)> {
    let hash = crypto::hash(presented.trim());

    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT id, user_id, org_id, client_id, scopes, resource, expires_at, consumed_at, revoked_at \
         FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;

    let r = row.ok_or_else(|| AuthError::InvalidGrant("unknown refresh token".into()))?;

    // Reuse: revoke the family before returning, so the attacker's stolen
    // successor stops working too.
    if r.consumed_at.is_some() {
        revoke_family(db, r.user_id, r.org_id, &r.client_id).await?;
        return Err(AuthError::InvalidGrant(
            "refresh token was already used; the token family has been revoked".into(),
        ));
    }
    if r.revoked_at.is_some() {
        return Err(AuthError::InvalidGrant("refresh token was revoked".into()));
    }
    if r.expires_at <= Utc::now() {
        return Err(AuthError::InvalidGrant("refresh token expired".into()));
    }
    // A refresh token belongs to the client it was issued to. Without this a
    // leaked token could be redeemed by any registered client.
    if r.client_id != client_id {
        return Err(AuthError::InvalidGrant(
            "refresh token was issued to a different client".into(),
        ));
    }
    if r.resource != expected_resource {
        return Err(AuthError::InvalidGrant(
            "refresh token was issued for a different resource".into(),
        ));
    }

    let issued = issue(
        db,
        IssueParams {
            user_id: r.user_id,
            org_id: r.org_id,
            client_id: Some(client_id),
            scopes: &r.scopes,
            resource: &r.resource,
            with_refresh: true,
        },
    )
    .await?;

    // Consume the presented token last, so a failure to mint the successor
    // leaves the caller's existing token usable rather than stranding them.
    sqlx::query("UPDATE refresh_tokens SET consumed_at = now() WHERE id = $1")
        .bind(r.id)
        .execute(db.pool())
        .await?;

    Ok((issued, r.user_id, r.org_id, false))
}

/// Revoke every token for one (user, org, client).
///
/// Broader than strictly necessary — the leaked token's own chain would do —
/// but the schema tracks rotation with `rotated_to` rather than a family id,
/// and an attacker who has one token from a session plausibly has others. Over-
/// revoking costs a legitimate user one re-login; under-revoking leaves the
/// attacker holding a live credential.
pub async fn revoke_family(db: &Db, user: UserId, org: OrgId, client_id: &str) -> Result<u64> {
    let mut tx = db.begin_unpinned().await?;

    let access = sqlx::query(
        "UPDATE access_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND org_id = $2 AND client_id = $3 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(org)
    .bind(client_id)
    .execute(tx.conn())
    .await?
    .rows_affected();

    let refresh = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND org_id = $2 AND client_id = $3 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(org)
    .bind(client_id)
    .execute(tx.conn())
    .await?
    .rows_affected();

    tx.commit().await?;
    Ok(access + refresh)
}

/// Revoke one token by its presented value (RFC 7009). Idempotent and silent:
/// the RFC requires a 200 even for an unknown token, so this never reports
/// whether the token existed.
pub async fn revoke_presented(db: &Db, presented: &str) -> Result<()> {
    let hash = crypto::hash(presented.trim());
    sqlx::query("UPDATE access_tokens SET revoked_at = now() WHERE token_hash = $1")
        .bind(&hash)
        .execute(db.pool())
        .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1")
        .bind(&hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Personal access tokens
// ---------------------------------------------------------------------------

/// Mint a PAT.
///
/// This is the compatibility path for MCP clients whose OAuth support is
/// partial or absent: the user pastes a bearer token into their agent's config.
/// It carries exactly the same claims as an OAuth token — same table, same
/// audience enforcement, same scope model — so no code downstream needs to know
/// which kind it received. That equivalence is the point: agent-agnosticism
/// must not mean a weaker security model for the awkward clients.
pub async fn mint_pat(
    db: &Db,
    user: UserId,
    org: OrgId,
    name: &str,
    scopes: &[String],
    resource: &str,
    ttl_days: Option<i64>,
) -> Result<(String, Uuid)> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AuthError::InvalidRequest("a PAT needs a name".into()));
    }

    let token = crypto::generate(prefix::PAT);
    let ttl = ttl_days.unwrap_or(PAT_TTL_DAYS).clamp(1, 365);

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO access_tokens \
           (token_hash, kind, name, user_id, org_id, scopes, resource, expires_at) \
         VALUES ($1, 'pat', $2, $3, $4, $5, $6, now() + make_interval(days => $7)) \
         RETURNING id",
    )
    .bind(&token.hash)
    .bind(name)
    .bind(user)
    .bind(org)
    .bind(scopes)
    .bind(resource)
    // `days` is an integer parameter of make_interval; `secs` is the double
    // one. Binding an f64 here fails at runtime with a no-such-function error.
    .bind(ttl as i32)
    .fetch_one(db.pool())
    .await?;

    Ok((token.into_plaintext(), id))
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct TokenSummary {
    pub id: Uuid,
    pub name: Option<String>,
    pub kind: TokenKind,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Live tokens for a user in an org — what the console lists so a user can see
/// and revoke what is connected.
pub async fn list_tokens(db: &Db, user: UserId, org: OrgId) -> Result<Vec<TokenSummary>> {
    let rows = sqlx::query_as(
        "SELECT id, name, kind, client_id, scopes, created_at, last_used_at, expires_at \
         FROM access_tokens \
         WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL AND expires_at > now() \
         ORDER BY created_at DESC",
    )
    .bind(user)
    .bind(org)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Revoke every token a user holds **in one org**.
///
/// What removing someone from an org has to do, and the reason it is scoped
/// rather than global: a token's org is fixed at issuance, so a person who is
/// still a member of two other orgs keeps working there. Leaving these behind
/// is the failure worth naming — a removed member's agent would keep claiming
/// work on a token that outlives their membership by up to its full lifetime,
/// and nothing in the console would explain why.
pub async fn revoke_all_in_org(db: &Db, user: UserId, org: OrgId) -> Result<u64> {
    // Both updates run in one transaction: if the refresh-token statement
    // failed after the access-token one had already committed, a removed
    // member's refresh token would still mint a fresh access token, undoing
    // the revocation this function exists to guarantee.
    let mut tx = db.begin_unpinned().await?;
    let revoked = revoke_all_in_org_on(tx.conn(), user, org).await?;
    tx.commit().await?;
    Ok(revoked)
}

/// The same revocation as [`revoke_all_in_org`], but run against a connection
/// the caller already holds a transaction on.
///
/// Membership removal calls this: deleting the `org_members` row and revoking
/// the removed member's tokens for that org must commit together, or a
/// failure of the second half after the first has committed leaves a
/// dangling member-shaped bearer token — introspection does not re-check
/// membership, so it would go on working until it naturally expired.
pub async fn revoke_all_in_org_tx(
    conn: &mut sqlx::PgConnection,
    user: UserId,
    org: OrgId,
) -> Result<u64> {
    revoke_all_in_org_on(conn, user, org).await
}

async fn revoke_all_in_org_on(
    conn: &mut sqlx::PgConnection,
    user: UserId,
    org: OrgId,
) -> Result<u64> {
    let access = sqlx::query(
        "UPDATE access_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(org)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    // Refresh tokens too, or the next refresh quietly mints a working access
    // token for someone who was just removed.
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(org)
    .execute(&mut *conn)
    .await?;

    Ok(access)
}

/// Revoke one token by id, scoped to its owner so a user cannot revoke another's.
pub async fn revoke_by_id(db: &Db, user: UserId, org: OrgId, id: Uuid) -> Result<bool> {
    let n = sqlx::query(
        "UPDATE access_tokens SET revoked_at = now() \
         WHERE id = $1 AND user_id = $2 AND org_id = $3 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(user)
    .bind(org)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Delete expired tokens. Revoked-but-unexpired rows are kept so introspection
/// can distinguish "revoked" from "never existed" while the token could still
/// plausibly be presented.
pub async fn sweep(db: &Db) -> Result<u64> {
    let a = sqlx::query("DELETE FROM access_tokens WHERE expires_at < now() - interval '7 days'")
        .execute(db.pool())
        .await?
        .rows_affected();
    let r = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now() - interval '7 days'")
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok(a + r)
}
