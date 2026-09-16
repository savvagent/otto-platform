//! Console browser sessions.
//!
//! The console's own credential, distinct from everything in [`crate::tokens`].
//! An access token says *what a client may do* and is bound to one org; a
//! session says *which human is at the keyboard* and is bound to none, because
//! a person switching between two orgs they belong to should not have to log in
//! twice. The org is chosen per request from the session's memberships.
//!
//! Storage is the same shape as every other credential: an opaque random token
//! handed out once, only its SHA-256 hash retained.
//!
//! **Two clocks, and they answer different questions.** [`IDLE_TTL_DAYS`] is
//! how long a session survives without being used, and [`resolve`] slides it
//! forward so an active user is not logged out mid-week. [`ABSOLUTE_TTL_DAYS`]
//! is how long it may live at all, and nothing slides it — without an absolute
//! cap a stolen cookie that is quietly used once a fortnight never expires,
//! which is the whole failure mode sliding expiry introduces.
//!
//! **Cookie attributes are the caller's job**, and they are not optional:
//! `HttpOnly` (script must not read it), `Secure`, `Path=/`, and
//! `SameSite=Lax` — `Lax` rather than `Strict` because `/oauth/authorize` is
//! reached by a top-level navigation from the agent that started the flow, and
//! `Strict` would drop the cookie there and bounce an already-signed-in user
//! back to a login screen.

use chrono::{DateTime, Duration, Utc};
use otto_tenant::ids::UserId;
use otto_tenant::Db;
use serde::Serialize;
use uuid::Uuid;

use crate::crypto::{self, prefix};
use crate::error::{AuthError, Result};

/// Idle timeout: a session unused for this long is dead.
pub const IDLE_TTL_DAYS: i64 = 14;

/// Hard ceiling measured from creation, regardless of use.
pub const ABSOLUTE_TTL_DAYS: i64 = 90;

/// The sliding window must be shorter than the cap, or the cap never binds and
/// a session that is used occasionally is immortal. Checked at compile time
/// because it is a property of the two constants, not of any code path.
const _: () = assert!(ABSOLUTE_TTL_DAYS > IDLE_TTL_DAYS);

/// A session as the console reads it. No token, plaintext or hashed — a caller
/// that already resolved a session has no further use for the credential, and
/// this type is serialized into the "your active sessions" view.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub user_id: UserId,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// A freshly created session: the cookie value, once, plus the row.
pub struct NewSession {
    pub token: String,
    pub session: Session,
}

impl std::fmt::Debug for NewSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSession")
            .field("token", &"<redacted>")
            .field("session", &self.session)
            .finish()
    }
}

/// Open a session for a user who has just proved who they are.
///
/// Always a new row. There is no session-fixation risk to defend against here
/// because no session exists before login — nothing is being *upgraded* — but
/// the same property makes "log out everywhere" (see [`revoke_all`]) mean what
/// it says, since no old row survives a fresh login by another route.
pub async fn create(db: &Db, user: UserId) -> Result<NewSession> {
    let token = crypto::generate(prefix::SESSION);
    let expires_at = Utc::now() + Duration::days(IDLE_TTL_DAYS);

    let session: Session = sqlx::query_as(
        "INSERT INTO browser_sessions (user_id, token_hash, expires_at) VALUES ($1,$2,$3) \
         RETURNING id, user_id, expires_at, created_at",
    )
    .bind(user)
    .bind(&token.hash)
    .bind(expires_at)
    .fetch_one(db.pool())
    .await?;

    Ok(NewSession {
        token: token.into_plaintext(),
        session,
    })
}

/// A resolved row, before the liveness checks.
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: UserId,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    /// From `users`, joined: a disabled account must lose its live sessions the
    /// moment it is disabled, not whenever the cookie happens to expire.
    disabled_at: Option<DateTime<Utc>>,
}

/// Resolve a presented cookie value to a live session.
pub async fn resolve(db: &Db, presented: &str) -> Result<Session> {
    let hash = crypto::hash(presented.trim());

    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.expires_at, s.created_at, s.revoked_at, u.disabled_at \
         FROM browser_sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;

    // Unknown and revoked are the same answer, for the same reason as in
    // `tokens::introspect`: whether a given string was ever a session is not
    // something a caller gets to probe for.
    let s = row.ok_or(AuthError::Revoked)?;

    if s.revoked_at.is_some() {
        return Err(AuthError::Revoked);
    }
    if s.disabled_at.is_some() {
        return Err(AuthError::Disabled);
    }

    let now = Utc::now();
    if s.expires_at <= now {
        return Err(AuthError::Expired);
    }
    let hard_deadline = s.created_at + Duration::days(ABSOLUTE_TTL_DAYS);
    if hard_deadline <= now {
        return Err(AuthError::Expired);
    }

    // Slide the idle window, but only once it is half spent. Extending on every
    // request would put a write on every authenticated page load to move a
    // deadline that is two weeks out; this costs at most one write per session
    // per week and produces the same user-visible behaviour.
    let mut expires_at = s.expires_at;
    if expires_at - now < Duration::days(IDLE_TTL_DAYS / 2) {
        // Never past the hard deadline — that is the point of having one.
        let extended = (now + Duration::days(IDLE_TTL_DAYS)).min(hard_deadline);
        sqlx::query("UPDATE browser_sessions SET expires_at = $2 WHERE id = $1")
            .bind(s.id)
            .bind(extended)
            .execute(db.pool())
            .await?;
        expires_at = extended;
    }

    Ok(Session {
        id: s.id,
        user_id: s.user_id,
        expires_at,
        created_at: s.created_at,
    })
}

/// End one session — the logout button.
///
/// Silent about whether the value matched anything: a logout that reports "no
/// such session" tells a visitor holding a stale cookie something, and there is
/// nothing useful for a caller to do differently either way.
pub async fn revoke(db: &Db, presented: &str) -> Result<()> {
    let hash = crypto::hash(presented.trim());
    sqlx::query("UPDATE browser_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL")
        .bind(&hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// End every session for a user — "log out everywhere", and the force-logout an
/// admin reaches for when a laptop goes missing.
///
/// Sessions only. Access tokens and PATs are a separate credential with a
/// separate revocation path ([`crate::tokens::revoke_family`],
/// [`crate::tokens::revoke_by_id`]), and an admin dealing with a lost device
/// needs both — quietly revoking tokens from here would make "log out
/// everywhere" disconnect the user's agents too, which is a different decision
/// than the button describes.
pub async fn revoke_all(db: &Db, user: UserId) -> Result<u64> {
    let n = sqlx::query(
        "UPDATE browser_sessions SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(n)
}

/// The same revocation as [`revoke_all`], but run against a connection the
/// caller already holds a transaction on.
///
/// An admin-assisted passkey reset calls this: revoking the target's
/// sessions must commit together with the passkey clear and the new claim
/// code, or a failure partway through can leave the account cleared with no
/// way back in.
pub async fn revoke_all_tx(conn: &mut sqlx::PgConnection, user: UserId) -> Result<u64> {
    let n = sqlx::query(
        "UPDATE browser_sessions SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .execute(conn)
    .await?
    .rows_affected();
    Ok(n)
}

/// Live sessions for a user, newest first — what the console lists so someone
/// can see where they are signed in.
pub async fn list(db: &Db, user: UserId) -> Result<Vec<Session>> {
    let rows = sqlx::query_as(
        "SELECT id, user_id, expires_at, created_at FROM browser_sessions \
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() \
           AND created_at > now() - make_interval(days => $2) \
         ORDER BY created_at DESC",
    )
    .bind(user)
    .bind(ABSOLUTE_TTL_DAYS as i32)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Delete sessions that can no longer be resolved by any path.
pub async fn sweep(db: &Db) -> Result<u64> {
    let n = sqlx::query(
        "DELETE FROM browser_sessions \
         WHERE expires_at < now() - interval '7 days' \
            OR created_at < now() - make_interval(days => $1)",
    )
    // `days` is an integer parameter of make_interval; binding an f64 fails at
    // runtime with a no-such-function error. Same trap as `tokens::mint_pat`.
    .bind((ABSOLUTE_TTL_DAYS + 7) as i32)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_the_cookie_value() {
        let s = NewSession {
            token: "otto_ss_supersecret".into(),
            session: Session {
                id: Uuid::nil(),
                user_id: UserId::new(),
                expires_at: Utc::now(),
                created_at: Utc::now(),
            },
        };
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("supersecret"), "Debug leaked the token");
        assert!(rendered.contains("redacted"));
    }
}
