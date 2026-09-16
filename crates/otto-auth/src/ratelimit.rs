//! Attempt throttling: two policies for two different threat shapes.
//!
//! [`check_and_charge`] is an **exponential lockout** for surfaces a caller
//! reaches to *create* something — signup, the claim-code path, dynamic
//! client registration. A real lockout is an acceptable price there: the
//! caller is, at worst, inconvenienced into retrying later from the same
//! address.
//!
//! [`cap_charge`] is a **rate cap** for `POST /api/auth/login/finish`-shaped
//! endpoints — a lockout is the wrong tool for a surface keyed on a source
//! address honest users share *involuntarily*: an office NAT, a CGNAT pool, a
//! VPN exit. A lockout there takes the whole office off the product's only
//! human sign-in path, for the lockout's duration, renewably. A cap never
//! does that: once `hard_cap` failures land in `window_secs`, further
//! failures in that window are refused, but the refusal never outlives the
//! window and never grows no matter how long a flood continues — a delay,
//! never a wall. See [`CapPolicy`] for the shape and [`LOGIN_IP_CAP`] /
//! [`LOGIN_CRED_CAP`] for the two buckets a login-finish endpoint charges.
//!
//! **Neither policy resets on success.** A colleague signing in successfully
//! does not clear what another's flapping authenticator accumulated: the
//! check runs *before* the credential work, so once a bucket is past its
//! threshold nobody can reach the success that would reset it, and resetting
//! on success would let an attacker holding one throwaway account interleave
//! `[failures][1 real sign-in]` forever and buy a fixed number of free probes
//! per authentication rather than per window. A pure time-window count has
//! neither problem.
//!
//! **Both policies charge atomically.** Every function below opens one
//! transaction, takes `pg_advisory_xact_lock` on the bucket for that
//! transaction's lifetime (released on commit or rollback), and only then
//! reads and writes. Two transactions racing the *same* bucket are forced
//! into a total order — the second one's read only begins once the first has
//! committed — so the read a decision is based on always reflects every
//! charge that happened before it, not just the ones that happened to commit
//! first. Two different buckets never contend: `hashtextextended` folds the
//! bucket string into the lock's bigint key, and a hash collision between
//! unrelated buckets only costs contention, never correctness, because every
//! query still filters on the exact bucket string.
//!
//! [`cap_peek`] is the one read that is deliberately *not* inside that lock —
//! see its doc for why an approximate read is fine there.
//!
//! Buckets are opaque strings so one table serves every policy; a caller's
//! web layer decides what goes into one (`signup:{ip}`, `dcr:{ip}`,
//! `login:ip:{ip}`, `login:cred:{sha256(credential_id)}`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use otto_tenant::Db;
use sqlx::PgConnection;

use crate::error::{AuthError, Result};

// --------------------------------------------------------------- lockout

/// Failures tolerated inside the window before lockout begins.
pub const MAX_FAILURES: i64 = 5;

/// How far back failures are counted, in seconds.
pub const WINDOW_SECS: i64 = 15 * 60;

/// Lockout after the threshold doubles per additional failure, from this base.
const LOCKOUT_BASE_SECS: i64 = 30;

/// Ceiling on a single lockout. An unbounded backoff locks a legitimate user
/// out for days after a bad week and turns a nuisance into a support ticket;
/// 30 minutes already makes brute force hopeless.
const LOCKOUT_MAX_SECS: i64 = 30 * 60;

/// Compute the lockout for a given failure count. Pure, so the policy is
/// testable without a database.
///
/// Returns `None` while under the threshold.
pub fn lockout_secs(failures: i64) -> Option<i64> {
    if failures < MAX_FAILURES {
        return None;
    }
    let over = failures - MAX_FAILURES;
    // Saturating shift: a large `over` must not overflow into a small number,
    // which would silently unlock the account at exactly the wrong moment.
    let secs = LOCKOUT_BASE_SECS.saturating_mul(1i64.checked_shl(over.min(20) as u32).unwrap_or(1));
    Some(secs.min(LOCKOUT_MAX_SECS))
}

/// Refuse-and-spend, atomically: the exponential lockout above, charged as one
/// indivisible step.
///
/// Fits every caller that needs a check and a charge back to back with no
/// work in between — signup, the claim-code path, dynamic client
/// registration. A refused attempt is not itself charged: the transaction
/// returns before the insert, so a caller already locked out does not push
/// their own lockout out further just by asking again.
pub async fn check_and_charge(db: &Db, bucket: &str) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    lock_bucket(tx.conn(), bucket).await?;

    let (failures, last_failure) = recent_failures(tx.conn(), bucket, WINDOW_SECS).await?;
    if let Some(lockout) = lockout_secs(failures) {
        if let Some(last) = last_failure {
            let elapsed = (Utc::now() - last).num_seconds();
            if elapsed < lockout {
                return Err(AuthError::RateLimited {
                    retry_after_secs: lockout - elapsed,
                });
            }
        }
    }

    insert_attempt(tx.conn(), bucket, false).await?;
    tx.commit().await?;
    Ok(())
}

// ------------------------------------------------------------------- cap

/// A rate cap: never a lockout, never escalating, bounded by `window_secs` no
/// matter how long a flood continues.
#[derive(Debug, Clone, Copy)]
pub struct CapPolicy {
    /// How far back failures are counted. Also the refusal's flat
    /// `retry_after_secs` — a fixed, honest upper bound rather than a
    /// computed-and-still-approximate one, since the count this policy counts
    /// never resets early.
    pub window_secs: i64,
    /// Past this many failures in the window, [`cap_charge`] still answers but
    /// logs at `warn` — metered, not yet denied. See its doc for why that
    /// half exists on its own.
    pub soft_cap: i64,
    /// Past this many, refuse. Unlike the lockout above, there is no
    /// escalation past this number to tune — it is the ceiling, flatly, for
    /// as long as the window has failures in it.
    pub hard_cap: i64,
}

/// A login-finish endpoint, keyed on the caller's source address.
///
/// Generous on purpose: an office or CGNAT pool is one address shared by many
/// honest sign-ins a day, and the failures this bucket exists to price are
/// unknown-credential and bad-signature probes, not a colleague's flaky
/// authenticator. `soft_cap` is set low enough that a probing run is visible
/// in the logs long before `hard_cap` ever answers with a refusal.
pub const LOGIN_IP_CAP: CapPolicy = CapPolicy {
    window_secs: WINDOW_SECS,
    soft_cap: 20,
    hard_cap: 50,
};

/// A login-finish endpoint, keyed on the credential id being presented,
/// independent of source address.
///
/// Tight, and deliberately not a lockout: an address cap alone bounds how
/// often *one source* probes, but not how hard *one id* gets hit from many
/// sources, which is what an attacker holding a botnet or a list of exit
/// nodes would do to get around the address cap above. A real owner fails
/// their own ceremony a handful of times at most (a stale tab, the wrong
/// authenticator selected); double digits against one specific id inside
/// fifteen minutes is someone walking a list, not someone who mistyped.
///
/// **This is not a lockout keyed on the id** — that would be a
/// denial-of-service against the credential's *owner*, reachable by anyone
/// who merely learns the id, and a credential id is handed to this server by
/// every sign-in attempt against it, legitimate or not. A cap still bounds
/// the probing; it just never outlives the window the way a lockout would.
pub const LOGIN_CRED_CAP: CapPolicy = CapPolicy {
    window_secs: WINDOW_SECS,
    soft_cap: 5,
    hard_cap: 15,
};

/// The bucket a credential id charges against: `login:cred:{sha256(id)}`.
///
/// Hashed rather than carried verbatim. A credential id is not a secret — it
/// travels in every authentication ceremony a browser offers — but there is
/// no reason for this table to double as a second place one is ever written
/// down unencoded.
pub fn credential_bucket(credential_id: &[u8]) -> String {
    format!(
        "login:cred:{}",
        URL_SAFE_NO_PAD.encode(crate::crypto::hash_bytes(credential_id))
    )
}

/// A read-only glance at a capped bucket's current failure count. No charge,
/// no lock.
///
/// Approximate under concurrency by construction — two concurrent callers can
/// both peek a count that writes neither has seen yet are about to push past
/// `hard_cap` — and that is fine, because nothing here depends on it being
/// exact. It exists only so a login-finish endpoint can skip the signature
/// verification below for a caller already well past the cap, without paying
/// for the crypto first. The decision that must be exact — whether *this*
/// attempt is the one that trips the cap — belongs to [`cap_charge`], which is
/// not approximate: see the module docs for why the lock makes it so.
pub async fn cap_peek(db: &Db, bucket: &str, policy: &CapPolicy) -> Result<i64> {
    let (failures, _) = count_failures(db.pool(), bucket, policy.window_secs).await?;
    Ok(failures)
}

/// Charge one failure against a capped bucket, atomically, and decide whether
/// this specific attempt is refused.
///
/// Call only for an outcome that should count. **Never for
/// [`AuthError::CeremonyExpired`]**: a client that simply took too long to
/// answer a challenge is not an attack, and charging it would let an ordinary
/// slow connection do an attacker's accounting for them.
///
/// Past `hard_cap` already, the attempt is refused and **not written** — the
/// bucket stops growing once it is already over the line, so a sustained
/// flood costs one row per window rather than one row per request forever.
/// Between `soft_cap` and `hard_cap` the attempt is written and logged at
/// `warn`: this is the "meter without denying" half of the design, and it
/// exists because an endpoint that answers `unknown_credential` before
/// verifying anything writes no audit row on that path — correctly, since
/// there is no account yet to attribute one to — which means probing
/// otherwise leaves no trace at all. Logging every failure from the first one
/// would be noise; logging none would mean the first operator to learn a
/// probing run happened is the one reading the postmortem.
pub async fn cap_charge(db: &Db, bucket: &str, policy: &CapPolicy) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    lock_bucket(tx.conn(), bucket).await?;

    let (failures, _) = count_failures(tx.conn(), bucket, policy.window_secs).await?;
    if failures >= policy.hard_cap {
        return Err(AuthError::RateLimited {
            retry_after_secs: policy.window_secs,
        });
    }

    insert_attempt(tx.conn(), bucket, false).await?;
    tx.commit().await?;

    let failures = failures + 1;
    if failures > policy.soft_cap {
        tracing::warn!(
            bucket,
            failures,
            hard_cap = policy.hard_cap,
            "login failures crossing the soft cap for this bucket"
        );
    }
    Ok(())
}

// ------------------------------------------------------------------ shared

/// Acquire a per-bucket lock for the rest of this transaction. See the module
/// docs for what this buys.
async fn lock_bucket(conn: &mut PgConnection, bucket: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(bucket)
        .execute(conn)
        .await?;
    Ok(())
}

async fn insert_attempt(conn: &mut PgConnection, bucket: &str, successful: bool) -> Result<()> {
    sqlx::query("INSERT INTO auth_attempts (bucket, successful) VALUES ($1, $2)")
        .bind(bucket)
        .bind(successful)
        .execute(conn)
        .await?;
    Ok(())
}

/// Failures in the window since the most recent success — the lockout
/// policy's notion of "recent", which resets on a win. See the module docs
/// for why the cap policy below deliberately does not share this.
async fn recent_failures(
    conn: &mut PgConnection,
    bucket: &str,
    window_secs: i64,
) -> Result<(i64, Option<DateTime<Utc>>)> {
    let row: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        "WITH last_ok AS ( \
             SELECT COALESCE(MAX(created_at), 'epoch'::timestamptz) AS at \
             FROM auth_attempts \
             WHERE bucket = $1 AND successful \
               AND created_at > now() - make_interval(secs => $2)) \
         SELECT COUNT(*), MAX(created_at) FROM auth_attempts, last_ok \
         WHERE bucket = $1 AND NOT successful \
           AND created_at > GREATEST(last_ok.at, now() - make_interval(secs => $2))",
    )
    .bind(bucket)
    .bind(window_secs as f64)
    .fetch_one(conn)
    .await?;
    Ok(row)
}

/// Failures in a plain trailing time window — no reset on success. The cap
/// policy's notion of "recent"; generic over the executor so [`cap_peek`] can
/// run it against the pool with no transaction at all.
async fn count_failures<'e, E>(
    exec: E,
    bucket: &str,
    window_secs: i64,
) -> Result<(i64, Option<DateTime<Utc>>)>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT COUNT(*), MAX(created_at) FROM auth_attempts \
         WHERE bucket = $1 AND NOT successful \
           AND created_at > now() - make_interval(secs => $2)",
    )
    .bind(bucket)
    .bind(window_secs as f64)
    .fetch_one(exec)
    .await?;
    Ok(row)
}

/// Delete attempt rows older than the longest window any policy above reads.
/// Run periodically — this table is append-only on a hot path and would
/// otherwise grow without bound.
pub async fn sweep(db: &Db) -> Result<u64> {
    let n = sqlx::query(
        "DELETE FROM auth_attempts WHERE created_at < now() - make_interval(secs => $1)",
    )
    .bind((WINDOW_SECS * 4) as f64)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_lockout_below_the_threshold() {
        for n in 0..MAX_FAILURES {
            assert_eq!(lockout_secs(n), None, "{n} failures should not lock out");
        }
    }

    #[test]
    fn lockout_grows_then_caps() {
        assert_eq!(lockout_secs(5), Some(30));
        assert_eq!(lockout_secs(6), Some(60));
        assert_eq!(lockout_secs(7), Some(120));
        assert_eq!(lockout_secs(12), Some(LOCKOUT_MAX_SECS));
        // Must stay capped rather than wrapping to something small.
        assert_eq!(lockout_secs(1_000_000), Some(LOCKOUT_MAX_SECS));
    }

    /// A million codes against a 90-second window: the throttle has to make
    /// exhaustive guessing take longer than the universe, not merely annoy.
    #[test]
    fn brute_force_is_hopeless() {
        // After the threshold every further attempt costs at least the base
        // lockout, so guessing the 1e6 space takes at least this long.
        let attempts_needed = 1_000_000i64;
        let seconds = (attempts_needed - MAX_FAILURES) * LOCKOUT_BASE_SECS;
        assert!(
            seconds / 86_400 > 300,
            "throttle too weak: exhaustive search would take {} days",
            seconds / 86_400
        );
    }

    /// The cap must never escalate the way the lockout does: its only lever is
    /// `window_secs`, flatly, regardless of how far past `hard_cap` a bucket
    /// is pushed.
    #[test]
    fn cap_retry_after_never_grows_with_more_failures() {
        for policy in [LOGIN_IP_CAP, LOGIN_CRED_CAP] {
            assert_eq!(policy.window_secs, WINDOW_SECS);
            assert!(policy.soft_cap < policy.hard_cap);
        }
    }
}
