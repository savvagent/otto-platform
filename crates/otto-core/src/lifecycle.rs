//! The lifecycle outbox: what resource servers must be told when identity
//! rows they hold references to go away.
//!
//! A resource server keeps domain rows keyed by org, team, and user ids, with
//! no foreign key back into this database (migration 0011 and
//! `docs/plans/2026-10-06-platform-cutover.md`, workstream 5). It cleans up
//! when it hears that an org was deleted, a team was deleted, or a member was
//! removed.
//!
//! [`enqueue`] is called from inside the transaction that performs the
//! mutation (`delete_org`, `delete_team`, `remove_member`), so the event and
//! the change commit or abort together. It writes one `lifecycle_events` row
//! and one `webhook_deliveries` row per enabled resource server that has a
//! webhook. Delivery is not this crate's concern — it knows nothing about HTTP.
//! The claim/mark functions below are the SQL a delivery task needs, and
//! `otto-platform-server` owns the task.

use chrono::{DateTime, Utc};
use otto_tenant::ids::{OrgId, TeamId, UserId};
use otto_tenant::Db;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::Result;

/// Delivery attempts before a row is given up on and marked failed. With
/// [`backoff_seconds`] this spans roughly a day.
pub const MAX_ATTEMPTS: i32 = 12;

/// How long a claimed row is invisible to other delivery tasks. Longer than
/// the HTTP timeout so a slow delivery is not picked up twice, short enough
/// that a replica that died mid-delivery is covered quickly.
pub const CLAIM_LEASE_SECONDS: i64 = 60;

/// Something that happened to identity data, to be told to resource servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    OrgDeleted { org: OrgId },
    TeamDeleted { org: OrgId, team: TeamId },
    MemberRemoved { org: OrgId, user: UserId },
}

impl LifecycleEvent {
    /// The wire name, also what `lifecycle_events.kind` stores.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::OrgDeleted { .. } => "org.deleted",
            Self::TeamDeleted { .. } => "team.deleted",
            Self::MemberRemoved { .. } => "member.removed",
        }
    }

    pub fn org(&self) -> OrgId {
        match *self {
            Self::OrgDeleted { org }
            | Self::TeamDeleted { org, .. }
            | Self::MemberRemoved { org, .. } => org,
        }
    }

    /// The event-specific fields of the webhook body.
    pub fn data(&self) -> serde_json::Value {
        match *self {
            Self::OrgDeleted { org } => serde_json::json!({ "org_id": org }),
            Self::TeamDeleted { org, team } => {
                serde_json::json!({ "org_id": org, "team_id": team })
            }
            Self::MemberRemoved { org, user } => {
                serde_json::json!({ "org_id": org, "user_id": user })
            }
        }
    }
}

/// Write an event and fan it out to every enabled resource server that has a
/// webhook. Takes a bare connection so it runs inside whichever transaction
/// (pinned or unpinned) made the change; the caller commits.
///
/// Returns the event id, which is what receivers dedupe on.
pub async fn enqueue(conn: &mut PgConnection, event: &LifecycleEvent) -> Result<Uuid> {
    // Minted here, not by the database with RETURNING: tenant-pinned callers
    // run as `otto_app`, which may insert into the outbox but (migration 0011)
    // may not read it, and RETURNING counts as a read.
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO lifecycle_events (id, kind, org_id, data) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(event.kind())
        .bind(event.org())
        .bind(event.data())
        .execute(&mut *conn)
        .await?;

    sqlx::query(
        "INSERT INTO webhook_deliveries (event_id, resource_uri) \
         SELECT $1, resource_uri FROM resource_servers \
         WHERE NOT disabled AND webhook_url IS NOT NULL",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;

    Ok(id)
}

/// Seconds to wait before retry number `attempts` (1 after the first
/// failure): 10 s doubling to a one-hour cap.
pub fn backoff_seconds(attempts: i32) -> i64 {
    let exp = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(0)
        .min(10);
    (10_i64 << exp).min(3600)
}

/// One delivery a task should attempt, with everything needed to make it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DueDelivery {
    pub event_id: Uuid,
    pub resource_uri: String,
    pub kind: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
    /// Attempts made before this one.
    pub attempts: i32,
    /// `None` if the resource server was disabled or lost its webhook after
    /// the event was queued; the caller records that as a failed attempt.
    pub webhook_url: Option<String>,
    pub secret_ciphertext: Option<Vec<u8>>,
    pub secret_nonce: Option<Vec<u8>>,
    pub disabled: bool,
}

/// Claim up to `limit` due deliveries for this task.
///
/// Claiming pushes `next_attempt_at` out by [`CLAIM_LEASE_SECONDS`] in the
/// same statement that selects the rows (`FOR UPDATE SKIP LOCKED`), so several
/// replicas can run a delivery task against one table without ever sending
/// the same row twice at once. A task that dies after claiming simply lets the
/// lease lapse and the row becomes due again.
pub async fn claim_due(db: &Db, limit: i64) -> Result<Vec<DueDelivery>> {
    let rows = sqlx::query_as(
        "WITH due AS ( \
           SELECT event_id, resource_uri FROM webhook_deliveries \
           WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now() \
           ORDER BY next_attempt_at \
           LIMIT $1 \
           FOR UPDATE SKIP LOCKED \
         ), claimed AS ( \
           UPDATE webhook_deliveries d \
              SET next_attempt_at = now() + make_interval(secs => $2) \
             FROM due \
            WHERE d.event_id = due.event_id AND d.resource_uri = due.resource_uri \
           RETURNING d.event_id, d.resource_uri, d.attempts \
         ) \
         SELECT c.event_id, c.resource_uri, e.kind, e.data, e.created_at, c.attempts, \
                r.webhook_url, \
                r.webhook_secret_ciphertext AS secret_ciphertext, \
                r.webhook_secret_nonce AS secret_nonce, \
                r.disabled \
           FROM claimed c \
           JOIN lifecycle_events e ON e.id = c.event_id \
           JOIN resource_servers r ON r.resource_uri = c.resource_uri \
          ORDER BY e.created_at",
    )
    .bind(limit)
    .bind(CLAIM_LEASE_SECONDS as f64)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Record a successful delivery.
pub async fn mark_delivered(
    db: &Db,
    event_id: Uuid,
    resource_uri: &str,
    status: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE webhook_deliveries \
            SET delivered_at = now(), attempts = attempts + 1, last_status = $3, last_error = NULL \
          WHERE event_id = $1 AND resource_uri = $2",
    )
    .bind(event_id)
    .bind(resource_uri)
    .bind(status)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Record a failed attempt and schedule the retry, or give up once
/// [`MAX_ATTEMPTS`] is spent. `attempts_before` is [`DueDelivery::attempts`].
/// Returns `true` if the row was given up on.
pub async fn mark_attempt_failed(
    db: &Db,
    delivery: &DueDelivery,
    status: Option<i32>,
    error: &str,
) -> Result<bool> {
    let attempts = delivery.attempts + 1;
    let gave_up = attempts >= MAX_ATTEMPTS;
    sqlx::query(
        "UPDATE webhook_deliveries \
            SET attempts = $3, \
                last_status = $4, \
                last_error = $5, \
                next_attempt_at = now() + make_interval(secs => $6), \
                failed_at = CASE WHEN $7 THEN now() END \
          WHERE event_id = $1 AND resource_uri = $2",
    )
    .bind(delivery.event_id)
    .bind(&delivery.resource_uri)
    .bind(attempts)
    .bind(status)
    .bind(error)
    .bind(backoff_seconds(attempts) as f64)
    .bind(gave_up)
    .execute(db.pool())
    .await?;
    Ok(gave_up)
}

/// Delete events whose every delivery finished (delivered or failed) more than
/// `keep_days` ago. Cascades to their delivery rows.
pub async fn sweep(db: &Db, keep_days: i32) -> Result<u64> {
    let n = sqlx::query(
        "DELETE FROM lifecycle_events e \
          WHERE e.created_at < now() - make_interval(days => $1) \
            AND NOT EXISTS ( \
              SELECT 1 FROM webhook_deliveries d \
               WHERE d.event_id = e.id AND d.delivered_at IS NULL AND d.failed_at IS NULL)",
    )
    .bind(keep_days)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_cap() {
        assert_eq!(backoff_seconds(1), 10);
        assert_eq!(backoff_seconds(2), 20);
        assert_eq!(backoff_seconds(6), 320);
        assert_eq!(backoff_seconds(9), 2560);
        assert_eq!(backoff_seconds(10), 3600);
        assert_eq!(backoff_seconds(50), 3600);
    }

    #[test]
    fn kinds_match_the_migration_check() {
        let (o, t, u) = (OrgId::new(), TeamId::new(), UserId::new());
        assert_eq!(LifecycleEvent::OrgDeleted { org: o }.kind(), "org.deleted");
        assert_eq!(
            LifecycleEvent::TeamDeleted { org: o, team: t }.kind(),
            "team.deleted"
        );
        assert_eq!(
            LifecycleEvent::MemberRemoved { org: o, user: u }.kind(),
            "member.removed"
        );
    }
}
