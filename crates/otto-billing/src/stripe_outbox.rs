//! Metered usage to Stripe meter events (savvagent/otto-platform#64, epic
//! #55): the outbox `stripe_meter_outbox` (migration 0023) and the SQL its
//! shipper needs.
//!
//! # Enqueue
//!
//! Usage ingest ([`crate::usage::UsageExt::ingest_usage_deferred`]) writes one
//! row for every accepted **metered** event of an org with a **live Stripe
//! subscription** (a Stripe customer and a subscription whose status is one of
//! [`crate::billing::LIVE_STATUSES`], as [`crate::billing::live_subscription`]
//! reads it). The insert is a data-modifying CTE of the event's own counter
//! statement, so it costs no round trip at all, for orgs with or without a
//! subscription, and commits or aborts with the usage it bills. It cannot fail
//! the event: every value it writes satisfies the table's checks by
//! construction (see [`enqueue_fields`]), it locks no row another ingest
//! needs, and a replayed identifier is `ON CONFLICT DO NOTHING`.
//!
//! **Usage of an org without a live subscription is not billed through
//! Stripe**, by design: a free org, or one that has not put a card on file
//! yet, accrues usage (and budgets) but nothing is queued for it, and nothing
//! is queued retroactively when it subscribes. Neither is an unmetered event,
//! which is free.
//!
//! # Shipping
//!
//! The server's shipper loop (`otto-platform-server`'s `stripe_shipper`, run
//! only when billing is enabled) [`claim_due`]s rows across every org, sends
//! each as one meter event ([`DueMeterEvent::meter_event`]) and records the
//! outcome with [`mark_sent`], [`mark_retry`] or [`mark_terminal`]. What to
//! do with a Stripe answer is [`verdict`]'s decision.
//!
//! **Exactly once.** Every parameter is fixed at enqueue, so a retry sends
//! the same event. Stripe dedupes meter events on `identifier`
//! (`<service>:<event_id>`) for at least 24 hours, so a retry of an event
//! Stripe already took (its answer lost) is dropped by Stripe. Retries
//! therefore stop at [`RETRY_WINDOW`] (12 h) after the first attempt, well
//! inside that 24 h, leaving room for the claim lease and clock skew: no retry
//! is ever sent once Stripe could have forgotten the identifier. A row still
//! failing then is **expired**, as is one whose event is older than Stripe
//! accepts ([`MAX_EVENT_AGE`], inside Stripe's 35 days).
//!
//! **Idempotency keys** ([`DueMeterEvent::idempotency_key`]) are derived from
//! the identifier and the attempt number. A send whose result was never
//! recorded (a crash, a lost lease) is retried under the same key, so Stripe
//! replays its first answer. A recorded failure moves to a new key, because
//! Stripe caches even a `500` under its key for 24 hours, longer than the
//! retry window; the identifier, not the key, is what keeps a new attempt
//! from counting twice.
//!
//! **Lost revenue is visible.** A `rejected` (terminal 4xx) or `expired` row
//! is kept, never retried and never swept, with its error in `last_error`;
//! the shipper logs it at error level and [`status_counts`] reports it.
//! `sent` rows are swept after [`KEEP_SENT_DAYS`].

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock, PoisonError};

use chrono::{DateTime, Duration, Utc};
use otto_tenant::{Db, Unpinned};
use uuid::Uuid;

use crate::billing::Result;
use crate::stripe::{meter_event_name, IdempotencyKey, MeterEvent, StripeError};
use crate::usage::Metered;

/// How long after its first attempt a row may still be retried. Well under
/// Stripe's (at least) 24 h identifier dedupe window, so every retry lands
/// while Stripe still remembers the identifier.
pub const RETRY_WINDOW: Duration = Duration::hours(12);

/// The oldest event the shipper sends. Stripe accepts meter events whose
/// timestamp is within the past 35 days; a day of margin covers clock skew and
/// the time a send takes.
pub const MAX_EVENT_AGE: Duration = Duration::days(34);

/// How long a claimed row is invisible to other shippers. The shipper's
/// slowest pass must fit inside it (asserted in `otto-platform-server`).
pub const CLAIM_LEASE_SECONDS: i64 = 600;

/// `sent` rows are kept this long (Stripe's own 35-day window), then swept.
pub const KEEP_SENT_DAYS: i32 = 35;

/// `last_error` is for a human; anything longer is cut.
const MAX_ERROR_LEN: usize = 500;

/// Where a row stands. Stored as `stripe_meter_outbox.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutboxStatus {
    /// Waiting to be sent.
    Pending,
    /// Stripe accepted it.
    Sent,
    /// Refused for good (a 4xx other than 429). Never retried.
    Rejected,
    /// Not sent in time. Never retried.
    Expired,
}

impl OutboxStatus {
    pub const ALL: [Self; 4] = [Self::Pending, Self::Sent, Self::Rejected, Self::Expired];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Whether the row's usage will never reach Stripe.
    pub fn is_lost(self) -> bool {
        matches!(self, Self::Rejected | Self::Expired)
    }
}

/// The meter-event identifier of an event: `<service>:<event_id>`. Event ids
/// are unique only per resource server, so the service is part of it. At most
/// 63 + 1 + 36 = 100 characters for a valid service slug.
///
/// ```
/// use otto_billing::stripe_outbox::identifier;
/// use uuid::Uuid;
///
/// let id = Uuid::nil();
/// assert_eq!(
///     identifier("otto-flags", id),
///     "otto-flags:00000000-0000-0000-0000-000000000000"
/// );
/// ```
pub fn identifier(service: &str, event_id: Uuid) -> String {
    format!("{service}:{}", event_id.hyphenated())
}

/// The meter keys this process has already reported as unshippable, so a
/// meter whose key has no Stripe event name logs once, not once per event.
static UNSHIPPABLE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// What ingest writes to the outbox for an event, as `(event_name,
/// identifier)`, or `None` when the event cannot be billed through Stripe:
/// unmetered, from a server with no service, or a meter whose key has no
/// Stripe event name (logged once per meter; `stripe sync` reports it too).
///
/// Both values satisfy the table's checks whenever this returns them: the
/// event name is 1 to 100 of `[a-z0-9_]` ([`meter_event_name`]), and a valid
/// service slug makes the identifier at most 100 characters.
pub(crate) fn enqueue_fields(
    service: Option<&str>,
    metered: Option<Metered<'_>>,
    event_id: Uuid,
) -> Option<(String, String)> {
    let (service, metered) = (service?, metered?);
    if !crate::budgets::is_service_slug(service) {
        return None;
    }
    let name = metered
        .meter
        .split_once('/')
        .filter(|(svc, _)| *svc == service)
        .ok_or(None)
        .and_then(|(svc, meter)| meter_event_name(svc, meter).map_err(Some));
    match name {
        Ok(name) => Some((name, identifier(service, event_id))),
        Err(e) => {
            let first = UNSHIPPABLE
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(metered.meter.to_owned());
            if first {
                let why = e.map_or_else(|| "not a <service>/<meter> key".into(), |e| e.to_string());
                tracing::error!(
                    meter = metered.meter,
                    error = %why,
                    "a metered event cannot be billed through Stripe; its usage is counted \
                     but not invoiced"
                );
            }
            None
        }
    }
}

/// One outbox row a shipper should send.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DueMeterEvent {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identifier: String,
    pub event_name: String,
    pub stripe_customer_id: String,
    pub value: i64,
    pub occurred_at: DateTime<Utc>,
    /// Recorded attempts before this one.
    pub attempts: i32,
    /// When the row was first claimed (this claim, for a first attempt).
    pub first_attempt_at: DateTime<Utc>,
    /// The database's clock at this claim.
    pub claimed_at: DateTime<Utc>,
}

impl DueMeterEvent {
    /// The meter event to send. The same for every attempt.
    pub fn meter_event(&self) -> MeterEvent {
        MeterEvent {
            event_name: self.event_name.clone(),
            stripe_customer_id: self.stripe_customer_id.clone(),
            value: self.value,
            identifier: self.identifier.clone(),
            timestamp: self.occurred_at,
        }
    }

    /// `otto-mev-<identifier>-<attempt>`: the same for a resend of an attempt
    /// whose result was never recorded, new for each recorded failure (see the
    /// module docs).
    pub fn idempotency_key(&self) -> Result<IdempotencyKey> {
        Ok(IdempotencyKey::new(format!(
            "otto-mev-{}-{}",
            self.identifier,
            self.attempts.saturating_add(1)
        ))?)
    }

    /// Why this row must not be sent at all, as of its claim: its event is
    /// older than Stripe accepts, or its retry window has closed (a row whose
    /// claims kept lapsing). `None` to send it.
    pub fn expired_before_send(&self) -> Option<String> {
        if self.occurred_at < self.claimed_at - MAX_EVENT_AGE {
            return Some(format!(
                "the event is older than {} days, and Stripe refuses meter events older \
                 than 35",
                MAX_EVENT_AGE.num_days()
            ));
        }
        if self.claimed_at > self.first_attempt_at + RETRY_WINDOW {
            return Some(format!(
                "not sent within {} hours of the first attempt",
                RETRY_WINDOW.num_hours()
            ));
        }
        None
    }
}

/// What to do with a row after one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Stripe accepted it.
    Sent,
    /// Try again after the backoff, inside the retry window.
    Retry(String),
    /// Stripe will never accept it: record it `rejected`.
    Reject(String),
}

/// What a send's result means for its row.
///
/// - 2xx: sent, even if the body could not be decoded (Stripe took it).
/// - 429 (rate or per-customer concurrency limit), 409 (a concurrent request
///   with the same key), 5xx, and no response at all: retry.
/// - 401 and 403: retry. They are about our API key, the same for every row,
///   and rejecting would throw away every queued event on the first try;
///   the shipper logs them at error level.
/// - `idempotency_error`: retry (the next attempt has a new key).
/// - Any other 4xx, and a request the client refused before sending: reject.
pub fn verdict(result: &std::result::Result<(), StripeError>) -> Verdict {
    let e = match result {
        Ok(()) | Err(StripeError::Decode(_)) => return Verdict::Sent,
        Err(e) => e,
    };
    let text = truncate(&e.to_string());
    match e {
        StripeError::Api(api) => match api.status {
            401 | 403 | 409 | 429 => Verdict::Retry(text),
            _ if api.kind == "idempotency_error" => Verdict::Retry(text),
            400..=499 => Verdict::Reject(text),
            _ => Verdict::Retry(text),
        },
        StripeError::Transport(_) => Verdict::Retry(text),
        StripeError::InvalidRequest(_) => Verdict::Reject(text),
        StripeError::Decode(_) => Verdict::Sent,
    }
}

/// Whether an error is about our Stripe credentials rather than the event.
pub fn is_credential_fault(e: &StripeError) -> bool {
    e.api().is_some_and(|a| matches!(a.status, 401 | 403))
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_ERROR_LEN {
        return s.to_owned();
    }
    let mut end = MAX_ERROR_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ------------------------------------------------------------------- SQL

/// An unpinned transaction opted in to the outbox's delivery policies
/// (migration 0023), which is what lets the shipper reach every org's rows
/// where the connecting role is subject to row-level security.
async fn delivery_tx(db: &Db) -> Result<Unpinned> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SELECT set_config('app.stripe_meter_delivery', 'on', true)")
        .execute(tx.conn())
        .await?;
    Ok(tx)
}

/// Claim up to `limit` due rows across every org, oldest due first.
///
/// The claim pushes `next_attempt_at` out by [`CLAIM_LEASE_SECONDS`] in the
/// statement that selects the rows (`FOR UPDATE SKIP LOCKED`), so several
/// machines can ship from one table without sending a row twice at once, and
/// a shipper that dies lets the lease lapse. It stamps `first_attempt_at` on
/// a row's first claim.
pub async fn claim_due(db: &Db, limit: i64) -> Result<Vec<DueMeterEvent>> {
    let mut tx = delivery_tx(db).await?;
    let rows = sqlx::query_as(
        "WITH due AS ( \
           SELECT id FROM stripe_meter_outbox \
            WHERE status = 'pending' AND next_attempt_at <= now() \
            ORDER BY next_attempt_at, created_at \
            LIMIT $1 \
            FOR UPDATE SKIP LOCKED \
         ) \
         UPDATE stripe_meter_outbox o \
            SET next_attempt_at = now() + make_interval(secs => $2), \
                first_attempt_at = COALESCE(o.first_attempt_at, now()) \
           FROM due \
          WHERE o.id = due.id \
         RETURNING o.id, o.org_id, o.identifier, o.event_name, o.stripe_customer_id, \
                   o.value, o.occurred_at, o.attempts, o.first_attempt_at, \
                   now() AS claimed_at",
    )
    .bind(limit)
    .bind(CLAIM_LEASE_SECONDS as f64)
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Record that Stripe accepted the row.
pub async fn mark_sent(db: &Db, row: &DueMeterEvent) -> Result<()> {
    let mut tx = delivery_tx(db).await?;
    sqlx::query(
        "UPDATE stripe_meter_outbox \
            SET status = 'sent', finished_at = now(), attempts = attempts + 1, \
                last_error = NULL \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(row.id)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record a retryable failure and schedule the next attempt after
/// [`crate::billing`]'s backoff (10 s doubling to an hour), or expire the row
/// when that attempt would fall outside its [`RETRY_WINDOW`] or past
/// [`MAX_EVENT_AGE`]. Returns the row's new status.
///
/// `error` is stored as given: the caller passes Stripe's error, which the
/// client has already scrubbed of the secret key.
pub async fn mark_retry(db: &Db, row: &DueMeterEvent, error: &str) -> Result<OutboxStatus> {
    let attempts = row.attempts.saturating_add(1);
    let backoff = otto_core::lifecycle::backoff_seconds(attempts);
    let mut tx = delivery_tx(db).await?;
    let status: Option<String> = sqlx::query_scalar(
        "WITH next AS ( \
           SELECT now() + make_interval(secs => $3) AS at \
         ) \
         UPDATE stripe_meter_outbox o \
            SET attempts = $2, \
                next_attempt_at = next.at, \
                status = CASE \
                  WHEN next.at > o.first_attempt_at + make_interval(secs => $4) \
                    OR next.at > o.occurred_at + make_interval(secs => $5) \
                  THEN 'expired' ELSE 'pending' END, \
                finished_at = CASE \
                  WHEN next.at > o.first_attempt_at + make_interval(secs => $4) \
                    OR next.at > o.occurred_at + make_interval(secs => $5) \
                  THEN now() END, \
                last_error = CASE \
                  WHEN next.at > o.first_attempt_at + make_interval(secs => $4) \
                    OR next.at > o.occurred_at + make_interval(secs => $5) \
                  THEN 'retry window closed; last error: ' || $6 ELSE $6 END \
           FROM next \
          WHERE o.id = $1 AND o.status = 'pending' \
         RETURNING o.status",
    )
    .bind(row.id)
    .bind(attempts)
    .bind(backoff as f64)
    .bind(RETRY_WINDOW.num_seconds() as f64)
    .bind(MAX_EVENT_AGE.num_seconds() as f64)
    .bind(error)
    .fetch_optional(tx.conn())
    .await?;
    tx.commit().await?;
    // No row: already finished by another shipper whose lease outlived ours.
    Ok(status
        .as_deref()
        .and_then(OutboxStatus::parse)
        .unwrap_or(OutboxStatus::Pending))
}

/// Record the row as never to be sent: `status` is [`OutboxStatus::Rejected`]
/// or [`OutboxStatus::Expired`]; anything else is treated as rejected.
pub async fn mark_terminal(
    db: &Db,
    row: &DueMeterEvent,
    status: OutboxStatus,
    error: &str,
    attempted: bool,
) -> Result<()> {
    let status = if status == OutboxStatus::Expired {
        status
    } else {
        OutboxStatus::Rejected
    };
    let mut tx = delivery_tx(db).await?;
    sqlx::query(
        "UPDATE stripe_meter_outbox \
            SET status = $2, finished_at = now(), last_error = $3, \
                attempts = attempts + $4 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(row.id)
    .bind(status.as_str())
    .bind(truncate(error))
    .bind(i32::from(attempted))
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Delete `sent` rows finished more than `keep_days` ago. Pending rows are
/// waiting and lost (`rejected`, `expired`) rows are the record of revenue
/// that never reached Stripe; neither is ever swept.
pub async fn sweep(db: &Db, keep_days: i32) -> Result<u64> {
    let mut tx = delivery_tx(db).await?;
    let n = sqlx::query(
        "DELETE FROM stripe_meter_outbox \
          WHERE status = 'sent' AND finished_at < now() - make_interval(days => $1)",
    )
    .bind(keep_days)
    .execute(tx.conn())
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(n)
}

/// How many rows are in each status, across every org, every status listed.
pub async fn status_counts(db: &Db) -> Result<Vec<(OutboxStatus, i64)>> {
    let mut tx = delivery_tx(db).await?;
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM stripe_meter_outbox GROUP BY status")
            .fetch_all(tx.conn())
            .await?;
    tx.commit().await?;
    Ok(OutboxStatus::ALL
        .into_iter()
        .map(|s| {
            let n = rows
                .iter()
                .find(|(name, _)| name == s.as_str())
                .map_or(0, |(_, n)| *n);
            (s, n)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::ApiError;

    fn api(status: u16, kind: &str) -> std::result::Result<(), StripeError> {
        Err(StripeError::Api(ApiError {
            status,
            kind: kind.into(),
            code: None,
            message: "m".into(),
            param: None,
        }))
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&Ok(())), Verdict::Sent);
        assert_eq!(
            verdict(&Err(StripeError::Decode("x".into()))),
            Verdict::Sent
        );
        for retry in [429, 409, 401, 403, 500, 502, 503] {
            assert!(
                matches!(verdict(&api(retry, "api_error")), Verdict::Retry(_)),
                "{retry}"
            );
        }
        assert!(matches!(
            verdict(&api(400, "idempotency_error")),
            Verdict::Retry(_)
        ));
        for reject in [400, 402, 404, 422] {
            assert!(
                matches!(
                    verdict(&api(reject, "invalid_request_error")),
                    Verdict::Reject(_)
                ),
                "{reject}"
            );
        }
        assert!(matches!(
            verdict(&Err(StripeError::InvalidRequest("x".into()))),
            Verdict::Reject(_)
        ));
        assert!(is_credential_fault(&api(401, "x").unwrap_err()));
        assert!(!is_credential_fault(&api(400, "x").unwrap_err()));
    }

    #[test]
    fn the_window_is_well_inside_stripes_dedupe_and_age_limits() {
        // Stripe dedupes identifiers for at least 24 h, and refuses
        // timestamps older than 35 days. Leave room for the claim lease.
        assert!(RETRY_WINDOW + Duration::seconds(CLAIM_LEASE_SECONDS) <= Duration::hours(13));
        assert!(RETRY_WINDOW * 2 <= Duration::hours(24));
        assert!(MAX_EVENT_AGE < Duration::days(35));
        assert!(i64::from(KEEP_SENT_DAYS) >= 35);
    }

    #[test]
    fn identifiers_fit_stripes_limit() {
        let longest = "a".repeat(63);
        assert_eq!(identifier(&longest, Uuid::new_v4()).len(), 100);
    }

    #[test]
    fn enqueue_fields_need_a_service_a_meter_and_a_name() {
        let id = Uuid::new_v4();
        let m = |meter| Some(Metered { meter, quantity: 3 });
        assert_eq!(
            enqueue_fields(Some("otto-flags"), m("otto-flags/evaluations"), id),
            Some((
                "otto_flags__evaluations".to_owned(),
                format!("otto-flags:{id}")
            ))
        );
        assert_eq!(enqueue_fields(Some("otto-flags"), None, id), None);
        assert_eq!(enqueue_fields(None, m("otto-flags/evaluations"), id), None);
        // Another service's key, or a key with no Stripe name.
        assert_eq!(
            enqueue_fields(Some("otto-cxp"), m("otto-flags/evaluations"), id),
            None
        );
        let long = format!("svc/{}", "m".repeat(99));
        assert_eq!(enqueue_fields(Some("svc"), m(&long), id), None);
    }

    fn due(attempts: i32) -> DueMeterEvent {
        let now = Utc::now();
        DueMeterEvent {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            identifier: "svc:1".into(),
            event_name: "svc__calls".into(),
            stripe_customer_id: "cus_1".into(),
            value: 3,
            occurred_at: now,
            attempts,
            first_attempt_at: now,
            claimed_at: now,
        }
    }

    #[test]
    fn keys_follow_the_attempt_and_the_event_never_changes() {
        let a = due(0);
        let b = due(1);
        assert_eq!(a.idempotency_key().unwrap().as_str(), "otto-mev-svc:1-1");
        assert_eq!(b.idempotency_key().unwrap().as_str(), "otto-mev-svc:1-2");
        let e = a.meter_event();
        assert_eq!(
            (e.identifier.as_str(), e.value, e.timestamp),
            ("svc:1", 3, a.occurred_at)
        );
    }

    #[test]
    fn too_old_or_out_of_window_rows_are_not_sent() {
        let ok = due(0);
        assert_eq!(ok.expired_before_send(), None);
        let mut old = due(0);
        old.occurred_at = old.claimed_at - Duration::days(40);
        assert!(old.expired_before_send().is_some());
        let mut late = due(3);
        late.first_attempt_at = late.claimed_at - Duration::hours(13);
        assert!(late.expired_before_send().is_some());
    }

    #[test]
    fn statuses_round_trip() {
        for s in OutboxStatus::ALL {
            assert_eq!(OutboxStatus::parse(s.as_str()), Some(s));
        }
        assert!(OutboxStatus::Rejected.is_lost() && OutboxStatus::Expired.is_lost());
        assert!(!OutboxStatus::Sent.is_lost());
    }
}
