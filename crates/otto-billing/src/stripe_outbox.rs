//! Metered usage to Stripe meter events (savvagent/otto-platform#64, epic
//! #55): the outbox `stripe_meter_outbox` (migration 0023) and the SQL its
//! shipper needs.
//!
//! # Enqueue: aggregated per hour
//!
//! Usage ingest ([`crate::usage::UsageExt::ingest_usage_deferred`]) adds every
//! accepted **metered** event of an org with a **live Stripe subscription** (a
//! Stripe customer and a subscription whose status is one of
//! [`crate::billing::LIVE_STATUSES`], as [`crate::billing::live_subscription`]
//! reads it) to an **open row**: the one pending row for the org, the meter's
//! Stripe event name, the customer and the UTC hour holding the instant the
//! event is billed at ([`crate::period::billed_at`],
//! [`crate::period::hour_bucket`]). The first event of the hour creates the
//! row; every later one adds its quantity (`INSERT … ON CONFLICT … DO UPDATE
//! SET value = value + EXCLUDED.value` against the partial unique index
//! `stripe_meter_outbox_open_idx`, whose predicate is [`OPEN_ROW`]). So a busy
//! org and meter costs one row, and one Stripe call, per hour, not per event.
//!
//! - **Identifier.** Each row mints its own (`agg:<uuid>`) when it is created.
//!   It never derives from an event, so replays are kept out upstream: ingest's
//!   ledger claim refuses an event already counted before this statement runs.
//! - **Timestamp.** The meter event's timestamp is the row's `bucket_start`,
//!   the start of the hour, which is in the same UTC month as every event the
//!   row carries, never in the future, and at most an hour older than they
//!   are.
//! - **A row closes at its first claim.** A row is open only while it is
//!   pending, has never been claimed (`attempts = 0 AND sending_since IS
//!   NULL`) and is not full ([`OPEN_ROW_MAX_VALUE`]); the claim sets
//!   `sending_since`, which takes it out of the index for good. From then on
//!   its value never changes, so every retry sends what the first attempt
//!   sent; an event counted after the claim opens a new row (with a new
//!   identifier) for the same hour.
//! - **Due at the end of its hour.** A row is first due when its hour has
//!   ended (`next_attempt_at = bucket_start + 1 hour`), which is what lets it
//!   collect the hour's events. An event billed in an hour that has already
//!   ended (a late one) lands in a row that is due at once.
//! - **Bounded values.** A row's value is at most [`MAX_OUTBOX_VALUE`]
//!   (10^15, exact as a JSON number). A row past [`OPEN_ROW_MAX_VALUE`] (half
//!   of it) takes no more additions, and one addition is at most the other
//!   half ([`MAX_ADDITION`]; an event's quantity is at most
//!   [`crate::usage::MAX_METER_QUANTITY`], far below it), so a sum can never
//!   overflow the table's check, and ingest can never fail on it.
//!
//! The insert is a data-modifying CTE of the event's own counter statement,
//! so it costs no round trip at all, for orgs with or without a subscription,
//! and commits or aborts with the usage it bills. It cannot fail the event:
//! every value it writes satisfies the table's checks by construction (see
//! [`enqueue_event_name`]).
//!
//! **Not queued, by design:**
//!
//! - usage of an org without a live subscription (a free org, or one with no
//!   card yet): it accrues usage and budgets, but nothing is queued for it
//!   until [`backfill_period`] is called when it subscribes;
//! - an unmetered event, which is free;
//! - an event whose hour is already older than [`MAX_EVENT_AGE`] when it is
//!   ingested. Ingest re-dates every event of a closed period to the moment
//!   it arrives ([`crate::period`]), so this cannot happen to an event ingest
//!   accepts; it is kept as a guard.
//!
//! # Shipping
//!
//! The server's shipper loop (`otto-platform-server`'s `stripe_shipper`, run
//! only when billing is enabled) [`claim_due`]s rows across every org, sends
//! each as one meter event ([`DueMeterEvent::meter_event`]) and records the
//! outcome with [`mark_sent`], [`mark_retry`] or [`mark_terminal`]. What to
//! do with a Stripe answer is [`verdict`]'s decision.
//!
//! **Only meters Stripe knows.** A row is claimed only once its event name
//! has a Stripe billing meter (`stripe_meters`, written by `stripe sync`), so
//! a meter declared since the last sync never has its events sent to a meter
//! that does not exist yet (Stripe would accept them and drop them
//! asynchronously). Such rows wait (and stay open), pushed back
//! [`UNSYNCED_RECHECK`] at a time ([`defer_unsynced`], at most
//! [`DEFER_BATCH`] rows a call) so they do not head the due index; their
//! retry window has not started, and they still expire by age
//! ([`expire_stale`]).
//!
//! **Fenced writes.** A claim's `sending_since` is its token: a shipper
//! records any outcome (sent, retry, terminal) only while the row still
//! carries the token of its own claim, so a shipper whose lease lapsed cannot
//! overwrite a newer claim's state (see [`claim_due`]). A row expired after an
//! attempt Stripe may have received says so in `last_error`
//! ([`MAY_HAVE_BEEN_DELIVERED`]).
//!
//! **`sent` means accepted for processing.** Stripe validates meter events
//! asynchronously (an unknown customer, an archived meter) and reports
//! failures only as `v1.billing.meter.error_report_triggered` events, which
//! nothing here reads yet.
//!
//! **Exactly once.** Every parameter is fixed by the first claim, so a retry
//! sends the same event. Stripe dedupes meter events on `identifier` for at
//! least 24 hours, so a retry of an event Stripe already took (its answer
//! lost) is dropped by Stripe; if Stripe answers such a retry with a
//! duplicate-identifier error instead, that too counts as sent
//! ([`is_duplicate_identifier`]). Retries therefore stop [`RETRY_WINDOW`]
//! (12 h) after the first attempt Stripe **may** have received, well inside
//! that 24 h, leaving room for the claim lease and clock skew: no retry is
//! sent once Stripe could have forgotten the identifier. A row still failing
//! then is **expired**, as is one whose hour is older than Stripe accepts
//! ([`MAX_EVENT_AGE`], inside Stripe's 35 days).
//!
//! **The window starts only when Stripe may have the event.** An ambiguous
//! outcome (a timeout, a transport error, a 5xx, a 409, or an attempt whose
//! result was never recorded because its shipper died) starts it. A definite
//! "not received" (401/403: our key; 429: throttled before processing; a
//! request the client refused before sending) does not, so a long credential
//! outage or throttling streak is bounded only by the row's age, and is
//! fixed in time without losing revenue. The claim records when a send
//! started (`sending_since`); recording any result clears it, so a claim that
//! finds it still set knows the previous attempt's answer was lost.
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
//! the shipper logs it at error level and [`outbox_summary`] reports it.
//! `sent` rows are swept after [`KEEP_SENT_DAYS`], [`SWEEP_BATCH`] at a time.
//! Deleting an org deletes its rows, shipped or not.
//!
//! # Invoicing
//!
//! [`has_pending_before`] tells Stripe invoicing whether an org still has
//! usage for a period on its way to Stripe; [`backfill_period`] queues the
//! usage an org accrued before its subscription went live.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock, PoisonError};

use chrono::{DateTime, Duration, Utc};
use otto_tenant::ids::OrgId;
use otto_tenant::{Db, Tx, Unpinned};
use uuid::Uuid;

use crate::billing::{Error, Result, LIVE_STATUSES};
use crate::period::{self, Month};
use crate::stripe::{meter_event_name, IdempotencyKey, MeterEvent, StripeError};
use crate::usage::Metered;

/// How long after the first attempt Stripe may have received a row may still
/// be retried. Well under Stripe's (at least) 24 h identifier dedupe window,
/// so every retry lands while Stripe still remembers the identifier.
pub const RETRY_WINDOW: Duration = Duration::hours(12);

/// The oldest hour the shipper sends, or ingest queues. Stripe accepts meter
/// events whose timestamp is within the past 35 days; a day of margin covers
/// clock skew and the time a send takes.
pub const MAX_EVENT_AGE: Duration = Duration::days(34);

/// How long a claimed row is invisible to other shippers. The shipper's
/// slowest pass must fit inside it (asserted in `otto-platform-server`).
pub const CLAIM_LEASE_SECONDS: i64 = 600;

/// `sent` rows are kept this long (Stripe's own 35-day window), then swept.
pub const KEEP_SENT_DAYS: i32 = 35;

/// The most rows one [`sweep`] statement deletes; it repeats until done.
pub const SWEEP_BATCH: i64 = 5_000;

/// The most rows one [`defer_unsynced`] call pushes back.
pub const DEFER_BATCH: i64 = 1_000;

/// The largest value one row (one meter event) carries: 10^15, the
/// `stripe_meter_outbox_value_range` check of migration 0023. Stripe
/// documents no upper bound for a meter event's value; this one keeps every
/// value exact as a JSON number (below 2^53), and is far above what an hour
/// of real usage reaches.
pub const MAX_OUTBOX_VALUE: i64 = 1_000_000_000_000_000;

/// A row whose value is past this takes no more additions (it leaves
/// `stripe_meter_outbox_open_idx`), and the next addition opens a new row.
pub const OPEN_ROW_MAX_VALUE: i64 = MAX_OUTBOX_VALUE / 2;

/// The largest single addition to a row. An open row plus one addition never
/// exceeds [`MAX_OUTBOX_VALUE`].
pub const MAX_ADDITION: i64 = MAX_OUTBOX_VALUE - OPEN_ROW_MAX_VALUE;

/// The predicate of `stripe_meter_outbox_open_idx` (migration 0023), which
/// every `ON CONFLICT` adding to an open row must repeat for Postgres to
/// infer that index.
pub(crate) const OPEN_ROW: &str = "status = 'pending' AND attempts = 0 AND sending_since IS NULL \
                                   AND value <= 500000000000000";

/// The conflict target and action that add a new row's value to the open row
/// for its key, if there is one.
pub(crate) fn add_to_open_row() -> String {
    format!(
        "ON CONFLICT (org_id, event_name, stripe_customer_id, bucket_start) WHERE {OPEN_ROW} \
         DO UPDATE SET value = stripe_meter_outbox.value + EXCLUDED.value"
    )
}

/// `last_error` is for a human; anything longer is cut.
const MAX_ERROR_LEN: usize = 500;

/// Where a row stands. Stored as `stripe_meter_outbox.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutboxStatus {
    /// Waiting to be sent.
    Pending,
    /// Stripe accepted it for processing.
    Sent,
    /// Refused for good (a 4xx other than 401, 403, 409 and 429). Never
    /// retried.
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

/// The meter keys this process has already reported as unshippable, so a
/// meter whose key has no Stripe event name logs once, not once per event.
static UNSHIPPABLE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// The Stripe event name ingest queues an event under, for an event billed in
/// the hour starting `bucket` and ingested at `now`, or `None` when the event
/// cannot be billed through Stripe: unmetered, from a server with no
/// service, an hour already older than [`MAX_EVENT_AGE`], or a meter whose
/// key has no Stripe event name (logged once per meter; `stripe sync`
/// reports it too).
///
/// The name satisfies the table's check whenever this returns it: 1 to 100
/// of `[a-z0-9_]` ([`meter_event_name`]).
pub(crate) fn enqueue_event_name(
    service: Option<&str>,
    metered: Option<Metered<'_>>,
    bucket: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<String> {
    let (service, metered) = (service?, metered?);
    if !crate::budgets::is_service_slug(service) || bucket < now - MAX_EVENT_AGE {
        return None;
    }
    event_name_of(metered.meter, Some(service))
}

/// The Stripe event name of meter key `meter` (`<service>/<meter>`), when it
/// has one and, with `service`, belongs to it. Logged once per meter when
/// it has none.
fn event_name_of(meter: &str, service: Option<&str>) -> Option<String> {
    let name = meter
        .split_once('/')
        .filter(|(svc, _)| service.is_none_or(|s| s == *svc))
        .ok_or(None)
        .and_then(|(svc, m)| meter_event_name(svc, m).map_err(Some));
    match name {
        Ok(name) => Some(name),
        Err(e) => {
            let first = UNSHIPPABLE
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(meter.to_owned());
            if first {
                let why = e.map_or_else(|| "not a <service>/<meter> key".into(), |e| e.to_string());
                tracing::error!(
                    meter,
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
    /// The sum of the quantities the row collected.
    pub value: i64,
    /// The start of the UTC hour the row's usage was billed in: the meter
    /// event's timestamp.
    pub bucket_start: DateTime<Utc>,
    /// Recorded attempts before this one.
    pub attempts: i32,
    /// When the first attempt Stripe may have received started, if any:
    /// the start of the retry window.
    pub window_started_at: Option<DateTime<Utc>>,
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
            timestamp: self.bucket_start,
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

    /// Why this row must not be sent at all, as of its claim: its hour is
    /// older than Stripe accepts, or its retry window has closed (a row whose
    /// claims kept lapsing). `None` to send it.
    pub fn expired_before_send(&self) -> Option<String> {
        let why = if self.bucket_start < self.claimed_at - MAX_EVENT_AGE {
            too_old()
        } else if self
            .window_started_at
            .is_some_and(|start| self.claimed_at > start + RETRY_WINDOW)
        {
            format!(
                "not sent within {} hours of the first attempt Stripe may have received",
                RETRY_WINDOW.num_hours()
            )
        } else {
            return None;
        };
        Some(match self.window_started_at {
            Some(_) => format!("{why}{MAY_HAVE_BEEN_DELIVERED}"),
            None => why,
        })
    }
}

/// Appended to the error of a row expired after an attempt Stripe may have
/// received: its usage may be on the invoice after all.
pub const MAY_HAVE_BEEN_DELIVERED: &str =
    " (an earlier attempt may have been delivered: check Stripe before re-billing)";

fn too_old() -> String {
    format!(
        "the usage is older than {} days, and Stripe refuses meter events older than 35",
        MAX_EVENT_AGE.num_days()
    )
}

/// What to do with a row after one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Stripe accepted it, or already had it.
    Sent,
    /// Try again after the backoff. `maybe_received` is whether Stripe may
    /// have processed this attempt, which starts the retry window.
    Retry { error: String, maybe_received: bool },
    /// Stripe will never accept it: record it `rejected`.
    Reject(String),
}

impl Verdict {
    fn retry(error: String, maybe_received: bool) -> Self {
        Self::Retry {
            error,
            maybe_received,
        }
    }
}

/// What a send's result means for its row.
///
/// - 2xx: sent, even if the body could not be decoded (Stripe took it).
/// - A duplicate-identifier error ([`is_duplicate_identifier`]): sent, since
///   an earlier attempt reached Stripe.
/// - 429 (rate or per-customer concurrency limit), 401 and 403 (our API key,
///   the same for every row; rejecting would discard every queued event):
///   retry; Stripe did not process it.
/// - 409 (a concurrent request with the same key), `idempotency_error`, 5xx,
///   and no response at all: retry; Stripe may have processed it.
/// - Any other 4xx, and a request the client refused before sending: reject.
pub fn verdict(result: &std::result::Result<(), StripeError>) -> Verdict {
    let e = match result {
        Ok(()) | Err(StripeError::Decode(_)) => return Verdict::Sent,
        Err(e) => e,
    };
    if is_duplicate_identifier(e) {
        return Verdict::Sent;
    }
    let text = truncate(&e.to_string());
    match e {
        StripeError::Api(api) => match api.status {
            401 | 403 | 429 => Verdict::retry(text, false),
            409 => Verdict::retry(text, true),
            _ if api.kind == "idempotency_error" => Verdict::retry(text, true),
            400..=499 => Verdict::Reject(text),
            _ => Verdict::retry(text, true),
        },
        StripeError::Transport(_) => Verdict::retry(text, true),
        StripeError::InvalidRequest(_) => Verdict::Reject(text),
        StripeError::Decode(_) => Verdict::Sent,
    }
}

/// Whether Stripe refused a meter event because its identifier was already
/// used, which means an earlier attempt of the same row reached Stripe: code
/// `resource_already_exists`, or a 400 whose message says the identifier
/// already exists or is a duplicate.
pub fn is_duplicate_identifier(e: &StripeError) -> bool {
    let Some(api) = e.api() else {
        return false;
    };
    if api.status != 400 {
        return false;
    }
    if api.code.as_deref() == Some("resource_already_exists") {
        return true;
    }
    let message = api.message.to_ascii_lowercase();
    message.contains("identifier") && (message.contains("already") || message.contains("duplicate"))
}

/// Whether an error is about our Stripe credentials rather than the event.
pub fn is_credential_fault(e: &StripeError) -> bool {
    e.api().is_some_and(|a| matches!(a.status, 401 | 403))
}

/// Whether Stripe throttled the request (429).
pub fn is_throttled(e: &StripeError) -> bool {
    e.api().is_some_and(|a| a.status == 429)
}

/// `s`, cut to at most [`MAX_ERROR_LEN`] bytes on a character boundary.
pub fn truncate(s: &str) -> String {
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

const DUE_COLS: &str = "o.id, o.org_id, o.identifier, o.event_name, o.stripe_customer_id, \
                        o.value, o.bucket_start, o.attempts, o.window_started_at, \
                        now() AS claimed_at";

/// Claim up to `limit` due rows across every org, oldest due first, whose
/// meter Stripe knows (`stripe_meters`).
///
/// The claim pushes `next_attempt_at` out by [`CLAIM_LEASE_SECONDS`] in the
/// statement that selects the rows (`FOR UPDATE SKIP LOCKED`), so several
/// machines can ship from one table without sending a row twice at once, and
/// a shipper that dies lets the lease lapse. It sets `sending_since`, which
/// also closes the row to further additions (see the module docs); a row
/// claimed with it still set had its previous answer lost, which starts its
/// retry window from that earlier send. A row an ingest is adding to right
/// now is locked, so it is skipped until that ingest commits.
///
/// `sending_since` is also the claim's **fence**: it equals the returned
/// [`DueMeterEvent::claimed_at`], and [`mark_sent`], [`mark_retry`] and
/// [`mark_terminal`] write only while it still does. A shipper whose lease
/// lapsed and was claimed again can therefore never record over the new claim
/// (and clear the evidence that the new claim's send may be in flight).
///
/// **Cost.** It walks `stripe_meter_outbox_due_idx` (pending rows by
/// `next_attempt_at`) in order and stops after `limit` claimable rows,
/// probing `stripe_meters` (its unique `event_name`) per row, however large
/// the due backlog (a Stripe outage) grows. The meter check is a correlated
/// subquery rather than `EXISTS` on purpose: as a semi-join the planner joins
/// every due row to the (tiny) `stripe_meters` first and sorts them all
/// (measured under `otto_app`'s row-level security at 300k due rows: 330 ms
/// and a spill to disk, against an index walk of the first rows). The
/// delivery policies' quals are a per-row filter that does not block the
/// ordered index scan, so no BYPASSRLS or SECURITY DEFINER route is needed.
/// Due rows whose meter is unsynced are pushed out of its way by
/// [`defer_unsynced`].
pub async fn claim_due(db: &Db, limit: i64) -> Result<Vec<DueMeterEvent>> {
    let mut tx = delivery_tx(db).await?;
    let rows = sqlx::query_as(&format!(
        "WITH due AS ( \
           SELECT id FROM stripe_meter_outbox d \
            WHERE d.status = 'pending' AND d.next_attempt_at <= now() \
              AND (SELECT true FROM stripe_meters m WHERE m.event_name = d.event_name) \
            ORDER BY d.next_attempt_at \
            LIMIT $1 \
            FOR UPDATE SKIP LOCKED \
         ) \
         UPDATE stripe_meter_outbox o \
            SET next_attempt_at = now() + make_interval(secs => $2), \
                window_started_at = COALESCE(o.window_started_at, o.sending_since), \
                sending_since = now() \
           FROM due \
          WHERE o.id = due.id \
         RETURNING {DUE_COLS}"
    ))
    .bind(limit)
    .bind(CLAIM_LEASE_SECONDS as f64)
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Record that Stripe accepted the row. Returns whether it was recorded:
/// `false` when this claim no longer holds the row (fenced out, see
/// [`claim_due`]). The newer claim then sends the same identifier, which
/// Stripe drops as a duplicate and the newer claim records as sent, so a
/// fenced-out `sent` loses nothing.
pub async fn mark_sent(db: &Db, row: &DueMeterEvent) -> Result<bool> {
    let mut tx = delivery_tx(db).await?;
    let written = sqlx::query(
        "UPDATE stripe_meter_outbox \
            SET status = 'sent', finished_at = now(), attempts = attempts + 1, \
                sending_since = NULL, last_error = NULL \
          WHERE id = $1 AND status = 'pending' \
            AND sending_since IS NOT DISTINCT FROM $2",
    )
    .bind(row.id)
    .bind(row.claimed_at)
    .execute(tx.conn())
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(written)
}

/// Record a retryable failure and schedule the next attempt after the
/// backoff (10 s doubling to an hour), or expire the row when that attempt
/// would fall outside its [`RETRY_WINDOW`] or past [`MAX_EVENT_AGE`]. With
/// `maybe_received`, this attempt starts the window if nothing has yet.
/// Returns the row's new status, or `None` when this claim no longer holds
/// the row (fenced out; nothing was written).
///
/// `error` is Stripe's error, already scrubbed of the secret key by the
/// client; it is cut to a readable length here.
pub async fn mark_retry(
    db: &Db,
    row: &DueMeterEvent,
    error: &str,
    maybe_received: bool,
) -> Result<Option<OutboxStatus>> {
    let attempts = row.attempts.saturating_add(1);
    let backoff = otto_core::lifecycle::backoff_seconds(attempts);
    let mut tx = delivery_tx(db).await?;
    let status: Option<String> = sqlx::query_scalar(
        "WITH cur AS ( \
           SELECT id, bucket_start, now() + make_interval(secs => $3) AS next_at, \
                  COALESCE(window_started_at, \
                           CASE WHEN $7 THEN COALESCE(sending_since, now()) END) AS win \
           FROM stripe_meter_outbox \
           WHERE id = $1 AND status = 'pending' \
             AND sending_since IS NOT DISTINCT FROM $8 \
         ), calc AS ( \
           SELECT id, next_at, win, \
                  (next_at > win + make_interval(secs => $4)) IS TRUE \
                    OR next_at > bucket_start + make_interval(secs => $5) AS expire \
           FROM cur \
         ) \
         UPDATE stripe_meter_outbox o \
            SET attempts = $2, \
                next_attempt_at = calc.next_at, \
                window_started_at = calc.win, \
                sending_since = NULL, \
                status = CASE WHEN calc.expire THEN 'expired' ELSE 'pending' END, \
                finished_at = CASE WHEN calc.expire THEN now() END, \
                last_error = CASE WHEN calc.expire \
                  THEN 'retry window closed; last error: ' || $6 \
                       || CASE WHEN calc.win IS NOT NULL THEN $9 ELSE '' END \
                  ELSE $6 END \
           FROM calc \
          WHERE o.id = calc.id \
         RETURNING o.status",
    )
    .bind(row.id)
    .bind(attempts)
    .bind(backoff as f64)
    .bind(RETRY_WINDOW.num_seconds() as f64)
    .bind(MAX_EVENT_AGE.num_seconds() as f64)
    .bind(truncate(error))
    .bind(maybe_received)
    .bind(row.claimed_at)
    .bind(MAY_HAVE_BEEN_DELIVERED)
    .fetch_optional(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(status.as_deref().and_then(OutboxStatus::parse))
}

/// Record the row as never to be sent: `status` is [`OutboxStatus::Rejected`]
/// or [`OutboxStatus::Expired`]; anything else is treated as rejected.
/// Returns whether it was recorded: `false` when this claim no longer holds
/// the row (fenced out, see [`claim_due`]).
pub async fn mark_terminal(
    db: &Db,
    row: &DueMeterEvent,
    status: OutboxStatus,
    error: &str,
    attempted: bool,
) -> Result<bool> {
    let status = if status == OutboxStatus::Expired {
        status
    } else {
        OutboxStatus::Rejected
    };
    let mut tx = delivery_tx(db).await?;
    let written = sqlx::query(
        "UPDATE stripe_meter_outbox \
            SET status = $2, finished_at = now(), last_error = $3, sending_since = NULL, \
                attempts = attempts + $4 \
          WHERE id = $1 AND status = 'pending' \
            AND sending_since IS NOT DISTINCT FROM $5",
    )
    .bind(row.id)
    .bind(status.as_str())
    .bind(truncate(error))
    .bind(i32::from(attempted))
    .bind(row.claimed_at)
    .execute(tx.conn())
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(written)
}

/// Expire every pending row whose hour has grown older than [`MAX_EVENT_AGE`]
/// without being claimed (its meter never synced, say, or billing disabled),
/// and return them, for the shipper to report as lost. Rows under a live
/// claim are left to their shipper.
pub async fn expire_stale(db: &Db) -> Result<Vec<DueMeterEvent>> {
    let mut tx = delivery_tx(db).await?;
    let rows = sqlx::query_as(&format!(
        "UPDATE stripe_meter_outbox o \
            SET status = 'expired', finished_at = now(), sending_since = NULL, \
                last_error = $2 || CASE WHEN o.window_started_at IS NOT NULL \
                                        OR o.sending_since IS NOT NULL \
                                   THEN $3 ELSE '' END \
          WHERE o.status = 'pending' \
            AND (o.sending_since IS NULL OR o.next_attempt_at <= now()) \
            AND o.bucket_start < now() - make_interval(secs => $1) \
         RETURNING {DUE_COLS}"
    ))
    .bind(MAX_EVENT_AGE.num_seconds() as f64)
    .bind(format!("{} before it could be sent", too_old()))
    .bind(MAY_HAVE_BEEN_DELIVERED)
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// How long rows whose meter Stripe does not know yet wait before they are
/// looked at again, so they do not sit at the head of the due index.
pub const UNSYNCED_RECHECK: Duration = Duration::minutes(5);

/// Push back up to [`DEFER_BATCH`] due pending rows whose meter Stripe does
/// not know yet (`stripe sync` has not made it) by [`UNSYNCED_RECHECK`], and
/// return how many there were and how long the oldest of them has been
/// queued. A row under a live claim is not due, so it is not touched; a row
/// an ingest is adding to is skipped (`SKIP LOCKED`).
///
/// The batch bounds the statement however large a backlog of unsynced rows
/// grows (an ordered walk of `stripe_meter_outbox_due_idx`, as in
/// [`claim_due`]); the shipper calls this every minute, which is more than
/// enough to keep them behind the rows it can send.
pub async fn defer_unsynced(db: &Db) -> Result<(i64, Option<Duration>)> {
    let mut tx = delivery_tx(db).await?;
    let (n, oldest): (i64, Option<f64>) = sqlx::query_as(
        "WITH waiting AS ( \
           SELECT id FROM stripe_meter_outbox w \
            WHERE w.status = 'pending' AND w.next_attempt_at <= now() \
              AND (SELECT true FROM stripe_meters m WHERE m.event_name = w.event_name) IS NULL \
            ORDER BY w.next_attempt_at \
            LIMIT $2 \
            FOR UPDATE SKIP LOCKED \
         ), deferred AS ( \
           UPDATE stripe_meter_outbox o \
              SET next_attempt_at = now() + make_interval(secs => $1) \
             FROM waiting \
            WHERE o.id = waiting.id \
           RETURNING o.created_at \
         ) \
         SELECT count(*), extract(epoch FROM now() - min(created_at))::float8 FROM deferred",
    )
    .bind(UNSYNCED_RECHECK.num_seconds() as f64)
    .bind(DEFER_BATCH)
    .fetch_one(tx.conn())
    .await?;
    tx.commit().await?;
    Ok((n, oldest.map(|s| Duration::seconds(s.max(0.0) as i64))))
}

/// Delete `sent` rows finished more than `keep_days` ago, [`SWEEP_BATCH`]
/// rows per statement (each its own transaction, through
/// `stripe_meter_outbox_sent_idx`) until none is left, and return how many.
/// Pending rows are waiting and lost (`rejected`, `expired`) rows are the
/// record of revenue that never reached Stripe; neither is ever swept.
pub async fn sweep(db: &Db, keep_days: i32) -> Result<u64> {
    let mut total = 0;
    loop {
        let mut tx = delivery_tx(db).await?;
        let n = sqlx::query(
            "DELETE FROM stripe_meter_outbox \
              WHERE id IN ( \
                SELECT id FROM stripe_meter_outbox \
                 WHERE status = 'sent' AND finished_at < now() - make_interval(days => $1) \
                 LIMIT $2)",
        )
        .bind(keep_days)
        .bind(SWEEP_BATCH)
        .execute(tx.conn())
        .await?
        .rows_affected();
        tx.commit().await?;
        total += n;
        if n < SWEEP_BATCH as u64 {
            return Ok(total);
        }
    }
}

/// Whether `org_id` has usage still waiting to reach Stripe (a `pending`
/// row, claimed or not, due or not) billed before `before`: a row whose hour
/// starts before `before`. Every event a row carries lies in its hour, so for
/// an hour-aligned `before` (a period's start, [`period::starts_at`]) this is
/// exactly "usage billed before `before`". `rejected` and `expired` rows will
/// never reach Stripe and do not count; neither do `sent` ones.
///
/// For Stripe invoicing: hold an invoice for a period until this is `false`
/// for the instant the period ends, so the invoice carries all its usage.
/// Usage can still be added for a period until it closes
/// ([`period::closes_at`]); ask after that.
///
/// `conn` must be a transaction pinned to `org_id` (`otto_tenant::Tx::conn`),
/// or an unpinned transaction opted in to the outbox's delivery policies.
/// Any other connection would see no rows under row-level security and
/// answer a false `false`, so it is refused with an error instead.
pub async fn has_pending_before(
    conn: &mut sqlx::PgConnection,
    org_id: OrgId,
    before: DateTime<Utc>,
) -> Result<bool> {
    let (pinned, opted_in): (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT current_org(), \
                COALESCE(current_setting('app.stripe_meter_delivery', true) = 'on', false)",
    )
    .fetch_one(&mut *conn)
    .await?;
    let sees_org = match pinned {
        Some(pinned) => pinned == org_id.as_uuid(),
        None => opted_in,
    };
    if !sees_org {
        return Err(Error::Tenant(otto_tenant::Error::Invalid(format!(
            "has_pending_before needs a transaction pinned to org {org_id} (or one opted in to \
             the stripe meter outbox's delivery policies)"
        ))));
    }
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM stripe_meter_outbox \
                         WHERE org_id = $1 AND status = 'pending' AND bucket_start < $2)",
    )
    .bind(org_id)
    .bind(before)
    .fetch_one(&mut *conn)
    .await?)
}

/// Queue for Stripe whatever of the org's metered usage in `month` is
/// counted (`org_meter_period_usage`) but not yet in the outbox, and return
/// the quantity queued, summed over meters. For Stripe billing to call when
/// an org's subscription goes live mid-month: usage before that was counted
/// but never queued.
///
/// **Contract.**
///
/// - `tx` is pinned to the org. It takes the org's ingest lock
///   ([`crate::usage::lock_org_ingest`]) first, so no ingest batch of the org
///   runs between the counters it reads and the rows it writes. Call it in
///   the transaction that makes the subscription live, or in one after it
///   commits; either way, every event is queued exactly once: an ingest
///   committed before it is in the counters it reads, and an ingest after it
///   sees the live subscription and queues its own events.
/// - **Idempotent.** For each meter it queues the counted quantity minus the
///   sum of every outbox row of that org and Stripe event name whose hour is
///   in `month` (any status, any customer: a row that was sent, or lost, was
///   already queued once). A second call queues nothing.
/// - It queues for the org's live subscription's customer, and returns `0`
///   with no live subscription (there is no one to bill).
/// - `month` must be a period that is still open ([`period::period_closed`]
///   is false): the current month, or the previous one during its grace. A
///   closed or future month is refused with an error. (A closed period's
///   invoice must not grow; and `sent` rows of a month long past may have
///   been swept, which would make the subtraction above queue them again.)
/// - The usage is aggregated like ingest's, into the open row of the hour it
///   is billed in: the current hour for the current month, or the last hour
///   of the previous month during its grace (inside it, so on that month's
///   invoice).
/// - Meters whose key has no Stripe event name are skipped, as ingest skips
///   them (logged once per meter).
///
/// `sent` rows are swept [`KEEP_SENT_DAYS`] after they were sent, which is
/// longer than any open period has existed, so none a backfill counts can
/// have been swept.
pub async fn backfill_period(tx: &mut Tx<'_>, month: Month) -> Result<u64> {
    crate::usage::lock_org_ingest(tx).await?;
    let org = tx.org();
    let now = Utc::now();
    let current = Month::of(now);
    let refuse = |why: &str| {
        Err(Error::Tenant(otto_tenant::Error::Invalid(format!(
            "cannot backfill {month}: {why}"
        ))))
    };
    if month > current {
        return refuse("it has not started");
    }
    if period::period_closed(month, now) {
        return refuse("its period has closed");
    }
    let bucket = if month == current {
        period::hour_bucket(now)
    } else {
        // The previous month, during its grace: its last hour.
        match month.offset(1) {
            Some(next) => period::starts_at(next) - Duration::hours(1),
            None => return refuse("it has no successor"),
        }
    };

    let customer: Option<String> = sqlx::query_scalar(
        "SELECT stripe_customer_id FROM subscriptions \
          WHERE org_id = $1 AND stripe_customer_id IS NOT NULL \
            AND stripe_subscription_id IS NOT NULL AND status = ANY($2::text[])",
    )
    .bind(org)
    .bind(&LIVE_STATUSES[..])
    .fetch_optional(tx.conn())
    .await?;
    let Some(customer) = customer else {
        return Ok(0);
    };

    let counted: Vec<(String, i64)> = sqlx::query_as(
        "SELECT meter, quantity FROM org_meter_period_usage \
          WHERE org_id = $1 AND period_start = $2 AND quantity > 0 ORDER BY meter",
    )
    .bind(org)
    .bind(month.first_day())
    .fetch_all(tx.conn())
    .await?;
    let (from, to) = (
        period::starts_at(month),
        month.offset(1).map(period::starts_at),
    );

    let mut queued: u64 = 0;
    for (meter, quantity) in counted {
        let Some(event_name) = event_name_of(&meter, None) else {
            continue;
        };
        let already: i64 = sqlx::query_scalar(
            "SELECT COALESCE(sum(value), 0)::bigint FROM stripe_meter_outbox \
              WHERE org_id = $1 AND event_name = $2 \
                AND bucket_start >= $3 AND ($4::timestamptz IS NULL OR bucket_start < $4)",
        )
        .bind(org)
        .bind(&event_name)
        .bind(from)
        .bind(to)
        .fetch_one(tx.conn())
        .await?;
        let mut missing = quantity.saturating_sub(already);
        while missing > 0 {
            let add = missing.min(MAX_ADDITION);
            sqlx::query(&format!(
                "INSERT INTO stripe_meter_outbox \
                   (org_id, event_name, stripe_customer_id, value, bucket_start, next_attempt_at) \
                 VALUES ($1, $2, $3, $4, $5, $5 + interval '1 hour') \
                 {}",
                add_to_open_row()
            ))
            .bind(org)
            .bind(&event_name)
            .bind(&customer)
            .bind(add)
            .bind(bucket)
            .execute(tx.conn())
            .await?;
            missing -= add;
            // `add` is positive.
            queued = queued.saturating_add(add.unsigned_abs());
        }
    }
    Ok(queued)
}

/// The outbox across every org, for an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxSummary {
    /// Rows in each status, every status listed.
    pub counts: Vec<(OutboxStatus, i64)>,
    /// How long the oldest pending row has waited since it was queued.
    pub oldest_pending: Option<Duration>,
}

impl OutboxSummary {
    /// Rows whose usage will never reach Stripe.
    pub fn lost(&self) -> i64 {
        self.counts
            .iter()
            .filter(|(s, _)| s.is_lost())
            .map(|(_, n)| n)
            .sum()
    }

    pub fn count(&self, status: OutboxStatus) -> i64 {
        self.counts
            .iter()
            .find(|(s, _)| *s == status)
            .map_or(0, |(_, n)| *n)
    }
}

/// How many rows are in each status, and the oldest pending row's age.
pub async fn outbox_summary(db: &Db) -> Result<OutboxSummary> {
    let mut tx = delivery_tx(db).await?;
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM stripe_meter_outbox GROUP BY status")
            .fetch_all(tx.conn())
            .await?;
    let oldest: Option<f64> = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - min(created_at))::float8 \
         FROM stripe_meter_outbox WHERE status = 'pending'",
    )
    .fetch_one(tx.conn())
    .await?;
    tx.commit().await?;
    let counts = OutboxStatus::ALL
        .into_iter()
        .map(|s| {
            let n = rows
                .iter()
                .find(|(name, _)| name == s.as_str())
                .map_or(0, |(_, n)| *n);
            (s, n)
        })
        .collect();
    Ok(OutboxSummary {
        counts,
        oldest_pending: oldest.map(|secs| Duration::seconds(secs.max(0.0) as i64)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::ApiError;

    fn api_err(status: u16, kind: &str, code: Option<&str>, message: &str) -> StripeError {
        StripeError::Api(ApiError {
            status,
            kind: kind.into(),
            code: code.map(Into::into),
            message: message.into(),
            param: None,
        })
    }

    fn api(status: u16, kind: &str) -> std::result::Result<(), StripeError> {
        Err(api_err(status, kind, None, "m"))
    }

    fn retry_received(v: Verdict) -> Option<bool> {
        match v {
            Verdict::Retry { maybe_received, .. } => Some(maybe_received),
            _ => None,
        }
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&Ok(())), Verdict::Sent);
        assert_eq!(
            verdict(&Err(StripeError::Decode("x".into()))),
            Verdict::Sent
        );
        for definite in [429, 401, 403] {
            assert_eq!(
                retry_received(verdict(&api(definite, "api_error"))),
                Some(false),
                "{definite}"
            );
        }
        for ambiguous in [409, 500, 502, 503] {
            assert_eq!(
                retry_received(verdict(&api(ambiguous, "api_error"))),
                Some(true),
                "{ambiguous}"
            );
        }
        assert_eq!(
            retry_received(verdict(&api(400, "idempotency_error"))),
            Some(true)
        );
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
        assert!(is_throttled(&api(429, "x").unwrap_err()));
    }

    #[test]
    fn a_duplicate_identifier_is_sent_either_way_stripe_says_it() {
        let by_code = api_err(
            400,
            "invalid_request_error",
            Some("resource_already_exists"),
            "x",
        );
        let by_message = api_err(
            400,
            "invalid_request_error",
            None,
            "An event with identifier svc:1 already exists.",
        );
        let duplicate = api_err(400, "invalid_request_error", None, "Duplicate identifier");
        for e in [by_code, by_message, duplicate] {
            assert!(is_duplicate_identifier(&e), "{e}");
            assert_eq!(verdict(&Err(e)), Verdict::Sent);
        }
        let unrelated = api_err(400, "invalid_request_error", None, "No such customer");
        assert!(!is_duplicate_identifier(&unrelated));
        let not_400 = api_err(
            500,
            "api_error",
            Some("resource_already_exists"),
            "identifier already exists",
        );
        assert!(!is_duplicate_identifier(&not_400));
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
    fn sums_can_never_overflow_a_row() {
        // Exact as a JSON number (f64), as Stripe reads it.
        const { assert!(MAX_OUTBOX_VALUE < 1 << 53) };
        const { assert!(OPEN_ROW_MAX_VALUE + MAX_ADDITION == MAX_OUTBOX_VALUE) };
        let per_event = i64::try_from(crate::usage::MAX_METER_QUANTITY).unwrap();
        assert!(per_event <= MAX_ADDITION);
        // The index predicate repeats the constant (migration 0023 too).
        assert!(OPEN_ROW.ends_with(&format!("value <= {OPEN_ROW_MAX_VALUE}")));
        assert!(add_to_open_row().contains(OPEN_ROW));
    }

    #[test]
    fn minted_identifiers_fit_stripes_limit() {
        // `'agg:' || gen_random_uuid()` in migration 0023.
        assert!(format!("agg:{}", Uuid::new_v4()).len() <= 100);
    }

    #[test]
    fn enqueue_needs_a_service_a_meter_a_name_and_a_young_hour() {
        let now = Utc::now();
        let m = |meter| Some(Metered { meter, quantity: 3 });
        let name = |service, metered, at| enqueue_event_name(service, metered, at, now);
        assert_eq!(
            name(Some("otto-flags"), m("otto-flags/evaluations"), now),
            Some("otto_flags__evaluations".to_owned())
        );
        assert_eq!(name(Some("otto-flags"), None, now), None);
        assert_eq!(name(None, m("otto-flags/evaluations"), now), None);
        // Another service's key, or a key with no Stripe name.
        assert_eq!(
            name(Some("otto-cxp"), m("otto-flags/evaluations"), now),
            None
        );
        let long = format!("svc/{}", "m".repeat(99));
        assert_eq!(name(Some("svc"), m(&long), now), None);
        // Too old for Stripe already: not queued.
        let old = now - MAX_EVENT_AGE - Duration::minutes(1);
        assert_eq!(
            name(Some("otto-flags"), m("otto-flags/evaluations"), old),
            None
        );
        let young = now - MAX_EVENT_AGE + Duration::minutes(1);
        assert!(name(Some("otto-flags"), m("otto-flags/evaluations"), young).is_some());
    }

    fn due(attempts: i32) -> DueMeterEvent {
        let now = Utc::now();
        DueMeterEvent {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            identifier: "agg:1".into(),
            event_name: "svc__calls".into(),
            stripe_customer_id: "cus_1".into(),
            value: 3,
            bucket_start: period::hour_bucket(now),
            attempts,
            window_started_at: None,
            claimed_at: now,
        }
    }

    #[test]
    fn keys_follow_the_attempt_and_the_event_never_changes() {
        let a = due(0);
        let b = due(1);
        assert_eq!(a.idempotency_key().unwrap().as_str(), "otto-mev-agg:1-1");
        assert_eq!(b.idempotency_key().unwrap().as_str(), "otto-mev-agg:1-2");
        let e = a.meter_event();
        assert_eq!(
            (e.identifier.as_str(), e.value, e.timestamp),
            ("agg:1", 3, a.bucket_start)
        );
    }

    #[test]
    fn too_old_or_out_of_window_rows_are_not_sent() {
        let ok = due(0);
        assert_eq!(ok.expired_before_send(), None);
        let mut old = due(0);
        old.bucket_start = old.claimed_at - Duration::days(40);
        assert!(old.expired_before_send().is_some());
        let mut late = due(3);
        late.window_started_at = Some(late.claimed_at - Duration::hours(13));
        assert!(late.expired_before_send().is_some());
        // No window yet (only definite failures so far): bounded by age only.
        let mut never_received = due(30);
        never_received.bucket_start = never_received.claimed_at - Duration::days(3);
        assert_eq!(never_received.expired_before_send(), None);
    }

    #[test]
    fn statuses_round_trip() {
        for s in OutboxStatus::ALL {
            assert_eq!(OutboxStatus::parse(s.as_str()), Some(s));
        }
        assert!(OutboxStatus::Rejected.is_lost() && OutboxStatus::Expired.is_lost());
        assert!(!OutboxStatus::Sent.is_lost());
    }

    #[test]
    fn errors_are_cut_on_a_char_boundary() {
        let long = "é".repeat(MAX_ERROR_LEN);
        let out = truncate(&long);
        assert!(out.len() <= MAX_ERROR_LEN + '…'.len_utf8());
        assert!(out.ends_with('…'));
    }
}
