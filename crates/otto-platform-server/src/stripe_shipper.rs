//! Shipping metered usage to Stripe meter events
//! (savvagent/otto-platform#64, epic #55) from `stripe_meter_outbox`
//! (migration 0023), which usage ingest fills for every metered event of an
//! org with a live Stripe subscription. See `otto_billing::stripe_outbox` for
//! what is queued and why every event reaches Stripe exactly once.
//!
//! [`run`] is a polling loop shaped like [`crate::email::run`]: claim due rows
//! across every org (a leased claim with `SKIP LOCKED`, so every machine can
//! run it), send each as one meter event under a [`SEND_DEADLINE`], record the
//! result. Only rows whose meter Stripe knows are claimed. Stripe allows one
//! concurrent meter-event call per customer and meter, so a pass sends the
//! rows of one customer and meter one after another, and up to
//! [`CONCURRENCY`] such groups at once.
//!
//! - Accepted (or already received): `sent`, swept after `KEEP_SENT_DAYS`.
//!   That means accepted for processing: Stripe's asynchronous error reports
//!   are not read yet.
//! - 429, 409, 5xx, no response, and 401/403 (our API key, logged at error
//!   once until a send succeeds): retried with backoff (10 s doubling to an
//!   hour), under the same identifier. Only outcomes where Stripe may have
//!   the event start its 12 h retry window.
//! - Any other 4xx, an event older than Stripe accepts, or a retry window
//!   that closed: `rejected` or `expired`, with the error kept on the row and
//!   logged at error level (at most [`MAX_LOGS_PER_MINUTE`] lines a minute,
//!   then a count). That usage will not be invoiced, so it is never silent:
//!   `otto-platform-server stripe outbox` counts rows by status.
//!
//! **Backing off.** The loop starts its next pass at once only when the pass
//! claimed a full batch and at least one send succeeded. Otherwise it waits
//! [`POLL`], and after a pass that Stripe throttled (429) or refused our key
//! (401/403) without a single success, twice as long as the last such wait,
//! up to [`MAX_BACKOFF`] ([`next_wait`]).
//!
//! The binary starts this only when billing is enabled (both Stripe secrets
//! set), through [`spawn`]. A shutdown interrupts a pass in flight; rows it
//! had claimed wait for their lease and are retried (under the same
//! idempotency key, so a send that did land is replayed, not repeated).
//!
//! **Secrets.** Nothing here sees the API key; the client scrubs it from every
//! Stripe error before one reaches a log line or `last_error`.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use futures::StreamExt;
use otto_billing::billing;
use otto_billing::stripe::Client;
use otto_billing::stripe_outbox::{self, DueMeterEvent, OutboxStatus, Verdict};
use otto_tenant::Db;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Rows claimed per pass.
pub const BATCH: i64 = 16;
/// Customer-and-meter groups sent at once per pass.
pub const CONCURRENCY: usize = 4;
/// The wait between passes with nothing to gain from hurrying.
pub const POLL: Duration = Duration::from_secs(5);
/// The longest wait after passes Stripe throttled or refused our key.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// One meter-event POST, connect to reply. Shorter than the client's own
/// 30 s timeout, so a pass is bounded by this.
pub const SEND_DEADLINE: Duration = Duration::from_secs(15);
/// The slowest possible pass (every row of the batch in one group, sent one
/// after another, each hitting [`SEND_DEADLINE`]) takes at most half of the
/// claim lease, leaving the other half for recording the results, so no row
/// is claimed again while its send is still running.
const _: () = assert!(
    BATCH as u64 * SEND_DEADLINE.as_secs() * 2 <= stripe_outbox::CLAIM_LEASE_SECONDS as u64
);
const SWEEP_EVERY: Duration = Duration::from_secs(3600);
/// How long rows may wait for their Stripe meter before an error says so.
const UNSYNCED_WARN_AFTER: chrono::Duration = chrono::Duration::hours(1);
/// How often that error may repeat.
const UNSYNCED_WARN_EVERY: Duration = Duration::from_secs(3600);
static UNSYNCED_WARNED: Mutex<Option<Instant>> = Mutex::new(None);
const EXPIRE_EVERY: Duration = Duration::from_secs(60);
/// Log lines a minute about lost usage, and separately about retries, before
/// the rest are counted.
pub const MAX_LOGS_PER_MINUTE: u32 = 10;

/// Start the shipper when billing is enabled (`stripe` is `Some`), or do
/// nothing and return `None` when it is not.
pub fn spawn(
    db: Db,
    stripe: Option<&billing::Stripe>,
    shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let client = stripe?.client.clone();
    Some(tokio::spawn(run(db, client, shutdown)))
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Rows claimed.
    pub claimed: usize,
    /// Rows Stripe accepted.
    pub sent: usize,
    /// Sends Stripe throttled (429).
    pub throttled: usize,
    /// Sends Stripe refused for our API key (401/403).
    pub credential_faults: usize,
}

impl PassReport {
    /// Whether the next pass should start at once: a full batch, and Stripe
    /// is taking events.
    pub fn more_waiting(&self) -> bool {
        self.claimed as i64 == BATCH && self.sent > 0
    }
}

/// How long to wait after a pass, given the wait after the previous one
/// (`Duration::ZERO` for none). Zero when [`PassReport::more_waiting`];
/// doubling from [`POLL`] to [`MAX_BACKOFF`] while passes are throttled or
/// refused without a success; [`POLL`] otherwise.
pub fn next_wait(report: &PassReport, previous: Duration) -> Duration {
    if report.more_waiting() {
        return Duration::ZERO;
    }
    if report.sent == 0 && (report.throttled > 0 || report.credential_faults > 0) {
        return (previous * 2).clamp(POLL, MAX_BACKOFF);
    }
    POLL
}

/// Run until `shutdown` flips to `true`.
pub async fn run(db: Db, client: Client, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("stripe meter event shipper started");
    let mut last_sweep: Option<Instant> = None;
    let mut last_expire: Option<Instant> = None;
    let mut wait = Duration::ZERO;
    loop {
        if *shutdown.borrow() {
            break;
        }
        if last_expire.is_none_or(|t| t.elapsed() >= EXPIRE_EVERY) {
            last_expire = Some(Instant::now());
            expire_stale(&db).await;
        }
        let report = tokio::select! {
            r = ship_due_with_deadline(&db, &client, SEND_DEADLINE) => r,
            _ = shutdown.changed() => break,
        };
        wait = match report {
            Ok(report) => next_wait(&report, wait),
            Err(e) => {
                tracing::error!(error = %e, "stripe meter event pass failed");
                POLL
            }
        };
        if wait.is_zero() {
            continue;
        }

        if last_sweep.is_none_or(|t| t.elapsed() >= SWEEP_EVERY) {
            last_sweep = Some(Instant::now());
            match stripe_outbox::sweep(&db, stripe_outbox::KEEP_SENT_DAYS).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(rows = n, "swept sent stripe meter events"),
                Err(e) => tracing::warn!(error = %e, "stripe meter event sweep failed"),
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
    }
    tracing::info!("stripe meter event shipper stopping");
}

/// Expire rows grown too old to send without ever being claimed, and report
/// each as lost; then push back rows whose meter Stripe does not know yet,
/// and say so (at most once an hour) once the oldest has waited an hour.
async fn expire_stale(db: &Db) {
    match stripe_outbox::expire_stale(db).await {
        Ok(rows) => {
            for row in &rows {
                report_lost(
                    row,
                    OutboxStatus::Expired,
                    "too old before it could be sent",
                );
            }
            lost_logs_summary();
        }
        Err(e) => tracing::warn!(error = %e, "expiring stale stripe meter events failed"),
    }
    match stripe_outbox::defer_unsynced(db).await {
        Ok((n, Some(oldest))) if oldest >= UNSYNCED_WARN_AFTER => {
            let mut last = UNSYNCED_WARNED
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if last.is_none_or(|t| t.elapsed() >= UNSYNCED_WARN_EVERY) {
                *last = Some(Instant::now());
                tracing::error!(
                    events = n,
                    oldest_minutes = oldest.num_minutes(),
                    "metered usage is waiting for a Stripe meter that does not exist yet: \
                     run `otto-platform-server stripe sync` and read its errors"
                );
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "deferring unsynced stripe meter events failed"),
    }
}

/// One pass with the production [`SEND_DEADLINE`].
pub async fn ship_due(db: &Db, client: &Client) -> billing::Result<PassReport> {
    ship_due_with_deadline(db, client, SEND_DEADLINE).await
}

/// One pass: claim up to [`BATCH`] due rows and send them, one customer and
/// meter at a time per group, [`CONCURRENCY`] groups at once, each send
/// bounded by `deadline` (at most [`SEND_DEADLINE`]).
pub async fn ship_due_with_deadline(
    db: &Db,
    client: &Client,
    deadline: Duration,
) -> billing::Result<PassReport> {
    let deadline = deadline.min(SEND_DEADLINE);
    let due = stripe_outbox::claim_due(db, BATCH).await?;
    let claimed = due.len();
    let mut groups: Vec<Vec<DueMeterEvent>> = Vec::new();
    for row in due {
        match groups.iter_mut().find(|g| {
            g[0].stripe_customer_id == row.stripe_customer_id && g[0].event_name == row.event_name
        }) {
            Some(g) => g.push(row),
            None => groups.push(vec![row]),
        }
    }
    let tally = Tally::default();
    // Collected first: a lazy `map` inside the stream trips the compiler's
    // higher-ranked `Send` inference once this is `tokio::spawn`ed.
    let sends: Vec<_> = groups
        .iter()
        .map(|g| ship_group(db, client, g, deadline, &tally))
        .collect();
    futures::stream::iter(sends)
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<()>>()
        .await;
    retry_logs_summary();
    lost_logs_summary();
    Ok(PassReport {
        claimed,
        sent: tally.sent.load(Ordering::Relaxed),
        throttled: tally.throttled.load(Ordering::Relaxed),
        credential_faults: tally.credential_faults.load(Ordering::Relaxed),
    })
}

#[derive(Default)]
struct Tally {
    sent: AtomicUsize,
    throttled: AtomicUsize,
    credential_faults: AtomicUsize,
}

async fn ship_group(
    db: &Db,
    client: &Client,
    rows: &[DueMeterEvent],
    deadline: Duration,
    tally: &Tally,
) {
    for row in rows {
        ship_one(db, client, row, deadline, tally).await;
    }
}

/// Set once a credential fault (401/403) has been logged at error, cleared by
/// the next accepted event.
static CREDENTIAL_FAULT_REPORTED: AtomicBool = AtomicBool::new(false);

async fn ship_one(
    db: &Db,
    client: &Client,
    row: &DueMeterEvent,
    deadline: Duration,
    tally: &Tally,
) {
    let recorded = async {
        if let Some(why) = row.expired_before_send() {
            if stripe_outbox::mark_terminal(db, row, OutboxStatus::Expired, &why, false).await? {
                report_lost(row, OutboxStatus::Expired, &why);
            }
            return Ok(());
        }
        let key = match row.idempotency_key() {
            Ok(key) => key,
            Err(billing::Error::Stripe(e)) => {
                let e = e.to_string();
                if stripe_outbox::mark_terminal(db, row, OutboxStatus::Rejected, &e, false).await? {
                    report_lost(row, OutboxStatus::Rejected, &e);
                }
                return Ok(());
            }
            Err(other) => return Err(other),
        };
        let result =
            match tokio::time::timeout(deadline, client.send_meter_event(&row.meter_event(), &key))
                .await
            {
                Ok(r) => r.map(drop),
                Err(_) => {
                    let error =
                        format!("no response from Stripe within {} ms", deadline.as_millis());
                    return retry(db, row, &error, true).await;
                }
            };
        if let Err(e) = &result {
            if stripe_outbox::is_throttled(e) {
                tally.throttled.fetch_add(1, Ordering::Relaxed);
            }
            if stripe_outbox::is_credential_fault(e) {
                tally.credential_faults.fetch_add(1, Ordering::Relaxed);
                if !CREDENTIAL_FAULT_REPORTED.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        error = %e,
                        "Stripe refused our API key for meter events: check STRIPE_SECRET_KEY \
                         and its permissions (Billing Meter Events: write). Metered usage stays \
                         queued until the event is 34 days old"
                    );
                }
            }
        }
        match stripe_outbox::verdict(&result) {
            Verdict::Sent => {
                CREDENTIAL_FAULT_REPORTED.store(false, Ordering::Relaxed);
                tally.sent.fetch_add(1, Ordering::Relaxed);
                stripe_outbox::mark_sent(db, row).await
            }
            Verdict::Retry {
                error,
                maybe_received,
            } => retry(db, row, &error, maybe_received).await,
            Verdict::Reject(e) => {
                if stripe_outbox::mark_terminal(db, row, OutboxStatus::Rejected, &e, true).await? {
                    report_lost(row, OutboxStatus::Rejected, &e);
                }
                Ok(())
            }
        }
    }
    .await;
    // The send already happened (or not); failing to write that down lets the
    // claim lapse and the row is sent again under the same idempotency key.
    if let Err(e) = recorded {
        tracing::error!(
            outbox_id = %row.id,
            error = %e,
            "could not record a stripe meter event result"
        );
    }
}

async fn retry(
    db: &Db,
    row: &DueMeterEvent,
    error: &str,
    maybe_received: bool,
) -> billing::Result<()> {
    if RETRY_LOGS.allow() {
        tracing::warn!(
            outbox_id = %row.id,
            org_id = %row.org_id,
            identifier = %row.identifier,
            attempt = row.attempts + 1,
            error,
            "stripe meter event failed; will retry"
        );
    }
    if stripe_outbox::mark_retry(db, row, error, maybe_received).await?
        == Some(OutboxStatus::Expired)
    {
        report_lost(row, OutboxStatus::Expired, error);
    }
    Ok(())
}

/// A per-minute budget of log lines: [`MAX_LOGS_PER_MINUTE`] are allowed,
/// the rest counted until [`LogBudget::take_held_back`] reports them.
struct LogBudget(Mutex<Option<(Instant, u32, u32)>>);

impl LogBudget {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Whether one more line may be logged now; counts it as held back if
    /// not.
    fn allow(&self) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, logged, held) = state.get_or_insert((Instant::now(), 0, 0));
        if start.elapsed() >= Duration::from_secs(60) {
            *start = Instant::now();
            *logged = 0;
        }
        if *logged < MAX_LOGS_PER_MINUTE {
            *logged += 1;
            true
        } else {
            *held += 1;
            false
        }
    }

    /// How many lines were held back since the last call.
    fn take_held_back(&self) -> u32 {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .as_mut()
            .map_or(0, |(_, _, held)| std::mem::take(held))
    }
}

static LOST_LOGS: LogBudget = LogBudget::new();
static RETRY_LOGS: LogBudget = LogBudget::new();

/// One summary line per pass for the retry warnings the budget held back.
fn retry_logs_summary() {
    let held = RETRY_LOGS.take_held_back();
    if held > 0 {
        tracing::warn!(
            events = held,
            "more stripe meter events failed and will be retried"
        );
    }
}

/// One line, at the end of each pass, for the lost-usage errors the budget
/// held back, so the end of a burst is reported without waiting for the next
/// loss.
fn lost_logs_summary() {
    let held = LOST_LOGS.take_held_back();
    if held > 0 {
        tracing::error!(
            events = held,
            "more metered usage was not billed; see `otto-platform-server stripe outbox`"
        );
    }
}

/// Log a row whose usage will never reach Stripe, at error level, within
/// [`LOST_LOGS`]' budget; the rest are counted and reported by
/// [`lost_logs_summary`].
fn report_lost(row: &DueMeterEvent, status: OutboxStatus, error: &str) {
    if !LOST_LOGS.allow() {
        return;
    }
    tracing::error!(
        outbox_id = %row.id,
        org_id = %row.org_id,
        identifier = %row.identifier,
        event_name = %row.event_name,
        value = row.value,
        status = status.as_str(),
        error,
        "metered usage will not be billed: Stripe never accepted its meter event"
    );
}

/// `otto-platform-server stripe outbox`: rows by status across every org,
/// and how long the oldest pending row has waited.
pub async fn write_counts(db: &Db, out: &mut impl Write) -> anyhow::Result<()> {
    let summary = stripe_outbox::outbox_summary(db).await?;
    for (status, n) in &summary.counts {
        writeln!(out, "{:<9} {n}", status.as_str())?;
    }
    match summary.oldest_pending {
        Some(age) => writeln!(
            out,
            "oldest pending: {}h {:02}m",
            age.num_hours(),
            age.num_minutes() % 60
        )?,
        None => writeln!(out, "oldest pending: none")?,
    }
    let lost = summary.lost();
    if lost > 0 {
        writeln!(
            out,
            "{lost} metered event(s) never reached Stripe and will not be invoiced; \
             each row's last_error says why"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(claimed: usize, sent: usize, throttled: usize, cred: usize) -> PassReport {
        PassReport {
            claimed,
            sent,
            throttled,
            credential_faults: cred,
        }
    }

    #[test]
    fn only_a_full_pass_with_progress_starts_the_next_at_once() {
        let full = BATCH as usize;
        assert_eq!(next_wait(&report(full, 1, 0, 0), POLL), Duration::ZERO);
        // A full batch where nothing succeeded: no hot loop.
        assert_eq!(next_wait(&report(full, 0, 0, 0), Duration::ZERO), POLL);
        assert_eq!(next_wait(&report(3, 3, 0, 0), Duration::ZERO), POLL);
        assert_eq!(next_wait(&report(0, 0, 0, 0), Duration::ZERO), POLL);
    }

    #[test]
    fn throttling_and_key_refusals_back_off_exponentially_to_a_cap() {
        let full = BATCH as usize;
        let mut wait = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..10 {
            wait = next_wait(&report(full, 0, full, 0), wait);
            seen.push(wait.as_secs());
        }
        assert_eq!(seen, [5, 10, 20, 40, 80, 160, 300, 300, 300, 300]);
        assert_eq!(
            next_wait(&report(1, 0, 0, 1), Duration::from_secs(40)),
            Duration::from_secs(80)
        );
        // One success resets it.
        assert_eq!(next_wait(&report(4, 1, 3, 0), MAX_BACKOFF), POLL);
    }

    #[test]
    fn the_log_budget_holds_back_and_reports_the_rest() {
        let budget = LogBudget::new();
        let allowed = (0..MAX_LOGS_PER_MINUTE + 5)
            .filter(|_| budget.allow())
            .count();
        assert_eq!(allowed, MAX_LOGS_PER_MINUTE as usize);
        assert_eq!(budget.take_held_back(), 5);
        assert_eq!(budget.take_held_back(), 0);
    }
}
