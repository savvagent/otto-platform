//! Shipping metered usage to Stripe meter events
//! (savvagent/otto-platform#64, epic #55) from `stripe_meter_outbox`
//! (migration 0023), which usage ingest fills for every metered event of an
//! org with a live Stripe subscription. See `otto_billing::stripe_outbox` for
//! what is queued and why every event reaches Stripe exactly once.
//!
//! [`run`] is a polling loop shaped like [`crate::email::run`]: claim due rows
//! across every org (a leased claim with `SKIP LOCKED`, so every machine can
//! run it), send each as one meter event under a [`SEND_DEADLINE`], record the
//! result. Stripe allows one concurrent meter-event call per customer and
//! meter, so a pass sends the rows of one customer and meter one after
//! another, and up to [`CONCURRENCY`] such groups at once.
//!
//! - Accepted: `sent`, swept after `KEEP_SENT_DAYS`.
//! - 429, 409, 5xx, no response, and 401/403 (our API key, logged at error
//!   once until a send succeeds): retried with backoff (10 s doubling to an
//!   hour), under the same identifier, inside the 12 h retry window.
//! - Any other 4xx, or an event older than Stripe accepts, or a retry window
//!   that closed: `rejected` or `expired`, with the error kept on the row and
//!   logged at error level (at most [`MAX_LOST_LOGS_PER_MINUTE`] lines a
//!   minute, then a count). That usage will not be invoiced, so it is never
//!   silent: `otto-platform-server stripe outbox` counts rows by status.
//!
//! The binary starts this only when billing is enabled (both Stripe secrets
//! set), through [`spawn`]. With billing disabled nothing is queued in the
//! first place unless an org already had a live subscription; such rows wait.
//!
//! **Secrets.** Nothing here sees the API key; the client scrubs it from every
//! Stripe error before one reaches a log line or `last_error`.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
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
const POLL: Duration = Duration::from_secs(5);
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
/// Error lines about lost usage per minute, before the rest are counted.
pub const MAX_LOST_LOGS_PER_MINUTE: u32 = 10;

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

/// Run until `shutdown` flips to `true`.
pub async fn run(db: Db, client: Client, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("stripe meter event shipper started");
    let mut last_sweep: Option<Instant> = None;
    loop {
        match ship_due(&db, &client).await {
            // A full batch means more is probably waiting, unless asked to
            // stop: under a backlog every pass is full and the shutdown check
            // below would never be reached.
            Ok(n) if n as i64 == BATCH && !*shutdown.borrow() => continue,
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "stripe meter event pass failed"),
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
            _ = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => {
                tracing::info!("stripe meter event shipper stopping");
                return;
            }
        }
    }
}

/// One pass: claim up to [`BATCH`] due rows and send them, one customer and
/// meter at a time per group, [`CONCURRENCY`] groups at once. Returns how many
/// rows were claimed.
pub async fn ship_due(db: &Db, client: &Client) -> billing::Result<usize> {
    let due = stripe_outbox::claim_due(db, BATCH).await?;
    let n = due.len();
    let mut groups: Vec<Vec<DueMeterEvent>> = Vec::new();
    for row in due {
        match groups.iter_mut().find(|g| {
            g[0].stripe_customer_id == row.stripe_customer_id && g[0].event_name == row.event_name
        }) {
            Some(g) => g.push(row),
            None => groups.push(vec![row]),
        }
    }
    // Collected first: a lazy `map` inside the stream trips the compiler's
    // higher-ranked `Send` inference once this is `tokio::spawn`ed.
    let sends: Vec<_> = groups.iter().map(|g| ship_group(db, client, g)).collect();
    futures::stream::iter(sends)
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<()>>()
        .await;
    Ok(n)
}

async fn ship_group(db: &Db, client: &Client, rows: &[DueMeterEvent]) {
    for row in rows {
        ship_one(db, client, row).await;
    }
}

/// Set once a credential fault (401/403) has been logged at error, cleared by
/// the next accepted event.
static CREDENTIAL_FAULT_REPORTED: AtomicBool = AtomicBool::new(false);

async fn ship_one(db: &Db, client: &Client, row: &DueMeterEvent) {
    let recorded = async {
        if let Some(why) = row.expired_before_send() {
            stripe_outbox::mark_terminal(db, row, OutboxStatus::Expired, &why, false).await?;
            report_lost(row, OutboxStatus::Expired, &why);
            return Ok(());
        }
        let result = match row.idempotency_key() {
            Ok(key) => {
                match tokio::time::timeout(
                    SEND_DEADLINE,
                    client.send_meter_event(&row.meter_event(), &key),
                )
                .await
                {
                    Ok(r) => r.map(drop),
                    Err(_) => {
                        return retry(
                            db,
                            row,
                            &format!(
                                "no response from Stripe within {} s",
                                SEND_DEADLINE.as_secs()
                            ),
                        )
                        .await;
                    }
                }
            }
            Err(e) => Err(match e {
                billing::Error::Stripe(e) => e,
                other => return Err(other),
            }),
        };
        if let Err(e) = &result {
            if stripe_outbox::is_credential_fault(e)
                && !CREDENTIAL_FAULT_REPORTED.swap(true, Ordering::Relaxed)
            {
                tracing::error!(
                    error = %e,
                    "Stripe refused our API key for meter events: check STRIPE_SECRET_KEY \
                     and its permissions (Billing meter events: write). Metered usage stays \
                     queued and is retried for 12 hours per event"
                );
            }
        }
        match stripe_outbox::verdict(&result) {
            Verdict::Sent => {
                CREDENTIAL_FAULT_REPORTED.store(false, Ordering::Relaxed);
                stripe_outbox::mark_sent(db, row).await
            }
            Verdict::Retry(e) => retry(db, row, &e).await,
            Verdict::Reject(e) => {
                stripe_outbox::mark_terminal(db, row, OutboxStatus::Rejected, &e, true).await?;
                report_lost(row, OutboxStatus::Rejected, &e);
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

async fn retry(db: &Db, row: &DueMeterEvent, error: &str) -> billing::Result<()> {
    tracing::warn!(
        outbox_id = %row.id,
        org_id = %row.org_id,
        identifier = %row.identifier,
        attempt = row.attempts + 1,
        error,
        "stripe meter event failed; will retry"
    );
    if stripe_outbox::mark_retry(db, row, error).await? == OutboxStatus::Expired {
        report_lost(row, OutboxStatus::Expired, error);
    }
    Ok(())
}

/// The error-log budget for lost usage: when the current minute started, how
/// many lines it has logged, and how many it held back.
static LOST_LOGS: Mutex<Option<(Instant, u32, u32)>> = Mutex::new(None);

/// Log a row whose usage will never reach Stripe, at error level, at most
/// [`MAX_LOST_LOGS_PER_MINUTE`] times a minute; the rest are counted and the
/// count logged when the next minute starts.
fn report_lost(row: &DueMeterEvent, status: OutboxStatus, error: &str) {
    let (log, held_back) = {
        let mut state = LOST_LOGS.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, logged, suppressed) = state.get_or_insert((Instant::now(), 0, 0));
        let mut held_back = 0;
        if start.elapsed() >= Duration::from_secs(60) {
            held_back = *suppressed;
            *start = Instant::now();
            *logged = 0;
            *suppressed = 0;
        }
        let log = *logged < MAX_LOST_LOGS_PER_MINUTE;
        if log {
            *logged += 1;
        } else {
            *suppressed += 1;
        }
        (log, held_back)
    };
    if held_back > 0 {
        tracing::error!(
            events = held_back,
            "more metered usage was not billed in the last minute; see \
             `otto-platform-server stripe outbox`"
        );
    }
    if log {
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
}

/// `otto-platform-server stripe outbox`: rows by status, across every org.
pub async fn write_counts(db: &Db, out: &mut impl Write) -> anyhow::Result<()> {
    let counts = stripe_outbox::status_counts(db).await?;
    for (status, n) in &counts {
        writeln!(out, "{:<9} {n}", status.as_str())?;
    }
    let lost: i64 = counts
        .iter()
        .filter(|(s, _)| s.is_lost())
        .map(|(_, n)| n)
        .sum();
    if lost > 0 {
        writeln!(
            out,
            "{lost} metered event(s) never reached Stripe and will not be invoiced; \
             each row's last_error says why"
        )?;
    }
    Ok(())
}
