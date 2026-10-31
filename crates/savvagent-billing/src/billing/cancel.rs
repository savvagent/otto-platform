//! Canceling a deleted org's Stripe subscription (savvagent/otto-platform#73).
//!
//! Deleting an org queues a row in `stripe_cancellations` (migration 0028) in
//! the deletion's own transaction, for an org that has a Stripe subscription.
//! [`run_pass`] carries the rows out, retrying until Stripe has canceled each
//! subscription, so a Stripe outage can neither block nor roll back a
//! deletion, and a canceled org's card is never invoiced again.
//!
//! **Policy.** The subscription is canceled with `invoice_now=true` and
//! `prorate=false`: the usage accrued up to the deletion is invoiced at once
//! and nothing is credited back. A row is not worked while the org still has
//! meter events waiting to be sent (`stripe_meter_outbox` rows that are
//! `pending`), so the final invoice includes them; a row older than
//! [`MAX_WAIT_FOR_USAGE`] stops waiting, because rows that can never ship (a
//! meter Stripe does not know) must not keep a card on the hook. The Stripe
//! customer is kept, so its invoices stay readable, and its card is detached.
//! A cycle invoice that was held as a draft before the deletion is deleted
//! in Stripe (and released as `deleted`, so sync does not look for it): its
//! automatic collection is off, so it would otherwise stay a draft forever.
//! What the draft billed is forgone; the cancel's own final invoice covers
//! only usage not yet invoiced.
//!
//! **Exactly once.** Before canceling, the subscription is retrieved: one
//! already `canceled`, or gone (404), is `done` with no call. Otherwise the
//! cancel carries an idempotency key derived from the row, so a retry after a
//! lost answer replays Stripe's. A unique key on the subscription id keeps a
//! redelivered deletion from queuing a second row.

use std::time::Duration;

use savvagent_tenant::ids::OrgId;
use savvagent_tenant::Db;
use uuid::Uuid;

use super::{invoices, Result};
use crate::stripe::{Client, IdempotencyKey, StripeError};
use crate::stripe_outbox::{self, Verdict};

/// Rows claimed per pass.
const BATCH: i64 = 20;

/// How long a claim holds a row, which is also how soon a pass that died
/// mid-row tries it again.
const CLAIM_LEASE_SECS: f64 = 300.0;

/// A row stops waiting for the org's queued meter events to ship after this.
pub const MAX_WAIT_FOR_USAGE: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// One queued cancellation, claimed.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DueCancellation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub stripe_payment_method_id: Option<String>,
    /// Attempts including this one.
    pub attempts: i32,
}

/// What one [`run_pass`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CancelReport {
    pub claimed: usize,
    /// Canceled in Stripe by this pass.
    pub canceled: usize,
    /// Already canceled or gone in Stripe: marked done with no cancel call.
    pub already_gone: usize,
    /// Failed for now and left to retry.
    pub retrying: usize,
    /// Refused for good, kept `failed` for an operator.
    pub failed: usize,
}

/// Claim up to [`BATCH`] due rows. A row whose org still has pending meter
/// events waits (unless it has waited [`MAX_WAIT_FOR_USAGE`]).
pub async fn claim_due(db: &Db) -> Result<Vec<DueCancellation>> {
    // Opted in to the meter outbox's delivery policies: the wait for the
    // org's pending rows reads across the org it is not pinned to.
    let mut tx = stripe_outbox::delivery_tx(db).await?;
    let rows = sqlx::query_as(
        "UPDATE stripe_cancellations c \
            SET attempts = c.attempts + 1, \
                next_attempt_at = now() + make_interval(secs => $2) \
          WHERE c.id IN ( \
                SELECT q.id FROM stripe_cancellations q \
                 WHERE q.status = 'pending' AND q.next_attempt_at <= now() \
                   AND (q.created_at < now() - make_interval(secs => $3) \
                        OR NOT EXISTS (SELECT 1 FROM stripe_meter_outbox o \
                                        WHERE o.org_id = q.org_id AND o.status = 'pending')) \
                 ORDER BY q.next_attempt_at \
                 LIMIT $1 \
                 FOR UPDATE OF q SKIP LOCKED) \
          RETURNING c.id, c.org_id, c.stripe_customer_id, c.stripe_subscription_id, \
                    c.stripe_payment_method_id, c.attempts",
    )
    .bind(BATCH)
    .bind(CLAIM_LEASE_SECS)
    .bind(MAX_WAIT_FOR_USAGE.as_secs_f64())
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

async fn mark_done(db: &Db, row: &DueCancellation, note: &str) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "UPDATE stripe_cancellations \
            SET status = 'done', finished_at = now(), last_error = $2 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(row.id)
    .bind(note)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Schedule the next attempt: a minute, doubling to an hour.
async fn mark_retry(db: &Db, row: &DueCancellation, error: &str) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "UPDATE stripe_cancellations \
            SET last_error = $2, \
                next_attempt_at = now() + make_interval(secs => \
                    least(3600.0, 60.0 * power(2.0, least(attempts - 1, 6)))) \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(row.id)
    .bind(stripe_outbox::truncate(error))
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_failed(db: &Db, row: &DueCancellation, error: &str) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "UPDATE stripe_cancellations \
            SET status = 'failed', finished_at = now(), last_error = $2 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(row.id)
    .bind(stripe_outbox::truncate(error))
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

fn is_missing(e: &StripeError) -> bool {
    e.api().is_some_and(|a| a.status == 404)
}

/// Whether a retrieved subscription needs no cancel.
fn is_over(status: &str) -> bool {
    matches!(status, "canceled" | "incomplete_expired")
}

enum Outcome {
    Canceled,
    AlreadyGone,
}

async fn cancel_in_stripe(
    client: &Client,
    row: &DueCancellation,
) -> std::result::Result<Outcome, StripeError> {
    match client
        .retrieve_subscription(&row.stripe_subscription_id)
        .await
    {
        Err(e) if is_missing(&e) => return Ok(Outcome::AlreadyGone),
        Err(e) => return Err(e),
        Ok(sub) if is_over(&sub.status) => return Ok(Outcome::AlreadyGone),
        Ok(_) => {}
    }
    let key = IdempotencyKey::new(format!("otto-cancel-{}", row.id))?;
    match client
        .cancel_subscription_invoice_now(&row.stripe_subscription_id, &key)
        .await
    {
        Ok(_) => Ok(Outcome::Canceled),
        // Canceled between the look and the call (by Stripe's dunning, or the
        // previous attempt whose answer was lost): what we wanted.
        Err(e) if is_missing(&e) => Ok(Outcome::AlreadyGone),
        Err(e) => Err(e),
    }
}

/// One pass: claim the due rows and cancel each subscription. Never fails on
/// Stripe: an error leaves its row to retry (or `failed`, for a refusal that
/// will not change). Only the database failing returns an error.
pub async fn run_pass(db: &Db, client: &Client) -> Result<CancelReport> {
    let due = claim_due(db).await?;
    let mut report = CancelReport {
        claimed: due.len(),
        ..CancelReport::default()
    };
    for row in &due {
        match cancel_in_stripe(client, row).await {
            Ok(outcome) => {
                // Drafts first: a failure here retries the row, which finds
                // the subscription already canceled and comes back to this.
                if let Err(e) =
                    invoices::delete_held_for_org(db, client, OrgId::from(row.org_id)).await
                {
                    report.retrying += 1;
                    tracing::warn!(
                        org = %row.org_id, error = %e,
                        "could not delete a deleted org's held draft invoice; will retry"
                    );
                    mark_retry(db, row, &e.to_string()).await?;
                    continue;
                }
                // The card goes with the subscription. A failure here is
                // logged and not retried: the subscription is what bills.
                if let Some(pm) = &row.stripe_payment_method_id {
                    if let Ok(key) = IdempotencyKey::new(format!("otto-cancel-pm-{}", row.id)) {
                        if let Err(e) = client.detach_payment_method(pm, &key).await {
                            tracing::warn!(
                                org = %row.org_id, error = %e,
                                "could not detach the card of a deleted org's customer"
                            );
                        }
                    }
                }
                match outcome {
                    Outcome::Canceled => {
                        report.canceled += 1;
                        mark_done(db, row, "canceled with invoice_now").await?;
                        tracing::info!(
                            org = %row.org_id,
                            subscription = %row.stripe_subscription_id,
                            "canceled the Stripe subscription of a deleted org"
                        );
                    }
                    Outcome::AlreadyGone => {
                        report.already_gone += 1;
                        mark_done(db, row, "already canceled in Stripe").await?;
                    }
                }
            }
            Err(e) => {
                let failure: std::result::Result<(), StripeError> = Err(e);
                match stripe_outbox::verdict(&failure) {
                    // `verdict` reads an undecodable answer as success; for a
                    // cancel that is "unknown", retried and found canceled.
                    Verdict::Sent => {
                        report.retrying += 1;
                        mark_retry(db, row, "Stripe's answer could not be read").await?;
                    }
                    Verdict::Retry { error, .. } => {
                        report.retrying += 1;
                        tracing::warn!(
                            org = %row.org_id, attempts = row.attempts, error = %error,
                            "canceling a deleted org's Stripe subscription failed; will retry"
                        );
                        mark_retry(db, row, &error).await?;
                    }
                    Verdict::Reject(why) => {
                        report.failed += 1;
                        tracing::error!(
                            org = %row.org_id,
                            subscription = %row.stripe_subscription_id,
                            error = %why,
                            "Stripe refused to cancel a deleted org's subscription; it will \
                             keep invoicing the card until an operator cancels it in the dashboard"
                        );
                        mark_failed(db, row, &why).await?;
                    }
                }
            }
        }
    }
    Ok(report)
}

/// How many rows are in each status, for `stripe outbox`.
pub async fn summary(db: &Db) -> Result<Vec<(String, i64)>> {
    let mut tx = db.begin_unpinned().await?;
    let rows = sqlx::query_as(
        "SELECT status, count(*) FROM stripe_cancellations GROUP BY status ORDER BY status",
    )
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}
