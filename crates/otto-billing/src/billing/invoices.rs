//! Invoices wait for their usage.
//!
//! Stripe makes a subscription's invoice for month M at 00:00 UTC on the
//! first of M+1, as a draft it would finalize about an hour later. Usage for
//! M can still reach Stripe after that: the meter outbox sends each hour's
//! usage after the hour ends, and M stays open for late events until
//! [`period::closes_at`] (02:00 UTC). Usage that reaches Stripe after M's
//! invoice is finalized is never invoiced. So:
//!
//! 1. **Hold.** The `invoice.created` webhook ([`invoice_created`]) records a
//!    subscription-cycle draft invoice of the org's recorded subscription in
//!    `stripe_held_invoices`, then sets its `auto_advance` to `false`, which
//!    keeps it a draft. Recorded first, so an invoice whose hold reached
//!    Stripe is always one sync will release. (Stripe also waits for a
//!    successful answer to `invoice.created` before it finalizes a
//!    subscription invoice on its own, so a failed hold is retried before
//!    the invoice can advance.)
//! 2. **Release.** Every [`super::sync`] run looks at each org's held
//!    invoices ([`release_held`]). One is finalized, with `auto_advance`
//!    back on so Stripe collects it, once its month has closed, none of the
//!    usage that can be on it has been waiting to reach Stripe for
//!    [`INVOICE_SETTLE`] (two sync runs in a row see none), and the last of
//!    it was sent at least [`INVOICE_SETTLE`] ago (time for Stripe to apply
//!    the last meter events it accepted). "Usage that can be on it" is
//!    [`stripe_outbox::invoice_shipping`]'s: the invoice's own month and
//!    customer, for meters Stripe knows. A stuck row of an older month,
//!    another customer's row, or a row of a meter Stripe does not know yet
//!    never holds it (the last is logged at warn). An invoice held
//!    [`MAX_INVOICE_HOLD`] is finalized anyway and logged at error: invoices
//!    never sit forever, and the usage still waiting is not on it.
//! 3. **Someone else moved it.** An invoice that is no longer a draft when
//!    sync comes to release it (finalized or voided in the dashboard) is left
//!    alone and recorded as `not_draft`. So is one that had already advanced
//!    when the webhook came to hold it: if it is `open`, `auto_advance` is
//!    turned back on so Stripe collects it; a `paid`, `void` or
//!    `uncollectible` one is not touched at all.
//!
//! Both halves run under the org's billing lease, like every other billing
//! change: no transaction is open during a Stripe call, and every write after
//! one is refused once the lease is lost. Both are idempotent: a redelivered
//! `invoice.created` finds the invoice recorded and only repeats the
//! (idempotent) hold, and a released invoice is never held again.

use chrono::{DateTime, Duration, TimeZone, Utc};
use otto_tenant::audit::Entry;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use serde_json::{json, Value};
use uuid::Uuid;

use super::webhook::{id_field, ignored, invoice_subscription};
use super::{
    actions, idem, lock_row, Error, EventOutcome, OrgLease, Result, SyncReport, STRIPE_ACTOR,
    SYNC_ACTOR,
};
use crate::period::{self, Month};
use crate::stripe::Client;
use crate::stripe_outbox;

/// The longest an invoice is held. Past it, it is finalized whatever is still
/// waiting to reach Stripe, with an error log.
pub const MAX_INVOICE_HOLD: Duration = Duration::hours(72);

/// How long sync must have seen none of a held invoice's usage waiting
/// before it finalizes the invoice: one sync interval, so two runs agree.
pub const INVOICE_SETTLE: Duration = Duration::minutes(10);

/// How long sync waits for an org another worker is busy with before moving
/// on; the next run tries again.
const ORG_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// `stripe_held_invoices.outcome`.
pub mod outcomes {
    /// Finalized once its usage had reached Stripe.
    pub const FINALIZED: &str = "finalized";
    /// Finalized at [`super::MAX_INVOICE_HOLD`] with usage still waiting.
    pub const FINALIZED_LATE: &str = "finalized_late";
    /// No longer a draft when sync came to it: left alone.
    pub const NOT_DRAFT: &str = "not_draft";
}

/// The month an invoice bills: the one holding the instant before its
/// `period_end` (a subscription invoice looks back one period, so the
/// invoice made at 00:00 UTC on 1 November ends its period then and bills
/// October), or before the event's `created` if it has none.
pub(super) fn billed_month(invoice: &Value, created: DateTime<Utc>) -> Option<Month> {
    let end = match invoice.get("period_end").and_then(Value::as_i64) {
        Some(end) => Utc.timestamp_opt(end, 0).single()?,
        None => created,
    };
    Some(Month::of(end - Duration::seconds(1)))
}

/// What sync does with one held invoice now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision {
    /// Not yet: its month is open, or usage was seen waiting too recently.
    Wait,
    /// Its usage has reached Stripe: finalize it.
    Finalize,
    /// Held too long: finalize it anyway, and say so at error level.
    FinalizeLate,
}

/// `clear_since`: since when sync has seen none of the month's usage waiting
/// (`None`: some is waiting). `last_sent_at`: when the last of it was sent
/// (`None`: none was).
pub(super) fn decide(
    month: Month,
    held_at: DateTime<Utc>,
    clear_since: Option<DateTime<Utc>>,
    last_sent_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Decision {
    let settled = |at: DateTime<Utc>| now - at >= INVOICE_SETTLE;
    if period::period_closed(month, now)
        && clear_since.is_some_and(settled)
        && last_sent_at.is_none_or(settled)
    {
        Decision::Finalize
    } else if now - held_at >= MAX_INVOICE_HOLD {
        Decision::FinalizeLate
    } else {
        Decision::Wait
    }
}

/// Whether sync should look closer at a held invoice at `now` (take the
/// org's lease): its month has closed, or its hold is up.
fn may_be_due(month: Month, held_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    period::period_closed(month, now) || now - held_at >= MAX_INVOICE_HOLD
}

/// `invoice.created`: hold a subscription-cycle draft invoice of the org's
/// recorded subscription until its usage has reached Stripe (see the module
/// docs). Every other invoice is acknowledged and left alone.
pub(super) async fn invoice_created(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    invoice: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    let Some(id) = id_field(invoice, "id") else {
        return Ok(ignored("the invoice has no id"));
    };
    if invoice.get("billing_reason").and_then(Value::as_str) != Some("subscription_cycle") {
        return Ok(ignored("not a subscription-cycle invoice"));
    }
    if invoice.get("status").and_then(Value::as_str) != Some("draft") {
        return Ok(ignored("the invoice is not a draft"));
    }
    let Some(subscription) = invoice_subscription(invoice) else {
        return Ok(ignored("the invoice is not for a subscription"));
    };
    let Some(month) = billed_month(invoice, created) else {
        return Ok(ignored("the invoice's period is out of range"));
    };
    // `handle_event` found the org by this very field.
    let Some(customer) = id_field(invoice, "customer") else {
        return Ok(ignored("the invoice names no customer"));
    };

    // Recorded before the hold is sent: an invoice held in Stripe is always
    // one sync will release.
    let mut tx = lease.begin(db).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_subscription_id.as_deref() != Some(subscription) {
        return Ok(ignored("not an invoice of the org's current subscription"));
    }
    let released: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
        "SELECT released_at FROM stripe_held_invoices WHERE stripe_invoice_id = $1",
    )
    .bind(id)
    .fetch_optional(tx.conn())
    .await?;
    match released {
        Some(Some(_)) => return Ok(ignored("the invoice was already released")),
        Some(None) => {}
        None => {
            sqlx::query(
                "INSERT INTO stripe_held_invoices \
                   (stripe_invoice_id, org_id, stripe_subscription_id, stripe_customer_id, \
                    period_month) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(id)
            .bind(org)
            .bind(subscription)
            .bind(customer)
            .bind(month.first_day())
            .execute(tx.conn())
            .await?;
            tx.audit(
                Entry::new(actions::INVOICE_HELD)
                    .actor_label(STRIPE_ACTOR)
                    .target("org", org.to_string())
                    .detail(json!({
                        "invoiceId": id,
                        "stripeSubscriptionId": subscription,
                        "period": month.to_string(),
                    })),
            )
            .await?;
        }
    }
    tx.commit().await?;

    lease.renew(db).await?;
    let status = match client
        .set_invoice_auto_advance(id, false, &idem("invoice-hold", &id)?)
        .await
    {
        Ok(held) => held.status,
        // Stripe may refuse to update an invoice that is no longer a draft
        // or open (paid, void). Look before failing the event, which Stripe
        // would redeliver for days.
        Err(e) if e.api().is_some_and(|a| a.status == 400) => {
            lease.renew(db).await?;
            let now = client.retrieve_invoice(id).await?;
            if now.status.as_deref() == Some("draft") {
                return Err(e.into());
            }
            now.status
        }
        Err(e) => return Err(e.into()),
    };
    if status.as_deref() != Some("draft") {
        // It advanced before the hold reached it (Stripe had stopped waiting
        // for this webhook). An open invoice gets collection back (the hold
        // just turned it off); a paid, void or uncollectible one is done
        // with and is not touched again.
        if status.as_deref() == Some("open") {
            lease.renew(db).await?;
            client
                .set_invoice_auto_advance(id, true, &idem("invoice-unhold", &id)?)
                .await?;
        }
        record_release(db, lease, org, id, month, outcomes::NOT_DRAFT, STRIPE_ACTOR).await?;
        return Ok(ignored(format!(
            "the invoice had already advanced ({}); left to Stripe",
            status.as_deref().unwrap_or("gone")
        )));
    }
    Ok(EventOutcome::Handled)
}

/// Write a release, under the lease, with its audit entry. `false` when the
/// invoice was already released (by a run that lost its answer).
async fn record_release(
    db: &Db,
    lease: &OrgLease,
    org: OrgId,
    id: &str,
    month: Month,
    outcome: &str,
    actor: &str,
) -> Result<bool> {
    let mut tx = lease.begin(db).await?;
    let released = sqlx::query(
        "UPDATE stripe_held_invoices SET released_at = now(), outcome = $2 \
         WHERE stripe_invoice_id = $1 AND released_at IS NULL",
    )
    .bind(id)
    .bind(outcome)
    .execute(tx.conn())
    .await?
    .rows_affected()
        == 1;
    if released {
        tx.audit(
            Entry::new(actions::INVOICE_RELEASED)
                .actor_label(actor)
                .target("org", org.to_string())
                .detail(json!({
                    "invoiceId": id,
                    "period": month.to_string(),
                    "outcome": outcome,
                })),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(released)
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct Held {
    stripe_invoice_id: String,
    stripe_customer_id: String,
    period_month: chrono::NaiveDate,
    held_at: DateTime<Utc>,
}

impl Held {
    fn month(&self) -> Month {
        Month::containing(self.period_month)
    }
}

/// Release every held invoice that is due (see the module docs), org by
/// org, stopping between orgs once `stop` says so. Failures are collected in
/// `report.errors`; the next run tries again.
pub(super) async fn release_held(
    db: &Db,
    client: &Client,
    stop: &(dyn Fn() -> bool + Send + Sync),
    report: &mut SyncReport,
) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    let orgs: Vec<Uuid> =
        sqlx::query_scalar("SELECT org_id FROM stripe_customers ORDER BY created_at, org_id")
            .fetch_all(tx.conn())
            .await?;
    tx.commit().await?;
    for org in orgs.into_iter().map(OrgId::from) {
        if stop() {
            return Ok(());
        }
        let mut tx = db.begin(org).await?;
        let held: Vec<Held> = sqlx::query_as(
            "SELECT stripe_invoice_id, stripe_customer_id, period_month, held_at \
               FROM stripe_held_invoices \
             WHERE released_at IS NULL ORDER BY held_at, stripe_invoice_id",
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        let now = Utc::now();
        let due: Vec<Held> = held
            .into_iter()
            .filter(|h| may_be_due(h.month(), h.held_at, now))
            .collect();
        if due.is_empty() {
            continue;
        }
        let lease = match OrgLease::acquire(db, org, ORG_WAIT).await {
            Ok(lease) => lease,
            Err(Error::Busy(_)) => {
                report.warnings.push(format!(
                    "org {org}: busy with another billing change; its held invoices wait for \
                     the next run"
                ));
                continue;
            }
            Err(e) => {
                report.errors.push(format!("org {org}: {e}"));
                continue;
            }
        };
        for h in &due {
            if let Err(e) = release_one(db, client, &lease, org, h, report).await {
                report.errors.push(format!(
                    "org {org}: held invoice {}: {e}",
                    h.stripe_invoice_id
                ));
                if matches!(e, Error::LeaseLost(_)) {
                    break;
                }
            }
        }
        lease.release(db).await;
    }
    Ok(())
}

async fn release_one(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    org: OrgId,
    held: &Held,
    report: &mut SyncReport,
) -> Result<()> {
    let id = held.stripe_invoice_id.as_str();
    let month = held.month();

    // Is any of the usage that can be on this invoice still on its way?
    // Asked in the org's own pinned transaction, as `invoice_shipping`
    // requires, under the lease.
    let mut tx = lease.begin(db).await?;
    let shipping =
        stripe_outbox::invoice_shipping(tx.conn(), org, &held.stripe_customer_id, month).await?;
    let pending = shipping.pending;
    let clear_since: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
        "UPDATE stripe_held_invoices \
            SET clear_since = CASE WHEN $2 THEN NULL ELSE COALESCE(clear_since, now()) END \
          WHERE stripe_invoice_id = $1 AND released_at IS NULL \
          RETURNING clear_since",
    )
    .bind(id)
    .bind(pending)
    .fetch_optional(tx.conn())
    .await?;
    tx.commit().await?;
    let Some(clear_since) = clear_since else {
        // Released meanwhile.
        return Ok(());
    };

    if shipping.unsynced > 0 {
        tracing::warn!(
            %org,
            invoice = %id,
            period = %month,
            rows = shipping.unsynced,
            "usage of a held invoice's period is waiting for a meter Stripe does not know \
             yet; it does not hold the invoice and will not be on it. Run `otto-platform-server \
             stripe sync`"
        );
        report.warnings.push(format!(
            "org {org}: held invoice {id} for {month}: {} outbox rows wait for a meter Stripe \
             does not know yet and will not be on it",
            shipping.unsynced
        ));
    }

    let decision = decide(
        month,
        held.held_at,
        clear_since,
        shipping.last_sent_at,
        Utc::now(),
    );
    if decision == Decision::Wait {
        return Ok(());
    }

    lease.renew(db).await?;
    let invoice = client.retrieve_invoice(id).await?;
    if invoice.status.as_deref() != Some("draft") {
        if record_release(db, lease, org, id, month, outcomes::NOT_DRAFT, SYNC_ACTOR).await? {
            report.warnings.push(format!(
                "org {org}: held invoice {id} for {month} was already {} in Stripe; left as \
                 it is",
                invoice.status.as_deref().unwrap_or("gone")
            ));
            report
                .invoices_released
                .push((org, id.to_owned(), outcomes::NOT_DRAFT.to_owned()));
        }
        return Ok(());
    }
    lease.renew(db).await?;
    // Finalized with `auto_advance` on: Stripe collects it from here.
    client
        .finalize_invoice(id, true, &idem("invoice-finalize", &id)?)
        .await?;
    let outcome = match decision {
        Decision::FinalizeLate => {
            tracing::error!(
                %org,
                invoice = %id,
                period = %month,
                pending,
                "finalized a Stripe invoice at its maximum hold of {} hours; usage of the period \
                 that had not reached Stripe yet is not on it. Check `otto-platform-server \
                 stripe outbox`",
                MAX_INVOICE_HOLD.num_hours()
            );
            report.warnings.push(format!(
                "org {org}: invoice {id} for {month} finalized at its maximum hold with usage \
                 still waiting to reach Stripe"
            ));
            outcomes::FINALIZED_LATE
        }
        _ => outcomes::FINALIZED,
    };
    if record_release(db, lease, org, id, month, outcome, SYNC_ACTOR).await? {
        report
            .invoices_released
            .push((org, id.to_owned(), outcome.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    #[test]
    fn an_invoice_bills_the_month_before_its_period_end() {
        let nov1 = utc(2026, 11, 1, 0, 0);
        let oct = Month::new(2026, 10).unwrap();
        let inv = json!({ "period_end": nov1.timestamp() });
        assert_eq!(billed_month(&inv, nov1 + Duration::days(3)), Some(oct));
        // No period: the instant before the event.
        assert_eq!(billed_month(&json!({}), nov1), Some(oct));
        assert_eq!(
            billed_month(&json!({}), nov1 + Duration::minutes(5)),
            Some(Month::new(2026, 11).unwrap())
        );
    }

    #[test]
    fn an_invoice_waits_for_its_period_to_close_and_its_usage_to_settle() {
        let oct = Month::new(2026, 10).unwrap();
        let held = utc(2026, 11, 1, 0, 1);
        let close = utc(2026, 11, 1, 2, 0);
        // Open period: wait, however clear.
        assert_eq!(
            decide(oct, held, Some(held), None, close - Duration::seconds(1)),
            Decision::Wait
        );
        // Closed, but usage seen waiting, or seen clear only just now.
        assert_eq!(decide(oct, held, None, None, close), Decision::Wait);
        let seen = close + Duration::minutes(1);
        assert_eq!(
            decide(
                oct,
                held,
                Some(seen),
                None,
                seen + INVOICE_SETTLE - Duration::seconds(1)
            ),
            Decision::Wait
        );
        assert_eq!(
            decide(oct, held, Some(seen), None, seen + INVOICE_SETTLE),
            Decision::Finalize
        );
        // Clear, but the last of its usage was sent only just now: Stripe
        // may not have applied it yet.
        let ready = seen + INVOICE_SETTLE;
        assert_eq!(
            decide(
                oct,
                held,
                Some(seen),
                Some(ready - INVOICE_SETTLE + Duration::seconds(1)),
                ready
            ),
            Decision::Wait
        );
        assert_eq!(
            decide(oct, held, Some(seen), Some(ready - INVOICE_SETTLE), ready),
            Decision::Finalize
        );
        // Held too long: finalized whatever is waiting.
        assert_eq!(
            decide(oct, held, None, None, held + MAX_INVOICE_HOLD),
            Decision::FinalizeLate
        );
        assert_eq!(
            decide(
                oct,
                held,
                None,
                None,
                held + MAX_INVOICE_HOLD - Duration::seconds(1)
            ),
            Decision::Wait
        );
    }

    #[test]
    fn only_a_closed_period_or_an_expired_hold_is_looked_at() {
        let oct = Month::new(2026, 10).unwrap();
        let held = utc(2026, 10, 31, 23, 0);
        assert!(!may_be_due(oct, held, utc(2026, 11, 1, 1, 59)));
        assert!(may_be_due(oct, held, utc(2026, 11, 1, 2, 0)));
        let nov = Month::new(2026, 11).unwrap();
        assert!(may_be_due(nov, held, held + MAX_INVOICE_HOLD));
    }
}
