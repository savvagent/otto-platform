//! Handling Stripe's webhook events.
//!
//! **Duplicates.** Stripe delivers at least once, sometimes twice at the same
//! moment, and out of order. Three things together make that safe:
//!
//! 1. The `stripe_events` ledger: a delivery of an event id already handled
//!    is acknowledged and does nothing. It is written after the event's
//!    effects commit, so it never records an event that was not handled.
//! 2. The org lease: two deliveries racing past the ledger check (both see
//!    the id unrecorded) are handled one after the other, never interleaved,
//!    because each handler holds the org's lease ([`super::OrgLease`]).
//! 3. Every handler is idempotent on its own: it compares what the event says
//!    with what is recorded, writes (and audits) only a change, and ignores an
//!    event older than the one that set the current status. So the second of
//!    two racing deliveries finds its change already made and does nothing;
//!    its Stripe calls carry the same idempotency keys as the first's and are
//!    replayed by Stripe, not repeated.

use chrono::{DateTime, TimeZone, Utc};
use otto_tenant::audit::Entry;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use serde_json::{json, Value};

use super::sync::reconcile_org;
use super::{
    actions, idem, lock_row, org_of_customer, read_row, Error, OrgLease, PaymentMethodStatus,
    Result, SyncReport, LEASE_WAIT, STRIPE_ACTOR,
};
use crate::stripe::{Client, WebhookEvent};

/// What [`handle_event`] did with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOutcome {
    /// Already in the ledger: acknowledged, nothing done.
    Duplicate,
    /// Handled; its effects (if any) are committed.
    Handled,
    /// Acknowledged with no action, and why (an unhandled type, an event for
    /// a customer that is not ours, a stale or superseded event).
    Ignored(String),
}

fn ignored(why: impl Into<String>) -> EventOutcome {
    EventOutcome::Ignored(why.into())
}

/// The event types [`handle_event`] acts on. Register the webhook endpoint for
/// exactly these.
pub const HANDLED_EVENT_TYPES: [&str; 6] = [
    "checkout.session.completed",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.paid",
    "invoice.payment_failed",
    "payment_method.detached",
];

/// A string field of a Stripe object, or the `id` of an expanded one.
fn id_field<'a>(object: &'a Value, field: &str) -> Option<&'a str> {
    match object.get(field)? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id")?.as_str(),
        _ => None,
    }
    .filter(|s| !s.is_empty() && s.len() <= 255)
}

/// The subscription an invoice bills: `parent.subscription_details.
/// subscription` from API version 2025-03-31.basil on, `subscription` before.
fn invoice_subscription(invoice: &Value) -> Option<&str> {
    invoice
        .get("parent")
        .and_then(|p| p.get("subscription_details"))
        .and_then(|d| id_field(d, "subscription"))
        .or_else(|| id_field(invoice, "subscription"))
}

/// Whether an event created at `created` may set a status last set by an
/// event created at `last`. Equal times apply, so a replay is a no-op rather
/// than a refusal.
fn not_older(last: Option<DateTime<Utc>>, created: DateTime<Utc>) -> bool {
    last.is_none_or(|last| created >= last)
}

/// Handle one verified Stripe event, at most once by its id.
///
/// `payload` is the verified request body the event was parsed from; a
/// handler that needs a field [`WebhookEvent`] does not carry
/// (`data.previous_attributes`) reads it from there.
///
/// An `Err` means the event was not handled and is not in the ledger: answer
/// Stripe with a 5xx so it retries.
pub async fn handle_event(
    db: &Db,
    client: &Client,
    event: &WebhookEvent,
    payload: &[u8],
) -> Result<EventOutcome> {
    if already_handled(db, &event.id).await? {
        return Ok(EventOutcome::Duplicate);
    }
    let created = Utc
        .timestamp_opt(event.created, 0)
        .single()
        .ok_or_else(|| Error::Unexpected(format!("event created at {}", event.created)))?;
    let object = &event.data.object;
    let kind = Kind::of(&event.event_type);
    let customer = match kind {
        Kind::Unhandled => None,
        Kind::Detached => id_field(object, "customer").map(str::to_owned).or_else(|| {
            serde_json::from_slice::<Value>(payload).ok().and_then(|v| {
                id_field(v.get("data")?.get("previous_attributes")?, "customer").map(str::to_owned)
            })
        }),
        _ => id_field(object, "customer").map(str::to_owned),
    };

    let outcome = match (kind, customer) {
        (Kind::Unhandled, _) => ignored("an event type billing does not handle"),
        (_, None) => ignored("the event names no customer"),
        (kind, Some(customer)) => match org_of_customer(db, &customer).await? {
            None => ignored("not one of our customers"),
            Some(org) => {
                let lease = OrgLease::acquire(db, org, LEASE_WAIT).await?;
                let result = match kind {
                    Kind::Checkout => {
                        checkout_completed(db, client, org, &customer, object, created).await
                    }
                    Kind::Subscription => subscription_changed(db, org, object, created).await,
                    Kind::InvoicePaid => invoice_settled(db, org, object, created, true).await,
                    Kind::InvoiceFailed => invoice_settled(db, org, object, created, false).await,
                    Kind::Detached => card_detached(db, org, object, created).await,
                    Kind::Unhandled => unreachable!("matched above"),
                };
                lease.release(db).await;
                result?
            }
        },
    };
    record_event(db, event, created).await?;
    Ok(outcome)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Checkout,
    Subscription,
    InvoicePaid,
    InvoiceFailed,
    Detached,
    Unhandled,
}

impl Kind {
    fn of(event_type: &str) -> Self {
        match event_type {
            "checkout.session.completed" => Self::Checkout,
            "customer.subscription.updated" | "customer.subscription.deleted" => Self::Subscription,
            "invoice.paid" => Self::InvoicePaid,
            "invoice.payment_failed" => Self::InvoiceFailed,
            "payment_method.detached" => Self::Detached,
            _ => Self::Unhandled,
        }
    }
}

async fn already_handled(db: &Db, event_id: &str) -> Result<bool> {
    let mut tx = db.begin_unpinned().await?;
    let seen: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM stripe_events WHERE event_id = $1)")
            .bind(event_id)
            .fetch_one(tx.conn())
            .await?;
    tx.commit().await?;
    Ok(seen)
}

async fn record_event(db: &Db, event: &WebhookEvent, created: DateTime<Utc>) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "INSERT INTO stripe_events (event_id, event_type, stripe_created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `checkout.session.completed` in setup mode: make the collected card the
/// customer's default, mark it on file (clearing a stop), detach the card it
/// replaces, and subscribe the org.
async fn checkout_completed(
    db: &Db,
    client: &Client,
    org: OrgId,
    customer: &str,
    session: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    if session.get("mode").and_then(Value::as_str) != Some("setup") {
        return Ok(ignored("not a setup-mode Checkout session"));
    }
    let claimed = session
        .get("metadata")
        .and_then(|m| m.get("org_id"))
        .and_then(Value::as_str);
    if claimed.is_some_and(|claimed| claimed != org.to_string()) {
        return Ok(ignored(
            "the session's metadata names a different org from its customer",
        ));
    }
    let Some(setup_intent) = id_field(session, "setup_intent") else {
        return Ok(ignored("the session has no setup intent"));
    };
    let row = read_row(db, org).await?;
    if row.as_ref().and_then(|r| r.stripe_customer_id.as_deref()) != Some(customer) {
        return Ok(ignored("the org's row records another customer"));
    }

    let intent = client.retrieve_setup_intent(setup_intent).await?;
    if intent.status != "succeeded" {
        return Ok(ignored(format!(
            "the setup intent has status {:?}",
            intent.status
        )));
    }
    if intent.customer.as_deref() != Some(customer) {
        return Ok(ignored("the setup intent belongs to another customer"));
    }
    let Some(pm) = intent.payment_method else {
        return Ok(ignored("the setup intent has no payment method"));
    };
    client
        .set_default_payment_method(customer, &pm, &idem("default-pm", &(customer, &pm))?)
        .await?;

    // Recorded before the old card is detached: the detach's own webhook then
    // finds a different card on file and is ignored.
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    let changed = row.card()? != PaymentMethodStatus::Active
        || row.stripe_payment_method_id.as_deref() != Some(pm.as_str())
        || row.billing_stopped_at.is_some();
    let mut replaced = None;
    if changed && not_older(row.payment_method_event_at, created) {
        sqlx::query(
            "UPDATE subscriptions SET payment_method_status = 'active', \
               stripe_payment_method_id = $2, payment_method_event_at = $3, \
               billing_stopped_at = NULL, updated_at = now() \
             WHERE org_id = $1",
        )
        .bind(org)
        .bind(&pm)
        .bind(created)
        .execute(tx.conn())
        .await?;
        tx.audit(
            Entry::new(actions::CARD_ADDED)
                .actor_label(STRIPE_ACTOR)
                .target("org", org.to_string())
                .detail(json!({
                    "checkoutSessionId": id_field(session, "id"),
                    "resumed": row.billing_stopped_at.is_some(),
                })),
        )
        .await?;
        replaced = row.stripe_payment_method_id.filter(|old| *old != pm);
    }
    tx.commit().await?;

    if let Some(old) = replaced {
        // Not essential: a stale card left attached is only clutter.
        if let Err(e) = client
            .detach_payment_method(&old, &idem("detach-pm", &old)?)
            .await
        {
            tracing::warn!(%org, error = %e, "could not detach the card a new one replaced");
        }
    }

    let mut report = SyncReport::default();
    reconcile_org(db, client, org, STRIPE_ACTOR, &mut report).await?;
    for w in report.warnings.iter().chain(&report.errors) {
        tracing::warn!(%org, "{w}");
    }
    Ok(EventOutcome::Handled)
}

/// `customer.subscription.updated` and `.deleted`: record the status. A
/// deleted subscription stops billing for the org until its owner puts a
/// card on file again; sync never re-subscribes a stopped org.
async fn subscription_changed(
    db: &Db,
    org: OrgId,
    subscription: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    let Some(id) = id_field(subscription, "id") else {
        return Ok(ignored("the subscription has no id"));
    };
    let Some(status) = subscription
        .get("status")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 64)
    else {
        return Ok(ignored("the subscription has no status"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_subscription_id.as_deref() != Some(id) {
        return Ok(ignored("not the org's current subscription"));
    }
    // Canceled is final in Stripe; a late `updated` cannot revive it.
    if row.status == "canceled" && status != "canceled" {
        return Ok(ignored("the subscription is already canceled"));
    }
    if !not_older(row.subscription_event_at, created) {
        return Ok(ignored("older than the status already recorded"));
    }
    let stops = status == "canceled" && row.billing_stopped_at.is_none();
    sqlx::query(
        "UPDATE subscriptions SET status = $2, subscription_event_at = $3, \
           billing_stopped_at = CASE WHEN $4 THEN $3 ELSE billing_stopped_at END, \
           stripe_schedule_id = CASE WHEN $4 THEN NULL ELSE stripe_schedule_id END, \
           stripe_plan = CASE WHEN $4 THEN NULL ELSE stripe_plan END, \
           updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(status)
    .bind(created)
    .bind(stops)
    .execute(tx.conn())
    .await?;
    if row.status != status || stops {
        tx.audit(
            Entry::new(actions::SUBSCRIPTION_STATUS_CHANGED)
                .actor_label(STRIPE_ACTOR)
                .target("org", org.to_string())
                .detail(json!({
                    "stripeSubscriptionId": id,
                    "from": row.status,
                    "to": status,
                    "billingStopped": stops,
                })),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

/// `invoice.paid` and `invoice.payment_failed` for the org's current
/// subscription: a failure marks the active card `failed`; a later payment
/// restores a `failed` card to `active`. Invoices of any other subscription
/// (an old, canceled one) change nothing.
async fn invoice_settled(
    db: &Db,
    org: OrgId,
    invoice: &Value,
    created: DateTime<Utc>,
    paid: bool,
) -> Result<EventOutcome> {
    let Some(subscription) = invoice_subscription(invoice) else {
        return Ok(ignored("the invoice is not for a subscription"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_subscription_id.as_deref() != Some(subscription) {
        return Ok(ignored("not an invoice of the org's current subscription"));
    }
    let (from, to, action) = if paid {
        (
            PaymentMethodStatus::Failed,
            "active",
            actions::PAYMENT_RECOVERED,
        )
    } else {
        (
            PaymentMethodStatus::Active,
            "failed",
            actions::PAYMENT_FAILED,
        )
    };
    // A detached card stays detached; a card that is fine stays fine.
    if row.card()? != from {
        return Ok(ignored(format!("the card is not {}", from.as_str())));
    }
    if !not_older(row.payment_method_event_at, created) {
        return Ok(ignored("older than the card's recorded status"));
    }
    sqlx::query(
        "UPDATE subscriptions SET payment_method_status = $2, \
           payment_method_event_at = $3, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(to)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(action)
            .actor_label(STRIPE_ACTOR)
            .target("org", org.to_string())
            .detail(json!({ "invoiceId": id_field(invoice, "id") })),
    )
    .await?;
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

/// `payment_method.detached`: the card on file was removed. (A detached
/// payment method no longer names its customer; [`handle_event`] takes it
/// from `data.previous_attributes.customer`.)
async fn card_detached(
    db: &Db,
    org: OrgId,
    payment_method: &Value,
    created: DateTime<Utc>,
) -> Result<EventOutcome> {
    let Some(pm) = id_field(payment_method, "id") else {
        return Ok(ignored("the payment method has no id"));
    };
    let mut tx = db.begin(org).await?;
    let row = lock_row(&mut tx).await?;
    if row.stripe_payment_method_id.as_deref() != Some(pm) {
        return Ok(ignored("not the card on file"));
    }
    if row.card()? == PaymentMethodStatus::Detached {
        return Ok(ignored("already detached"));
    }
    if !not_older(row.payment_method_event_at, created) {
        return Ok(ignored("older than the card's recorded status"));
    }
    sqlx::query(
        "UPDATE subscriptions SET payment_method_status = 'detached', \
           payment_method_event_at = $2, updated_at = now() \
         WHERE org_id = $1",
    )
    .bind(org)
    .bind(created)
    .execute(tx.conn())
    .await?;
    tx.audit(
        Entry::new(actions::CARD_DETACHED)
            .actor_label(STRIPE_ACTOR)
            .target("org", org.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok(EventOutcome::Handled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_events_do_not_apply_and_replays_do() {
        let t = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
        assert!(not_older(None, t));
        assert!(not_older(Some(t), t));
        assert!(not_older(Some(t - chrono::Duration::seconds(1)), t));
        assert!(!not_older(Some(t + chrono::Duration::seconds(1)), t));
    }

    #[test]
    fn ids_are_read_plain_or_expanded_and_bounded() {
        let v = json!({
            "a": "cus_1", "b": {"id": "cus_2"}, "c": null, "d": "", "e": "x".repeat(256),
        });
        assert_eq!(id_field(&v, "a"), Some("cus_1"));
        assert_eq!(id_field(&v, "b"), Some("cus_2"));
        assert_eq!(id_field(&v, "c"), None);
        assert_eq!(id_field(&v, "d"), None);
        assert_eq!(id_field(&v, "e"), None);
        assert_eq!(id_field(&v, "missing"), None);
    }

    #[test]
    fn an_invoices_subscription_is_read_in_either_api_shape() {
        let basil = json!({"parent": {"subscription_details": {"subscription": "sub_1"}}});
        let older = json!({"subscription": "sub_2"});
        assert_eq!(invoice_subscription(&basil), Some("sub_1"));
        assert_eq!(invoice_subscription(&older), Some("sub_2"));
        assert_eq!(invoice_subscription(&json!({"parent": null})), None);
    }

    #[test]
    fn every_handled_type_is_dispatched() {
        for t in HANDLED_EVENT_TYPES {
            assert_ne!(Kind::of(t), Kind::Unhandled, "{t}");
        }
        assert_eq!(Kind::of("customer.created"), Kind::Unhandled);
    }
}
