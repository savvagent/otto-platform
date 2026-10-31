//! The Stripe calls billing needs: request parameters, response shapes, and
//! the [`Client`] methods that send them.
//!
//! Response structs carry only the fields billing reads; Stripe sends more,
//! and unknown fields are ignored.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::client::{Client, Form};
use super::error::StripeError;
use super::event_name::is_event_name_shaped;
use super::money::ucents_to_unit_amount_decimal;
use super::secret::IdempotencyKey;

type Metadata = BTreeMap<String, String>;

// ---------------------------------------------------------------- responses

/// A page of a Stripe list (`object: "list"`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct List<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Customer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
    pub invoice_settings: Option<InvoiceSettings>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct InvoiceSettings {
    /// A `pm_...` id (never expanded by this client).
    pub default_payment_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    /// The hosted page to send the user to.
    pub url: Option<String>,
    pub mode: String,
    pub customer: Option<String>,
    /// A `seti_...` id once the session has one.
    pub setup_intent: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SetupIntent {
    pub id: String,
    /// e.g. `succeeded`, `requires_payment_method`.
    pub status: String,
    pub customer: Option<String>,
    /// A `pm_...` id once one is attached.
    pub payment_method: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Meter {
    pub id: String,
    pub event_name: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Recurring {
    pub interval: String,
    pub usage_type: String,
    pub meter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Price {
    pub id: String,
    pub currency: String,
    /// A `prod_...` id (never expanded by this client).
    pub product: String,
    pub lookup_key: Option<String>,
    pub tiers_mode: Option<String>,
    pub recurring: Option<Recurring>,
    #[serde(default)]
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SubscriptionItem {
    pub id: String,
    pub price: Price,
    pub subscription: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub customer: String,
    pub status: String,
    pub items: List<SubscriptionItem>,
    #[serde(default)]
    pub metadata: Metadata,
    /// The `sub_sched_...` managing it, if any (never expanded).
    #[serde(default)]
    pub schedule: Option<String>,
}

/// A payment method, as `detach` returns it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PaymentMethod {
    pub id: String,
    pub customer: Option<String>,
}

/// The current phase's window of a subscription schedule, Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct PhaseWindow {
    pub start_date: i64,
    pub end_date: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SchedulePhaseItem {
    /// A `price_...` id (never expanded by this client).
    pub price: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SchedulePhase {
    pub start_date: i64,
    pub end_date: Option<i64>,
    #[serde(default)]
    pub items: Vec<SchedulePhaseItem>,
    pub proration_behavior: Option<String>,
}

/// A subscription schedule: the subscription's items phase by phase, each
/// phase switching in at an exact time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SubscriptionSchedule {
    pub id: String,
    /// `not_started`, `active`, `completed`, `released` or `canceled`.
    pub status: String,
    pub subscription: Option<String>,
    pub current_phase: Option<PhaseWindow>,
    #[serde(default)]
    pub phases: Vec<SchedulePhase>,
    pub end_behavior: Option<String>,
}

impl SubscriptionSchedule {
    /// Whether the schedule still manages its subscription and can be
    /// updated.
    pub fn is_open(&self) -> bool {
        matches!(self.status.as_str(), "not_started" | "active")
    }
}

/// An invoice, with the fields invoicing reads.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Invoice {
    pub id: String,
    /// A `cus_...` id (never expanded by this client).
    pub customer: Option<String>,
    /// `draft`, `open`, `paid`, `uncollectible` or `void`.
    pub status: Option<String>,
    /// Whether Stripe advances the invoice on its own (finalizes a draft,
    /// then collects it).
    #[serde(default)]
    pub auto_advance: Option<bool>,
    /// e.g. `subscription_cycle`, `subscription_create`, `manual`.
    pub billing_reason: Option<String>,
    /// The usage period the invoice bills, Unix seconds. For a subscription
    /// invoice it looks back one period: an invoice made at 00:00 UTC on
    /// 1 November has `period_end` at that instant.
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
}

/// Stripe's acknowledgement of a meter event.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MeterEventRecord {
    pub event_name: String,
    pub identifier: String,
    pub timestamp: i64,
}

// ---------------------------------------------------------------- parameters

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateCustomer {
    pub email: Option<String>,
    pub name: Option<String>,
    pub metadata: Metadata,
}

/// Which payment methods a setup-mode Checkout Session offers. Stripe needs
/// one or the other in setup mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupPaymentMethods {
    /// Let Stripe choose dynamically for this three-letter currency (`usd`).
    Currency(String),
    /// An explicit list, e.g. `["card"]`. Must not be empty.
    Types(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSetupCheckoutSession {
    /// `cus_...`
    pub customer: String,
    pub payment_methods: SetupPaymentMethods,
    pub success_url: String,
    pub cancel_url: String,
    /// Sent as `metadata[org_id]`, so the completion webhook can be tied back
    /// to the org.
    pub org_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMeter {
    pub display_name: String,
    /// See [`super::meter_event_name`].
    pub event_name: String,
}

/// Where a tier ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierUpTo {
    /// Up to and including this many units. At least 1.
    Units(u64),
    /// No upper bound. Only the last tier, which must have it.
    Inf,
}

/// One graduated tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceTier {
    pub up_to: TierUpTo,
    /// Per-unit price in millionths of a cent; converted exactly to
    /// `unit_amount_decimal`.
    pub unit_amount_ucents: i64,
}

/// The product a new price belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriceProduct {
    /// An existing `prod_...`.
    Id(String),
    /// Create one inline (`product_data[name]`).
    New { name: String },
}

/// A monthly metered price with graduated tiers, tied to a billing meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMeteredPrice {
    /// Three-letter ISO code, lowercase (`usd`).
    pub currency: String,
    pub product: PriceProduct,
    /// `mtr_...`
    pub meter: String,
    pub tiers: Vec<PriceTier>,
    pub lookup_key: Option<String>,
    pub nickname: Option<String>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSubscription {
    /// `cus_...`
    pub customer: String,
    /// One item per price (`price_...`). Metered items take no quantity.
    pub prices: Vec<String>,
    /// When the first full period starts. Proration is always off.
    pub billing_cycle_anchor: Option<DateTime<Utc>>,
    /// Start the subscription in the past (`backdate_start_date`), so its
    /// first period covers metered usage from then on. Must be before now
    /// and before `billing_cycle_anchor`.
    pub backdate_start_date: Option<DateTime<Utc>>,
    pub metadata: Metadata,
}

/// One phase of an [`UpdateSchedule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulePhaseParams {
    /// Only the first phase may name its start, and when updating a running
    /// schedule it must be the current phase's start exactly. Later phases
    /// start where the previous one ends.
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: DateTime<Utc>,
    /// One item per price (`price_...`); metered items take no quantity.
    pub prices: Vec<String>,
}

/// The whole phase list of a schedule. Sent with `end_behavior=release` (the
/// subscription carries on with the last phase's items after it) and
/// `proration_behavior=none`, at the top level and on every phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSchedule {
    pub phases: Vec<SchedulePhaseParams>,
}

/// One usage report for a meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterEvent {
    /// The meter's `event_name`.
    pub event_name: String,
    /// `cus_...`, sent as `payload[stripe_customer_id]`.
    pub stripe_customer_id: String,
    /// Units, sent as `payload[value]`. Must not be negative.
    pub value: i64,
    /// Stripe dedupes on this (1 to 100 characters).
    pub identifier: String,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------- validation

fn invalid(msg: impl Into<String>) -> StripeError {
    StripeError::InvalidRequest(msg.into())
}

/// A Stripe object id that is safe to put in a URL path: 1 to 255 of
/// `[A-Za-z0-9_]`.
fn check_id(what: &str, id: &str) -> Result<(), StripeError> {
    if id.is_empty()
        || id.len() > 255
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid(format!("{what} is not a valid Stripe id")));
    }
    Ok(())
}

/// Refuse an event name Stripe would reject or that is plainly not one this
/// crate produced (e.g. a raw `service/meter` key).
fn check_event_name(name: &str) -> Result<(), StripeError> {
    if !is_event_name_shaped(name) {
        return Err(invalid(
            "event_name must be 1 to 100 of [a-z0-9_]; map meter keys with meter_event_name",
        ));
    }
    Ok(())
}

fn push_metadata(form: &mut Form, metadata: &Metadata) -> Result<(), StripeError> {
    for (k, v) in metadata {
        // A bracket would change the nesting of the form key.
        if k.is_empty() || k.contains(['[', ']']) {
            return Err(invalid("metadata keys must be non-empty and bracket-free"));
        }
        form.push(format!("metadata[{k}]"), v.as_str());
    }
    Ok(())
}

fn push_tiers(form: &mut Form, tiers: &[PriceTier]) -> Result<(), StripeError> {
    let Some((last, init)) = tiers.split_last() else {
        return Err(invalid("a tiered price needs at least one tier"));
    };
    if last.up_to != TierUpTo::Inf {
        return Err(invalid("the last tier must be unbounded"));
    }
    let mut prev = 0u64;
    for t in init {
        match t.up_to {
            TierUpTo::Units(n) if n > prev => prev = n,
            TierUpTo::Units(_) => {
                return Err(invalid(
                    "tier bounds must be at least 1 and strictly increasing",
                ))
            }
            TierUpTo::Inf => return Err(invalid("only the last tier may be unbounded")),
        }
    }
    for (i, t) in tiers.iter().enumerate() {
        let up_to = match t.up_to {
            TierUpTo::Units(n) => n.to_string(),
            TierUpTo::Inf => "inf".to_owned(),
        };
        form.push(format!("tiers[{i}][up_to]"), up_to);
        form.push(
            format!("tiers[{i}][unit_amount_decimal]"),
            ucents_to_unit_amount_decimal(t.unit_amount_ucents)?,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- calls

impl Client {
    /// `POST /v1/customers`
    pub async fn create_customer(
        &self,
        params: &CreateCustomer,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Customer, StripeError> {
        let mut form = Form::default();
        form.push_opt("email", params.email.as_deref());
        form.push_opt("name", params.name.as_deref());
        push_metadata(&mut form, &params.metadata)?;
        self.post("/v1/customers", form, idempotency_key).await
    }

    /// `POST /v1/checkout/sessions` in `setup` mode: collect a payment method
    /// for later off-session charges.
    pub async fn create_setup_checkout_session(
        &self,
        params: &CreateSetupCheckoutSession,
        idempotency_key: &IdempotencyKey,
    ) -> Result<CheckoutSession, StripeError> {
        check_id("customer", &params.customer)?;
        let mut form = Form::default();
        form.push("mode", "setup");
        form.push("customer", params.customer.as_str());
        match &params.payment_methods {
            SetupPaymentMethods::Currency(c) => form.push("currency", c.as_str()),
            SetupPaymentMethods::Types(types) => {
                if types.is_empty() {
                    return Err(invalid("payment_method_types must not be empty"));
                }
                for (i, t) in types.iter().enumerate() {
                    form.push(format!("payment_method_types[{i}]"), t.as_str());
                }
            }
        }
        form.push("success_url", params.success_url.as_str());
        form.push("cancel_url", params.cancel_url.as_str());
        form.push("metadata[org_id]", params.org_id.as_str());
        self.post("/v1/checkout/sessions", form, idempotency_key)
            .await
    }

    /// `GET /v1/setup_intents/{id}`
    pub async fn retrieve_setup_intent(&self, id: &str) -> Result<SetupIntent, StripeError> {
        check_id("setup intent", id)?;
        self.get(&format!("/v1/setup_intents/{id}")).await
    }

    /// `POST /v1/customers/{id}` setting
    /// `invoice_settings[default_payment_method]`, which subscriptions charge.
    pub async fn set_default_payment_method(
        &self,
        customer: &str,
        payment_method: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Customer, StripeError> {
        check_id("customer", customer)?;
        check_id("payment method", payment_method)?;
        let mut form = Form::default();
        form.push("invoice_settings[default_payment_method]", payment_method);
        self.post(&format!("/v1/customers/{customer}"), form, idempotency_key)
            .await
    }

    /// `POST /v1/billing/meters`: a meter that sums `payload[value]` per
    /// customer, mapped by `payload[stripe_customer_id]`.
    pub async fn create_meter(
        &self,
        params: &CreateMeter,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Meter, StripeError> {
        check_event_name(&params.event_name)?;
        let mut form = Form::default();
        form.push("display_name", params.display_name.as_str());
        form.push("event_name", params.event_name.as_str());
        form.push("default_aggregation[formula]", "sum");
        form.push("customer_mapping[type]", "by_id");
        form.push("customer_mapping[event_payload_key]", "stripe_customer_id");
        form.push("value_settings[event_payload_key]", "value");
        self.post("/v1/billing/meters", form, idempotency_key).await
    }

    /// `POST /v1/prices`: monthly, metered by `meter`, graduated tiers priced
    /// with `unit_amount_decimal`.
    pub async fn create_metered_price(
        &self,
        params: &CreateMeteredPrice,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Price, StripeError> {
        check_id("meter", &params.meter)?;
        let mut form = Form::default();
        form.push("currency", params.currency.as_str());
        match &params.product {
            PriceProduct::Id(id) => {
                check_id("product", id)?;
                form.push("product", id.as_str());
            }
            PriceProduct::New { name } => form.push("product_data[name]", name.as_str()),
        }
        form.push("billing_scheme", "tiered");
        form.push("tiers_mode", "graduated");
        form.push("recurring[interval]", "month");
        form.push("recurring[usage_type]", "metered");
        form.push("recurring[meter]", params.meter.as_str());
        push_tiers(&mut form, &params.tiers)?;
        form.push_opt("lookup_key", params.lookup_key.as_deref());
        form.push_opt("nickname", params.nickname.as_deref());
        push_metadata(&mut form, &params.metadata)?;
        self.post("/v1/prices", form, idempotency_key).await
    }

    /// `POST /v1/subscriptions` with `proration_behavior=none`.
    pub async fn create_subscription(
        &self,
        params: &CreateSubscription,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Subscription, StripeError> {
        check_id("customer", &params.customer)?;
        if params.prices.is_empty() {
            return Err(invalid("a subscription needs at least one item"));
        }
        let mut form = Form::default();
        form.push("customer", params.customer.as_str());
        for (i, price) in params.prices.iter().enumerate() {
            check_id("price", price)?;
            form.push(format!("items[{i}][price]"), price.as_str());
        }
        if let Some(anchor) = params.billing_cycle_anchor {
            form.push("billing_cycle_anchor", anchor.timestamp().to_string());
        }
        if let Some(start) = params.backdate_start_date {
            if params
                .billing_cycle_anchor
                .is_some_and(|anchor| anchor <= start)
            {
                return Err(invalid(
                    "backdate_start_date must be before billing_cycle_anchor",
                ));
            }
            form.push("backdate_start_date", start.timestamp().to_string());
        }
        form.push("proration_behavior", "none");
        push_metadata(&mut form, &params.metadata)?;
        self.post("/v1/subscriptions", form, idempotency_key).await
    }

    /// `POST /v1/subscription_items`: add a price to a subscription, without
    /// proration.
    pub async fn add_subscription_item(
        &self,
        subscription: &str,
        price: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<SubscriptionItem, StripeError> {
        check_id("subscription", subscription)?;
        check_id("price", price)?;
        let mut form = Form::default();
        form.push("subscription", subscription);
        form.push("price", price);
        form.push("proration_behavior", "none");
        self.post("/v1/subscription_items", form, idempotency_key)
            .await
    }

    /// `POST /v1/subscription_items/{id}`: move an item to another price,
    /// without proration.
    pub async fn change_subscription_item_price(
        &self,
        item: &str,
        price: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<SubscriptionItem, StripeError> {
        check_id("subscription item", item)?;
        check_id("price", price)?;
        let mut form = Form::default();
        form.push("price", price);
        form.push("proration_behavior", "none");
        self.post(
            &format!("/v1/subscription_items/{item}"),
            form,
            idempotency_key,
        )
        .await
    }

    /// `GET /v1/subscriptions/{id}`
    pub async fn retrieve_subscription(&self, id: &str) -> Result<Subscription, StripeError> {
        check_id("subscription", id)?;
        self.get(&format!("/v1/subscriptions/{id}")).await
    }

    /// `DELETE /v1/subscriptions/{id}` with `invoice_now=true` and
    /// `prorate=false`: cancel the subscription now and invoice its unbilled
    /// usage at once, without prorating credits.
    pub async fn cancel_subscription_invoice_now(
        &self,
        id: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Subscription, StripeError> {
        check_id("subscription", id)?;
        let mut form = Form::default();
        form.push("invoice_now", "true");
        form.push("prorate", "false");
        self.delete(&format!("/v1/subscriptions/{id}"), form, idempotency_key)
            .await
    }

    /// `GET /v1/subscriptions?customer=...&status=all`: every subscription of
    /// one customer, whatever its status (one page of up to 100).
    pub async fn list_subscriptions(
        &self,
        customer: &str,
    ) -> Result<List<Subscription>, StripeError> {
        check_id("customer", customer)?;
        self.get(&format!(
            "/v1/subscriptions?customer={customer}&status=all&limit=100"
        ))
        .await
    }

    /// `GET /v1/subscription_items?subscription=...`: every item (Stripe
    /// allows at most 20, so one page of 100 is all of them).
    pub async fn list_subscription_items(
        &self,
        subscription: &str,
    ) -> Result<List<SubscriptionItem>, StripeError> {
        check_id("subscription", subscription)?;
        self.get(&format!(
            "/v1/subscription_items?subscription={subscription}&limit=100"
        ))
        .await
    }

    /// `GET /v1/customers/search` for `metadata['<key>']:'<value>'`.
    ///
    /// Stripe's search is eventually consistent (a customer created in the
    /// last minute may be missing). `key` and `value` are restricted to
    /// `[A-Za-z0-9_-]` so nothing can change the query's meaning.
    pub async fn search_customers_by_metadata(
        &self,
        key: &str,
        value: &str,
    ) -> Result<List<Customer>, StripeError> {
        let plain = |s: &str| {
            !s.is_empty()
                && s.len() <= 100
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        if !plain(key) || !plain(value) {
            return Err(invalid(
                "metadata search terms must be 1 to 100 of [A-Za-z0-9_-]",
            ));
        }
        let query =
            serde_urlencoded::to_string([("query", format!("metadata['{key}']:'{value}'"))])
                .map_err(|e| invalid(format!("query encoding: {e}")))?;
        self.get(&format!("/v1/customers/search?{query}&limit=100"))
            .await
    }

    /// `GET /v1/billing/meters?status=active`, one page of up to 100, after
    /// `starting_after` (a `mtr_...`) when given.
    pub async fn list_meters(
        &self,
        starting_after: Option<&str>,
    ) -> Result<List<Meter>, StripeError> {
        let mut path = "/v1/billing/meters?status=active&limit=100".to_owned();
        if let Some(after) = starting_after {
            check_id("meter", after)?;
            path.push_str(&format!("&starting_after={after}"));
        }
        self.get(&path).await
    }

    /// `POST /v1/payment_methods/{id}/detach`
    pub async fn detach_payment_method(
        &self,
        payment_method: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<PaymentMethod, StripeError> {
        check_id("payment method", payment_method)?;
        self.post(
            &format!("/v1/payment_methods/{payment_method}/detach"),
            Form::default(),
            idempotency_key,
        )
        .await
    }

    /// `POST /v1/subscription_schedules` with `from_subscription`: put an
    /// existing subscription under a schedule whose one phase is what it has
    /// now.
    pub async fn create_schedule_from_subscription(
        &self,
        subscription: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<SubscriptionSchedule, StripeError> {
        check_id("subscription", subscription)?;
        let mut form = Form::default();
        form.push("from_subscription", subscription);
        self.post("/v1/subscription_schedules", form, idempotency_key)
            .await
    }

    /// `GET /v1/subscription_schedules/{id}`
    pub async fn retrieve_schedule(&self, id: &str) -> Result<SubscriptionSchedule, StripeError> {
        check_id("subscription schedule", id)?;
        self.get(&format!("/v1/subscription_schedules/{id}")).await
    }

    /// `POST /v1/subscription_schedules/{id}`: replace the phase list. See
    /// [`UpdateSchedule`].
    pub async fn update_schedule(
        &self,
        id: &str,
        params: &UpdateSchedule,
        idempotency_key: &IdempotencyKey,
    ) -> Result<SubscriptionSchedule, StripeError> {
        check_id("subscription schedule", id)?;
        if params.phases.is_empty() {
            return Err(invalid("a schedule needs at least one phase"));
        }
        let mut form = Form::default();
        form.push("end_behavior", "release");
        form.push("proration_behavior", "none");
        let mut previous_end: Option<DateTime<Utc>> = None;
        for (i, phase) in params.phases.iter().enumerate() {
            if i > 0 && phase.start_date.is_some() {
                return Err(invalid("only the first phase may name its start"));
            }
            if phase.prices.is_empty() {
                return Err(invalid("every phase needs at least one item"));
            }
            let start = phase.start_date.or(previous_end);
            if start.is_some_and(|s| phase.end_date <= s) {
                return Err(invalid("each phase must end after it starts"));
            }
            if let Some(start) = phase.start_date {
                form.push(
                    format!("phases[{i}][start_date]"),
                    start.timestamp().to_string(),
                );
            }
            form.push(
                format!("phases[{i}][end_date]"),
                phase.end_date.timestamp().to_string(),
            );
            form.push(format!("phases[{i}][proration_behavior]"), "none");
            for (j, price) in phase.prices.iter().enumerate() {
                check_id("price", price)?;
                form.push(format!("phases[{i}][items][{j}][price]"), price.as_str());
            }
            previous_end = Some(phase.end_date);
        }
        self.post(
            &format!("/v1/subscription_schedules/{id}"),
            form,
            idempotency_key,
        )
        .await
    }

    /// `POST /v1/subscription_schedules/{id}/release`: stop managing the
    /// subscription, which keeps its current items.
    pub async fn release_schedule(
        &self,
        id: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<SubscriptionSchedule, StripeError> {
        check_id("subscription schedule", id)?;
        self.post(
            &format!("/v1/subscription_schedules/{id}/release"),
            Form::default(),
            idempotency_key,
        )
        .await
    }

    /// `GET /v1/invoices/{id}`
    pub async fn retrieve_invoice(&self, id: &str) -> Result<Invoice, StripeError> {
        check_id("invoice", id)?;
        self.get(&format!("/v1/invoices/{id}")).await
    }

    /// `POST /v1/invoices/{id}` setting `auto_advance`: `false` keeps a draft
    /// invoice a draft until it is finalized explicitly.
    pub async fn set_invoice_auto_advance(
        &self,
        id: &str,
        auto_advance: bool,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Invoice, StripeError> {
        check_id("invoice", id)?;
        let mut form = Form::default();
        form.push("auto_advance", auto_advance.to_string());
        self.post(&format!("/v1/invoices/{id}"), form, idempotency_key)
            .await
    }

    /// `DELETE /v1/invoices/{id}`: delete a draft invoice. Stripe refuses any
    /// invoice that is not a draft.
    pub async fn delete_draft_invoice(
        &self,
        id: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<serde_json::Value, StripeError> {
        check_id("invoice", id)?;
        self.delete(
            &format!("/v1/invoices/{id}"),
            Form::default(),
            idempotency_key,
        )
        .await
    }

    /// `POST /v1/invoices/{id}/finalize`: turn a draft into an open invoice,
    /// with `auto_advance` deciding whether Stripe then collects it on its
    /// own.
    pub async fn finalize_invoice(
        &self,
        id: &str,
        auto_advance: bool,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Invoice, StripeError> {
        check_id("invoice", id)?;
        let mut form = Form::default();
        form.push("auto_advance", auto_advance.to_string());
        self.post(
            &format!("/v1/invoices/{id}/finalize"),
            form,
            idempotency_key,
        )
        .await
    }

    /// `POST /v1/billing/meter_events`.
    ///
    /// Stripe dedupes on `identifier` as well as on the idempotency key; use
    /// the same stable value for both when shipping from an outbox.
    pub async fn send_meter_event(
        &self,
        event: &MeterEvent,
        idempotency_key: &IdempotencyKey,
    ) -> Result<MeterEventRecord, StripeError> {
        check_event_name(&event.event_name)?;
        check_id("customer", &event.stripe_customer_id)?;
        if event.value < 0 {
            return Err(invalid("meter event value must not be negative"));
        }
        if event.identifier.is_empty() || event.identifier.len() > 100 {
            return Err(invalid(
                "meter event identifier must be 1 to 100 characters",
            ));
        }
        let mut form = Form::default();
        form.push("event_name", event.event_name.as_str());
        form.push(
            "payload[stripe_customer_id]",
            event.stripe_customer_id.as_str(),
        );
        form.push("payload[value]", event.value.to_string());
        form.push("identifier", event.identifier.as_str());
        form.push("timestamp", event.timestamp.timestamp().to_string());
        self.post("/v1/billing/meter_events", form, idempotency_key)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(up_to: TierUpTo, ucents: i64) -> PriceTier {
        PriceTier {
            up_to,
            unit_amount_ucents: ucents,
        }
    }

    fn tiers(t: &[PriceTier]) -> Result<Form, StripeError> {
        let mut f = Form::default();
        push_tiers(&mut f, t).map(|()| f)
    }

    #[test]
    fn tier_validation() {
        use TierUpTo::*;
        assert!(tiers(&[]).is_err());
        assert!(tiers(&[tier(Units(10), 1)]).is_err(), "last must be inf");
        assert!(
            tiers(&[tier(Inf, 1), tier(Inf, 1)]).is_err(),
            "inf only last"
        );
        assert!(
            tiers(&[tier(Units(0), 1), tier(Inf, 1)]).is_err(),
            "up_to >= 1"
        );
        assert!(
            tiers(&[tier(Units(10), 1), tier(Units(10), 1), tier(Inf, 1)]).is_err(),
            "strictly increasing"
        );
        assert!(
            tiers(&[tier(Units(10), -1), tier(Inf, 1)]).is_err(),
            "negative price"
        );
        assert!(tiers(&[tier(Inf, 0)]).is_ok());
        assert!(tiers(&[tier(Units(1), 5), tier(Units(2), 4), tier(Inf, 3)]).is_ok());
    }

    #[test]
    fn id_validation() {
        assert!(check_id("x", "cus_ABC123").is_ok());
        for bad in [
            "",
            "cus/../x",
            "cus_1?x=1",
            "cus 1",
            "cus%2F",
            &"a".repeat(256),
        ] {
            assert!(check_id("x", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn metadata_keys_cannot_nest() {
        let mut f = Form::default();
        let m: Metadata = [("a]b[c".to_owned(), "v".to_owned())].into();
        assert!(push_metadata(&mut f, &m).is_err());
    }
}
