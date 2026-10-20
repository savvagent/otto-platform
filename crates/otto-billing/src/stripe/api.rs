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
    pub metadata: Metadata,
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

    /// `POST /v1/billing/meter_events`.
    ///
    /// Stripe dedupes on `identifier` as well as on the idempotency key; use
    /// the same stable value for both when shipping from an outbox.
    pub async fn send_meter_event(
        &self,
        event: &MeterEvent,
        idempotency_key: &IdempotencyKey,
    ) -> Result<MeterEventRecord, StripeError> {
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
