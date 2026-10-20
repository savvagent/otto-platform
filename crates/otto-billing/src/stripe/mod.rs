//! A small, hand-written Stripe client: just the calls pay-as-you-go billing
//! needs, on `reqwest`, with no Stripe SDK.
//!
//! - [`Client`] sends form-encoded requests pinned to [`STRIPE_VERSION`].
//!   Every POST takes an [`IdempotencyKey`], so a retried call can never act
//!   twice. Callers that retry must reuse the key they first sent.
//! - [`SecretKey`] and [`WebhookSecret`] redact themselves in `Debug` and
//!   `Display`, and [`StripeError`] scrubs the key out of anything Stripe
//!   echoes back.
//! - [`meter_event_name`] maps a platform meter key `<service>/<meter>` to a
//!   Stripe meter event name, injectively.
//! - [`verify_webhook`] checks a `Stripe-Signature` header and returns the
//!   event envelope.
//!
//! Money: platform prices are integers in millionths of a cent ("ucents").
//! [`ucents_to_unit_amount_decimal`] converts them exactly to Stripe's
//! `unit_amount_decimal` (cents, as a decimal string). No floats anywhere.
//!
//! This module performs no retries and holds no configuration: the caller
//! decides when to call, with which key, and against which base URL.

mod api;
mod client;
mod error;
mod event_name;
mod money;
mod secret;
mod webhook;

#[cfg(test)]
mod tests;

pub use api::{
    CheckoutSession, CreateCustomer, CreateMeter, CreateMeteredPrice, CreateSetupCheckoutSession,
    CreateSubscription, Customer, InvoiceSettings, List, Meter, MeterEvent, MeterEventRecord,
    Price, PriceProduct, PriceTier, Recurring, SetupIntent, SetupPaymentMethods, Subscription,
    SubscriptionItem, TierUpTo,
};
pub use client::{Client, DEFAULT_BASE_URL, MAX_RESPONSE_BYTES, STRIPE_VERSION};
pub use error::{ApiError, StripeError};
pub use event_name::{meter_event_name, parse_meter_event_name, EventNameError};
pub use money::ucents_to_unit_amount_decimal;
pub use secret::{IdempotencyKey, SecretKey, WebhookSecret};
pub use webhook::{
    sign_webhook, verify_webhook, verify_webhook_at, EventData, WebhookError, WebhookEvent,
    MAX_SIGNATURES, MAX_SIGNATURE_HEADER_BYTES, SIGNATURE_HEADER, TOLERANCE_SECS,
};
