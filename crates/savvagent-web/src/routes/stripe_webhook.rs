//! `POST /api/stripe/webhook` — Stripe's events about our customers.
//!
//! **Public, and authenticated by signature alone.** Stripe sends no cookie
//! and no `Origin`, so the console's cross-site guard (`crate::csrf`, which
//! only inspects cookie-bearing writes) lets it through, and nothing else
//! would identify the caller. Every delivery is checked against
//! `STRIPE_WEBHOOK_SECRET` (`Stripe-Signature`, HMAC-SHA256 over the raw body,
//! a five-minute timestamp tolerance) before its body is even parsed.
//!
//! **Bounded.** The route reads at most
//! [`MAX_WEBHOOK_PAYLOAD_BYTES`] (64 KiB) of body, the same cap the verifier
//! applies; anything larger is `413` and logged as an error, because a real
//! Stripe event that size would be one we are silently failing to handle.
//!
//! **Idempotent.** Stripe redelivers, out of order. A handled event id is in
//! the `stripe_events` ledger and a redelivery does nothing; every handler only
//! moves a status forward in event time. See `savvagent_billing::billing`.
//!
//! **Answers.** `200` for every verified event, including types billing does
//! not act on and events about customers that are not ours, so Stripe stops
//! sending them. `400` for a missing or bad signature, `413` for an oversized
//! body, `503 billing_disabled` when billing is off, and `500` when handling
//! failed (including waiting too long for another change to the same org),
//! which makes Stripe retry.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Json, State};
use http::{HeaderMap, StatusCode};
use savvagent_billing::billing::{self, EventOutcome};
use savvagent_billing::stripe::{verify_webhook, WebhookError, SIGNATURE_HEADER};
use serde::Serialize;

pub use savvagent_billing::stripe::MAX_WEBHOOK_PAYLOAD_BYTES;

use crate::error::{ApiError, ApiResult};
use crate::routes::billing::billing_disabled;
use crate::state::AppState;

/// The wire shape of a `200`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Received {
    pub received: bool,
}

fn too_large() -> ApiError {
    tracing::error!(
        limit = MAX_WEBHOOK_PAYLOAD_BYTES,
        "Stripe webhook refused: the body is over the limit. If this was Stripe, an event is \
         not being handled"
    );
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        "the webhook body is too large",
    )
}

fn bad_signature() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_signature",
        "the Stripe-Signature header does not verify this body",
    )
}

/// `POST /api/stripe/webhook`.
pub async fn receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult<Json<Received>> {
    let body = match body {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return Err(too_large())
        }
        Err(rejection) => {
            return Err(ApiError::bad_request(format!(
                "the webhook body could not be read: {rejection}"
            )))
        }
    };
    let stripe = state.stripe.clone().ok_or_else(billing_disabled)?;

    let Some(signature) = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok()) else {
        tracing::warn!("Stripe webhook refused: no {SIGNATURE_HEADER} header");
        return Err(bad_signature());
    };
    let event = match verify_webhook(&stripe.webhook_secret, signature, &body) {
        Ok(event) => event,
        Err(WebhookError::PayloadTooLarge) => return Err(too_large()),
        Err(WebhookError::InvalidPayload(why)) => {
            // Signed by Stripe but not an event: a Stripe change we do not
            // understand, worth an operator's look.
            tracing::error!(error = %why, "Stripe webhook refused: signed, but not an event");
            return Err(ApiError::bad_request(
                "the webhook body is not a Stripe event",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "Stripe webhook refused: signature did not verify");
            return Err(bad_signature());
        }
    };

    match billing::handle_event(&state.db, &stripe.client, &event, &body).await {
        Ok(EventOutcome::Handled) => {
            tracing::info!(event_id = %event.id, event_type = %event.event_type, "Stripe event handled");
        }
        Ok(EventOutcome::Duplicate) => {
            tracing::info!(event_id = %event.id, event_type = %event.event_type, "Stripe event already handled");
        }
        Ok(EventOutcome::Ignored(why)) => {
            tracing::info!(event_id = %event.id, event_type = %event.event_type, reason = %why, "Stripe event acknowledged with no action");
        }
        Err(e) => {
            tracing::error!(event_id = %event.id, event_type = %event.event_type, error = %e, "Stripe event not handled; Stripe will retry");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the event could not be handled; retry",
            ));
        }
    }
    Ok(Json(Received { received: true }))
}
