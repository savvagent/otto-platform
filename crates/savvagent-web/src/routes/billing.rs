//! The org's billing: whether a card is on file, the Stripe subscription's
//! status, and putting a card on file.
//!
//! **Owner-only, reads included** (`Role::can_own`): billing is what an owner
//! answers for, and the card status of an org is not a member's business.
//!
//! **Billing may be off.** With no Stripe secrets the deployment runs without
//! billing: `GET` says `billingEnabled: false` and `POST …/setup` answers
//! `503 billing_disabled`. Nothing else about the org changes.
//!
//! A card goes on file through Stripe Checkout, never through this server: the
//! card number is typed into Stripe's page, and Stripe tells us the outcome on
//! the webhook ([`super::stripe_webhook`]). All SQL and every Stripe call are
//! in `savvagent_billing::billing`.

use axum::extract::{Json, State};
use http::request::Parts;
use http::StatusCode;
use savvagent_billing::billing::{self, PaymentMethodStatus, SetupParams};
use savvagent_tenant::audit::Entry;
use serde::Serialize;

use crate::error::{ApiError, ApiResult};
use crate::session::OrgCtx;
use crate::state::{client_ip, AppState};

/// The wire shape of `GET /api/orgs/{org}/billing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingStatusView {
    /// Whether this deployment bills through Stripe at all.
    pub billing_enabled: bool,
    pub card_status: PaymentMethodStatus,
    /// The Stripe subscription's status (`active`, `past_due`, `canceled`,
    /// ...), or `None` when the org has no subscription.
    pub subscription_status: Option<String>,
    /// Whether the subscription is one usage is invoiced through.
    pub subscription_live: bool,
    /// Stripe canceled the subscription; billing resumes only when an owner
    /// puts a card on file again.
    pub billing_stopped: bool,
}

/// The wire shape of `POST /api/orgs/{org}/billing/setup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupSession {
    /// Stripe Checkout, in setup mode. Send the owner here.
    pub url: String,
}

/// `503 billing_disabled`.
pub fn billing_disabled() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "billing_disabled",
        "billing is not enabled on this deployment",
    )
}

/// A billing failure, for a console caller. Stripe's and the database's own
/// words are logged, never sent.
pub(crate) fn from_billing(context: &str, e: billing::Error) -> ApiError {
    match e {
        billing::Error::Tenant(inner) => ApiError::from(inner),
        billing::Error::Busy(_) | billing::Error::LeaseLost(_) => ApiError::conflict(
            "billing_busy",
            "another billing change for this org is in progress; try again shortly",
        ),
        billing::Error::Stripe(_) | billing::Error::Unexpected(_) => {
            tracing::error!(error = %e, context, "Stripe request failed");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "stripe_unavailable",
                "the payment provider could not complete this right now; try again shortly",
            )
        }
        other => ApiError::internal(context, other),
    }
}

/// `GET /api/orgs/{org}/billing` — card and subscription status.
pub async fn get_billing(
    State(state): State<AppState>,
    ctx: OrgCtx,
) -> ApiResult<Json<BillingStatusView>> {
    ctx.require_owner()?;
    let mut tx = state.db.begin(ctx.org.id).await?;
    let status = billing::status(&mut tx)
        .await
        .map_err(|e| from_billing("read billing status", e))?;
    tx.commit().await?;
    Ok(Json(BillingStatusView {
        billing_enabled: state.stripe.is_some(),
        card_status: status.payment_method,
        subscription_live: status
            .subscription
            .as_ref()
            .is_some_and(billing::SubscriptionState::is_live),
        subscription_status: status.subscription.map(|s| s.status),
        billing_stopped: status.stopped,
    }))
}

/// `POST /api/orgs/{org}/billing/setup` — start putting a card on file.
///
/// Finds or creates the org's Stripe customer (named for the org, with the
/// requesting owner's email) and returns a Stripe Checkout URL in setup mode,
/// for cards only. Returning from Checkout lands on the console's billing page with
/// `?setup=success` or `?setup=cancelled`; whether a card is actually on file
/// is what Stripe later reports on the webhook, not the redirect.
pub async fn start_setup(
    State(state): State<AppState>,
    ctx: OrgCtx,
    parts: Parts,
) -> ApiResult<Json<SetupSession>> {
    ctx.require_owner()?;
    let stripe = state.stripe.clone().ok_or_else(billing_disabled)?;

    let page = format!("/o/{}/billing", ctx.org.slug);
    let audit = Entry::new(billing::actions::SETUP_STARTED)
        .actor(ctx.user.id)
        .from_request(client_ip(&parts, &state.config).as_deref(), None);
    let url = billing::start_setup(
        &state.db,
        &stripe.client,
        SetupParams {
            org: ctx.org.id,
            org_name: &ctx.org.name,
            owner_email: ctx.user.email.as_deref(),
            success_url: state.config.url(&format!("{page}?setup=success")),
            cancel_url: state.config.url(&format!("{page}?setup=cancelled")),
        },
        audit,
    )
    .await
    .map_err(|e| from_billing("start billing setup", e))?;
    Ok(Json(SetupSession { url }))
}
