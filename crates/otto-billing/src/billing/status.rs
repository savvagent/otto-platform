//! Reading an org's billing state.

use chrono::{DateTime, Utc};
use otto_tenant::Tx;
use serde::Serialize;

use super::{read_row_in, Error, Result, LIVE_STATUSES};

/// Whether the org has a usable card on file. Stored as
/// `subscriptions.payment_method_status`, a CHECKed vocabulary (0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethodStatus {
    /// No card has ever been put on file.
    None,
    /// A card is on file and is the Stripe customer's default.
    Active,
    /// Stripe could not collect an invoice with the card on file.
    Failed,
    /// The card was removed from the Stripe customer.
    Detached,
}

impl PaymentMethodStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Detached => "detached",
        }
    }

    pub(super) fn parse(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "active" => Ok(Self::Active),
            "failed" => Ok(Self::Failed),
            "detached" => Ok(Self::Detached),
            // Unreachable while the CHECK holds.
            other => Err(Error::Unexpected(format!(
                "stored payment_method_status {other:?}"
            ))),
        }
    }
}

/// Whether a Stripe subscription status is one of [`LIVE_STATUSES`].
pub fn is_live_status(status: &str) -> bool {
    LIVE_STATUSES.contains(&status)
}

/// An org's Stripe subscription, as last reported by Stripe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionState {
    pub stripe_subscription_id: String,
    pub status: String,
}

impl SubscriptionState {
    pub fn is_live(&self) -> bool {
        is_live_status(&self.status)
    }
}

/// Where an org's billing stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingStatus {
    pub stripe_customer_id: Option<String>,
    pub payment_method: PaymentMethodStatus,
    /// When `payment_method` became what it is (the Stripe event that set
    /// it); `None` before any card.
    pub payment_method_since: Option<DateTime<Utc>>,
    pub subscription: Option<SubscriptionState>,
    /// When the subscription became `past_due`, while it is; `None`
    /// otherwise.
    pub past_due_since: Option<DateTime<Utc>>,
    /// Stripe deleted the subscription; nothing re-subscribes the org until
    /// its owner puts a card on file again.
    pub stopped: bool,
}

/// What metered-usage shipping (#64) needs about an org: its Stripe customer
/// and its live subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSubscription {
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub status: String,
}

/// The org's billing state. An org that never started setup has no customer,
/// no card and no subscription.
pub async fn status(tx: &mut Tx<'_>) -> Result<BillingStatus> {
    Ok(match read_row_in(tx).await? {
        Some(row) => BillingStatus {
            stripe_customer_id: row.stripe_customer_id.clone(),
            payment_method: row.card()?,
            payment_method_since: row.payment_method_event_at,
            subscription: row.subscription(),
            past_due_since: row
                .past_due_since
                .filter(|_| row.status == "past_due" && row.stripe_subscription_id.is_some()),
            stopped: row.billing_stopped_at.is_some(),
        },
        None => BillingStatus {
            stripe_customer_id: None,
            payment_method: PaymentMethodStatus::None,
            payment_method_since: None,
            subscription: None,
            past_due_since: None,
            stopped: false,
        },
    })
}

/// The org's Stripe customer and subscription, when the subscription is live
/// ([`LIVE_STATUSES`]). `None` for an org with no subscription or a dead one:
/// its usage is not billed through Stripe.
pub async fn live_subscription(tx: &mut Tx<'_>) -> Result<Option<LiveSubscription>> {
    let Some(row) = read_row_in(tx).await? else {
        return Ok(None);
    };
    Ok(
        match (row.stripe_customer_id.clone(), row.live_subscription()) {
            (Some(customer), Some(sub)) => Some(LiveSubscription {
                stripe_customer_id: customer,
                stripe_subscription_id: sub.stripe_subscription_id,
                status: sub.status,
            }),
            _ => None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn live_statuses() {
        for s in ["active", "trialing", "past_due", "unpaid"] {
            assert!(is_live_status(s), "{s}");
        }
        for s in ["canceled", "incomplete", "incomplete_expired", "paused", ""] {
            assert!(!is_live_status(s), "{s}");
        }
    }

    #[test]
    fn card_status_round_trips() {
        for s in [
            PaymentMethodStatus::None,
            PaymentMethodStatus::Active,
            PaymentMethodStatus::Failed,
            PaymentMethodStatus::Detached,
        ] {
            assert_eq!(PaymentMethodStatus::parse(s.as_str()).unwrap(), s);
            assert_eq!(serde_json::to_value(s).unwrap(), json!(s.as_str()));
        }
        assert!(PaymentMethodStatus::parse("maybe").is_err());
    }
}
