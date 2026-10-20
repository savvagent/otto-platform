//! Whether a service must refuse billable calls, and why: **one rule, in one
//! place**, read by both the resource servers' usage-status
//! (`otto-platform-server`'s `/internal/orgs/{org}/usage-status`) and the
//! console's usage page (`otto-web`'s `GET /api/orgs/{org}/usage`), so the
//! two can never disagree about whether an org is blocked or why.
//!
//! [`blocked_reason`] answers, per service and period:
//!
//! 1. [`BUDGET_EXCEEDED`] when the service's budget has its hard stop on and
//!    spend has reached it ([`ServiceBudgetStatus::blocked`]). It wins over
//!    everything else.
//! 2. [`PAYMENT_REQUIRED`] when billing is enabled, the org is not in good
//!    [`Standing`] to pay, and the service's spend this period is known and
//!    above zero (past its free tiers).
//! 3. Nothing otherwise. Unknown spend never blocks: enforcement fails open.
//!
//! **Standing** ([`standing_of`]) is about paying, not about whether usage is
//! queued for Stripe. Metered usage of any subscription Stripe still invoices
//! ([`super::LIVE_STATUSES`], `past_due` and `unpaid` included) keeps being
//! queued, so it is invoiced if the card recovers; what changes with
//! standing is only whether more billable use is allowed. An org is in good
//! standing when
//!
//! - its subscription is `active` or `trialing`, or `past_due` for less than
//!   [`PAYMENT_GRACE`] (counted from when it became `past_due`); `unpaid`
//!   (Stripe gave up retrying), `canceled`, `incomplete`, no subscription at
//!   all, and `past_due` past the grace are not; and
//! - its card is not `failed` or `detached` for [`PAYMENT_GRACE`] or longer
//!   (counted from when it became so). A failed or detached card inside the
//!   grace is fine, as is no card recorded on a subscription that is itself
//!   in good standing.
//!
//! With billing disabled nobody can put a card on file, so every org is in
//! good standing and only a budget's hard stop can block.
//!
//! ```
//! use chrono::{Duration, Utc};
//! use otto_billing::billing::gate::{standing_of, Billing, Standing, PAYMENT_GRACE};
//! use otto_billing::billing::{BillingStatus, PaymentMethodStatus, SubscriptionState};
//!
//! let now = Utc::now();
//! let mut org = BillingStatus {
//!     stripe_customer_id: Some("cus_1".into()),
//!     payment_method: PaymentMethodStatus::Failed,
//!     payment_method_since: Some(now - Duration::days(2)),
//!     subscription: Some(SubscriptionState {
//!         stripe_subscription_id: "sub_1".into(),
//!         status: "past_due".into(),
//!     }),
//!     past_due_since: Some(now - Duration::days(2)),
//!     stopped: false,
//! };
//! // Two days into a failed payment: still allowed.
//! assert_eq!(standing_of(&org, Billing::Enabled, now), Standing::Good);
//! // Past the grace: payment is required.
//! let later = now + PAYMENT_GRACE;
//! assert_eq!(standing_of(&org, Billing::Enabled, later), Standing::PaymentRequired);
//! // Stripe gave up: no grace.
//! org.subscription.as_mut().unwrap().status = "unpaid".into();
//! assert_eq!(standing_of(&org, Billing::Enabled, now), Standing::PaymentRequired);
//! // Billing off: nobody could pay, so nobody is asked to.
//! assert_eq!(standing_of(&org, Billing::Disabled, later), Standing::Good);
//! ```

use chrono::{DateTime, Duration, Utc};
use otto_tenant::Tx;

use super::{status, BillingStatus, PaymentMethodStatus, Result};
use crate::budgets::{ServiceBudgetStatus, BUDGET_EXCEEDED, PAYMENT_REQUIRED};

/// **Policy.** How long an org whose payment has failed may keep running up
/// billable usage: seven days from when its subscription became `past_due`
/// (or its card `failed` or `detached`). Long enough for Stripe's first
/// retries and for an owner to notice the email and replace the card; short
/// enough that an org that never pays runs up at most a week of usage past
/// its last good invoice. Usage in the grace is still queued and invoiced.
pub const PAYMENT_GRACE: Duration = Duration::days(7);

/// Whether this deployment bills through Stripe: both Stripe secrets set.
/// Decides whether payment can ever be required: with billing off nobody can
/// put a card on file, so requiring one would lock every org out of billable
/// use the moment a price exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Billing {
    Enabled,
    Disabled,
}

impl Billing {
    /// [`Billing::Enabled`] when `enabled`.
    pub fn enabled_if(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// Whether an org may run up billable usage as far as paying for it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// It may (or billing is disabled).
    Good,
    /// It must put a working payment method on file first: billable use past
    /// the free tiers answers [`PAYMENT_REQUIRED`].
    PaymentRequired,
}

/// Whether `since` is less than [`PAYMENT_GRACE`] before `now`. An unknown
/// start is treated as long past: every writer of the statuses that have a
/// grace records when they began (migration 0021).
fn within_grace(since: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    since.is_some_and(|since| now - since < PAYMENT_GRACE)
}

/// The org's [`Standing`] at `now`, from its billing state (see the module
/// docs).
pub fn standing_of(status: &BillingStatus, billing: Billing, now: DateTime<Utc>) -> Standing {
    if billing == Billing::Disabled {
        return Standing::Good;
    }
    let subscription_ok = match status.subscription.as_ref().map(|s| s.status.as_str()) {
        Some("active" | "trialing") => true,
        Some("past_due") => within_grace(status.past_due_since, now),
        // `unpaid`, `canceled`, `incomplete`, `incomplete_expired`, `paused`,
        // anything Stripe adds later, and no subscription at all.
        _ => false,
    };
    let card_ok = match status.payment_method {
        PaymentMethodStatus::None | PaymentMethodStatus::Active => true,
        PaymentMethodStatus::Failed | PaymentMethodStatus::Detached => {
            within_grace(status.payment_method_since, now)
        }
    };
    if subscription_ok && card_ok {
        Standing::Good
    } else {
        Standing::PaymentRequired
    }
}

/// The org's [`Standing`] now, read in `tx` (pinned to the org). With billing
/// disabled it is [`Standing::Good`] without a query.
pub async fn standing(tx: &mut Tx<'_>, billing: Billing) -> Result<Standing> {
    if billing == Billing::Disabled {
        return Ok(Standing::Good);
    }
    Ok(standing_of(&status(tx).await?, billing, Utc::now()))
}

/// Whether [`blocked_reason`] for a service can depend on its spend: it has
/// a budget, or the org must pay. When it cannot, a caller need not rate
/// spend at all (so a price the rater refuses can neither fail nor degrade
/// the answer).
pub fn needs_spend(has_budget: bool, standing: Standing) -> bool {
    has_budget || standing == Standing::PaymentRequired
}

/// Why billable calls of the service `service` describes must be refused, if
/// they must: [`BUDGET_EXCEEDED`] or [`PAYMENT_REQUIRED`] (see the module
/// docs), the budget winning when both apply.
pub fn blocked_reason(service: &ServiceBudgetStatus, standing: Standing) -> Option<&'static str> {
    if service.blocked() {
        Some(BUDGET_EXCEEDED)
    } else if standing == Standing::PaymentRequired
        && service.spend_cents.is_some_and(|cents| cents > 0)
    {
        Some(PAYMENT_REQUIRED)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::SubscriptionState;
    use crate::budgets::Budget;
    use crate::period::Month;

    fn org(sub: Option<&str>, card: PaymentMethodStatus) -> BillingStatus {
        BillingStatus {
            stripe_customer_id: Some("cus_1".into()),
            payment_method: card,
            payment_method_since: None,
            subscription: sub.map(|s| SubscriptionState {
                stripe_subscription_id: "sub_1".into(),
                status: s.into(),
            }),
            past_due_since: None,
            stopped: false,
        }
    }

    fn budget(cents: i64, hard_stop: bool) -> Budget {
        Budget {
            service: "otto-flags".into(),
            monthly_budget_cents: cents,
            hard_stop,
            updated_by: None,
            updated_at: Utc::now(),
        }
    }

    fn service(spend: Option<i64>, b: Option<Budget>) -> ServiceBudgetStatus {
        ServiceBudgetStatus {
            service: "otto-flags".into(),
            period: Month::new(2026, 10).unwrap(),
            spend_cents: spend,
            thresholds_reached: vec![],
            budget: b,
        }
    }

    use PaymentMethodStatus::{Active, Detached, Failed};
    use Standing::{Good, PaymentRequired};
    const ON: Billing = Billing::Enabled;

    #[test]
    fn an_active_or_trialing_subscription_is_in_good_standing() {
        let now = Utc::now();
        for s in ["active", "trialing"] {
            assert_eq!(standing_of(&org(Some(s), Active), ON, now), Good, "{s}");
            assert_eq!(
                standing_of(&org(Some(s), PaymentMethodStatus::None), ON, now),
                Good,
                "{s}"
            );
        }
    }

    #[test]
    fn past_due_is_allowed_only_within_the_grace() {
        let now = Utc::now();
        let mut o = org(Some("past_due"), Active);
        o.past_due_since = Some(now - PAYMENT_GRACE + Duration::seconds(1));
        assert_eq!(standing_of(&o, ON, now), Good);
        o.past_due_since = Some(now - PAYMENT_GRACE);
        assert_eq!(standing_of(&o, ON, now), PaymentRequired);
        o.past_due_since = None;
        assert_eq!(standing_of(&o, ON, now), PaymentRequired, "unknown start");
    }

    #[test]
    fn unpaid_and_dead_subscriptions_require_payment_at_once() {
        let now = Utc::now();
        for s in [
            Some("unpaid"),
            Some("canceled"),
            Some("incomplete"),
            Some("incomplete_expired"),
            Some("paused"),
            Some("something_new"),
            None,
        ] {
            let mut o = org(s, Active);
            o.past_due_since = Some(now);
            assert_eq!(standing_of(&o, ON, now), PaymentRequired, "{s:?}");
        }
    }

    #[test]
    fn a_failed_or_detached_card_is_allowed_only_within_the_grace() {
        let now = Utc::now();
        for card in [Failed, Detached] {
            let mut o = org(Some("active"), card);
            o.payment_method_since = Some(now - Duration::days(1));
            assert_eq!(standing_of(&o, ON, now), Good, "{card:?}");
            o.payment_method_since = Some(now - PAYMENT_GRACE);
            assert_eq!(standing_of(&o, ON, now), PaymentRequired, "{card:?}");
            o.payment_method_since = None;
            assert_eq!(standing_of(&o, ON, now), PaymentRequired, "{card:?}");
        }
        // A failed card inside its grace does not rescue a past-due
        // subscription past its own.
        let mut o = org(Some("past_due"), Failed);
        o.payment_method_since = Some(now);
        o.past_due_since = Some(now - PAYMENT_GRACE);
        assert_eq!(standing_of(&o, ON, now), PaymentRequired);
    }

    #[test]
    fn with_billing_disabled_every_org_is_in_good_standing() {
        let now = Utc::now();
        for o in [
            org(None, PaymentMethodStatus::None),
            org(Some("unpaid"), Failed),
            org(Some("past_due"), Detached),
        ] {
            assert_eq!(standing_of(&o, Billing::Disabled, now), Good);
        }
        assert_eq!(Billing::enabled_if(true), Billing::Enabled);
        assert_eq!(Billing::enabled_if(false), Billing::Disabled);
    }

    #[test]
    fn payment_is_required_only_out_of_standing_and_past_free() {
        assert_eq!(
            blocked_reason(&service(Some(0), None), PaymentRequired),
            None,
            "free tier"
        );
        assert_eq!(
            blocked_reason(&service(Some(1), None), PaymentRequired),
            Some(PAYMENT_REQUIRED)
        );
        assert_eq!(blocked_reason(&service(Some(1), None), Good), None);
        assert_eq!(
            blocked_reason(&service(None, None), PaymentRequired),
            None,
            "unknown spend fails open"
        );
    }

    #[test]
    fn the_budgets_hard_stop_wins() {
        let over = service(Some(5_000), Some(budget(1_000, true)));
        assert_eq!(
            blocked_reason(&over, PaymentRequired),
            Some(BUDGET_EXCEEDED)
        );
        assert_eq!(blocked_reason(&over, Good), Some(BUDGET_EXCEEDED));
        let soft = service(Some(5_000), Some(budget(1_000, false)));
        assert_eq!(
            blocked_reason(&soft, PaymentRequired),
            Some(PAYMENT_REQUIRED)
        );
        assert_eq!(blocked_reason(&soft, Good), None);
        let unknown = service(None, Some(budget(1_000, true)));
        assert_eq!(blocked_reason(&unknown, PaymentRequired), None);
    }

    #[test]
    fn spend_is_needed_only_when_it_can_change_the_answer() {
        assert!(!needs_spend(false, Good));
        assert!(needs_spend(true, Good));
        assert!(needs_spend(false, PaymentRequired));
    }
}
