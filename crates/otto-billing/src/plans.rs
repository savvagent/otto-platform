//! The plan catalog: every tier on offer, as the `plans` table holds it.
//!
//! **Unpinned, not pinned.** `plans` is global reference data — it has no
//! `org_id` and no tenant-isolation policy, and the people reading it (a
//! pricing page, a visitor deciding whether to sign up) belong to no org yet.
//! A pinned [`otto_tenant::Tx`] would demand an org that does not exist, so
//! this takes an [`Unpinned`] transaction instead. It is also why the catalog
//! carries `monthly_cents` and [`crate::usage::PlanLimits`] does not: limits are
//! what one org is entitled to (after its negotiated override), the catalog is
//! what anyone is offered.
//!
//! Read-only by construction: `otto_app` has no write grant on `plans`
//! (migration 0016), and operators change tiers as the migrating role.

use otto_core::error::Result;
use otto_core::orgs::Plan;
use otto_tenant::Unpinned;
use sqlx::FromRow;

/// One tier as offered, before any org-specific override.
///
/// Not called `Plan`: that name is the enum in [`otto_core::orgs`], which this
/// struct (and `usage.rs`) carries as its `plan` field.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct PlanOffer {
    pub plan: Plan,
    pub display_name: String,
    /// Billable operations included each month, as listed. A subscription's
    /// `included_ops_override` is deliberately not applied: the catalog is the
    /// public offer, not anyone's contract.
    pub included_ops: i64,
    /// Whether exceeding the bucket stops billable work rather than metering
    /// overage.
    pub hard_stop: bool,
    /// The list price, in US cents. `0` on enterprise means negotiated, not
    /// free; the column has no way to say "call us", and the only reader that
    /// needs to tell the two apart is a pricing page, which knows the tier.
    pub monthly_cents: i32,
    /// Capabilities the tier unlocks (`plans.features`), keyed by capability.
    pub features: serde_json::Value,
}

/// Every plan, cheapest tier first.
///
/// `ORDER BY plan` sorts by the `org_plan` enum's declaration order (free,
/// team, business, enterprise), not alphabetically, which is the order a buyer
/// reads tiers in and the one a new tier is slotted into by its migration.
pub async fn list_plans(tx: &mut Unpinned) -> Result<Vec<PlanOffer>> {
    let plans = sqlx::query_as(
        "SELECT plan, display_name, included_ops, hard_stop, monthly_cents, features \
         FROM plans ORDER BY plan",
    )
    .fetch_all(tx.conn())
    .await?;
    Ok(plans)
}
