//! `otto-billing` — metering, pricing, budgets and Stripe billing shared by
//! every otto-* service. Each service bills by its own value meters, counted
//! in its own pool and rated by the price book; plans buy features, not usage
//! (`docs/specs/2026-10-20-value-meters-design.md`). The family-wide usage
//! bucket survives only as deprecated fields for resource servers pinned to an
//! older client. Built on [`otto_tenant`] for the pinned
//! transaction and [`otto_core::orgs::Plan`] for the plan enum; owns no
//! identity data of its own. [`plans`], [`meters`] and [`pricebook`] are global
//! reference data that `otto_app` reads and never writes: the
//! public catalog of tiers, what each service bills by, and what it costs.

pub mod billing;
pub mod budgets;
pub mod meters;
pub mod plans;
pub mod pricebook;
pub mod stripe;
pub mod stripe_outbox;
pub mod usage;
