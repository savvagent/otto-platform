//! `otto-billing` — metering and plan-limit queries shared by every otto-*
//! service, per `docs/specs/2026-09-15-otto-flags-design.md` §4: one plan,
//! one usage bucket, family-wide. Built on [`otto_tenant`] for the pinned
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
