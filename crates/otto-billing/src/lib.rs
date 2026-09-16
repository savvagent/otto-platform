//! `otto-billing` — metering and plan-limit queries shared by every otto-*
//! service, per `docs/specs/2026-09-15-otto-flags-design.md` §4: one plan,
//! one usage bucket, family-wide. Built on [`otto_tenant`] for the pinned
//! transaction and [`otto_core::orgs::Plan`] for the plan enum; owns no
//! identity data of its own.

pub mod usage;
