//! `otto-resource` — what a resource server (otto-factory, otto-flags, ...)
//! links to work with the otto platform.
//!
//! The platform is the OAuth authorization server and owns identity: users,
//! orgs, teams, members, plans, and metering. A resource server owns its own
//! domain data and its own database, and talks to the platform over HTTP,
//! authenticated by the credential it was issued at registration
//! (`otto-platform-server resource register`). This crate is that HTTP
//! client, plus the receiving end of the platform's webhooks. It has no
//! database dependency.
//!
//! | Need | API |
//! |---|---|
//! | Authenticate a request's bearer token | [`PlatformClient::introspect`] (cached 60 s) |
//! | Read this service's metered usage | [`PlatformClient::usage_status`] (cached 60 s), [`UsageStatus::meters`] |
//! | Declare value meters, at startup | [`PlatformClient::declare_meters`] |
//! | Report metered calls | [`PlatformClient::ship_usage`] from your own outbox |
//! | Resolve members and teams | [`PlatformClient::member`], [`member_teams`](PlatformClient::member_teams), [`member_by_email`](PlatformClient::member_by_email), [`team`](PlatformClient::team), [`team_by_slug`](PlatformClient::team_by_slug) |
//! | Link to the platform console | [`PlatformClient::usage_page_url`] |
//! | Clean up when the platform deletes things | [`webhook::verify`], [`webhook::LifecycleEvent`] |
//!
//! # Metering
//!
//! Write a row to an outbox table in **your** transaction when billable work
//! happens, with a freshly minted `event_id`. A background task reads unsent
//! rows, calls [`PlatformClient::ship_usage`], and deletes the rows it was
//! told about (accepted, duplicate, or rejected). Because the platform dedupes
//! on `(resource server, event_id)`, the task can retry anything, forever.
//! This crate deliberately does not own that table.
//!
//! Declare your value meters ([`MeterDeclaration`], keyed
//! `<service>/<meter>`) with [`PlatformClient::declare_meters`] at startup,
//! before starting that task: the platform rejects usage for an undeclared
//! meter, and the task drops what is rejected. Your service slug is assigned
//! by the platform operator (`otto-platform-server resource set-service`);
//! until it is, declaring fails with HTTP 409 `service_not_set`.
//!
//! A metered event names a declared meter by key in [`UsageEvent::meter`],
//! with a [`UsageEvent::quantity`]; an event with no meter is recorded as
//! unmetered (free). Each service's usage counts in its own pool:
//! [`UsageStatus::meters`] reports only the calling service's meters, and the
//! legacy family-wide fields ([`UsageStatus::is_blocked`] among them) are
//! deprecated and never block.
//!
//! # Revocation latency
//!
//! A token revoked at the platform, or whose user is removed from the org,
//! keeps working at this resource server for up to [`INTROSPECTION_TTL`].
//! That is the cost of not calling the platform on every request.
//!
//! Likewise [`PlatformClient::member`] and [`PlatformClient::member_teams`]
//! are cached for [`MEMBER_TTL`] (10 s, `ClientConfig::member_ttl`, zero
//! disables), and "not a member" for at most [`MEMBER_NEGATIVE_TTL`]. A role
//! or team change made at the platform therefore takes up to that long to
//! apply at the resource server.

mod cache;
mod client;
mod error;
mod types;
pub mod webhook;

pub use client::{
    ClientConfig, PlatformClient, INTROSPECTION_TTL, MEMBER_NEGATIVE_TTL, MEMBER_TTL, NEGATIVE_TTL,
    USAGE_STATUS_TTL,
};
pub use error::{Error, Result};
pub use types::*;
