//! Wire types shared by the platform's resource-server API and this crate.
//!
//! The platform serializes these and the client deserializes them, so the two
//! cannot drift. Ids are plain [`Uuid`]s: this crate has no dependency on the
//! platform's typed ids.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A member's role in an org.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    /// Owners and admins may manage members, teams, and connections.
    pub fn can_administer(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }
}

/// Whether `s` has the shape of a token the platform mints for a resource
/// server: an OAuth access (`*_at_`) or personal access (`*_pat_`) prefix
/// followed by 43 base64url characters (32 random bytes, unpadded). Refresh
/// tokens (`*_rt_`) are never presented to a resource server.
///
/// Both the `otto_` and the `sav_` prefixes pass while the Savvagent rebrand
/// (#128) is under way: resource servers pin this crate by rev, so they have to
/// accept `sav_` tokens before the platform starts minting them.
///
/// A pre-filter only: passing it says nothing about validity, but failing it
/// means the platform would answer inactive, so no call is needed. This
/// mirrors `otto_auth::crypto::generate`; the platform's test suite asserts
/// every token kind it mints passes.
pub fn looks_like_token(s: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sav_at_", "sav_pat_", "otto_at_", "otto_pat_"];
    let Some(rest) = PREFIXES.iter().find_map(|p| s.strip_prefix(p)) else {
        return false;
    };
    rest.len() == 43
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// How a token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// Minted through the OAuth authorization-code flow.
    Oauth,
    /// A personal access token.
    Pat,
}

/// Everything the platform asserts about an active token. Returned by
/// [`crate::PlatformClient::introspect`].
#[derive(Debug, Clone, PartialEq)]
pub struct TokenClaims {
    /// The token's own id, stable across introspections.
    pub token_id: Uuid,
    pub user_id: Uuid,
    /// Fixed when the token was issued; a token opens exactly one org.
    pub org_id: Uuid,
    /// The user's role in that org right now, not when the token was issued.
    pub role: Role,
    pub scopes: Vec<String>,
    /// The audience: this resource server's `resource_uri`.
    pub resource: String,
    pub expires_at: DateTime<Utc>,
    pub client_id: Option<String>,
    pub kind: TokenKind,
}

impl TokenClaims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// The RFC 7662 response body, as it appears on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// Space-separated, per RFC 7662.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// `oauth` or `pat`. Not part of RFC 7662.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_kind: Option<TokenKind>,
    /// The token id (RFC 7519 `jti`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
}

impl IntrospectionResponse {
    /// The `{"active": false}` body.
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            org_id: None,
            role: None,
            scope: None,
            aud: None,
            exp: None,
            client_id: None,
            token_type: None,
            token_kind: None,
            jti: None,
        }
    }

    /// `None` for an inactive token, for an "active" one missing a claim this
    /// crate requires, or for one whose `aud` is not `expected_resource`: all
    /// treated as inactive rather than guessed at. The platform already refuses
    /// to introspect another server's tokens; checking again here means a
    /// misrouted or tampered response cannot authenticate a request.
    pub fn into_claims(self, expected_resource: &str) -> Option<TokenClaims> {
        if !self.active || self.aud.as_deref() != Some(expected_resource) {
            return None;
        }
        Some(TokenClaims {
            token_id: self.jti?,
            user_id: self.sub?,
            org_id: self.org_id?,
            role: self.role?,
            scopes: self
                .scope
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            resource: self.aud?,
            expires_at: DateTime::from_timestamp(self.exp?, 0)?,
            client_id: self.client_id,
            kind: self.token_kind?,
        })
    }
}

/// An org's usage this billing month, from
/// `GET /internal/orgs/{org}/usage-status`.
///
/// Two generations of fields share this body. [`service`](Self::service) and
/// [`meters`](Self::meters) are the calling resource server's own value
/// meters: its pool, unaffected by any other service. The rest (`plan`
/// through `hard_stop`) are the legacy family-wide bucket, kept so resource
/// servers pinned to an older release of this crate keep parsing the body.
/// They are **deprecated**: during the move to value meters the platform
/// always serves `hard_stop: false`, so [`is_blocked`](Self::is_blocked) is
/// never true and one service's usage can never stop another's work.
///
/// ```
/// let body = serde_json::json!({
///     "org_id": "8b5c6f8e-6a43-4f53-9a49-0f1f7a1d2b3c",
///     "plan": "free",
///     "period_start": "2026-10-01",
///     "billable_count": 9000,
///     "total_count": 9000,
///     "included_ops": 500,
///     "hard_stop": false,
///     "service": "otto-flags",
///     "meters": [{
///         "meter": "otto-flags/evaluations",
///         "display_name": "Flag evaluations",
///         "unit": "evaluation",
///         "quantity": 1200
///     }]
/// });
/// let status: otto_resource::UsageStatus = serde_json::from_value(body).unwrap();
/// assert!(!status.is_blocked());
/// assert_eq!(status.meter("otto-flags/evaluations").unwrap().quantity, 1200);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageStatus {
    pub org_id: Uuid,
    /// `free`, `team`, `business`, or `enterprise`. A string so a new plan
    /// does not break older resource servers.
    pub plan: String,
    /// First day of the UTC billing month the counts are for.
    pub period_start: NaiveDate,
    /// **Deprecated.** Billable calls this month across every service in the
    /// family (the legacy shared bucket). Read [`meters`](Self::meters) for
    /// this service's own usage.
    pub billable_count: i64,
    /// **Deprecated.** Every call this month across every service in the
    /// family, billable or not.
    pub total_count: i64,
    /// **Deprecated.** Billable operations the legacy plan bucket includes,
    /// after any negotiated override.
    pub included_ops: i64,
    /// **Deprecated.** Always `false` from a platform that serves
    /// [`meters`](Self::meters), so [`is_blocked`](Self::is_blocked) is never
    /// true: a family-wide bucket would let one service's usage stop another.
    pub hard_stop: bool,
    /// Capabilities the org's plan unlocks, keyed by capability, as the
    /// platform's `plans.features` holds them. Read them with
    /// [`UsageStatus::feature_enabled`]. Defaults to empty when the platform
    /// predates the field, so an older platform grants nothing.
    #[serde(default)]
    pub features: BTreeMap<String, serde_json::Value>,
    /// The calling resource server's service slug, which [`meters`](Self::meters)
    /// belong to. `None` from an older platform, or when no service has been
    /// assigned yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// This month's quantity for each meter the calling service has declared,
    /// zero for one with no usage yet. Only the caller's own meters: another
    /// service's usage never appears here. Empty from an older platform.
    #[serde(default)]
    pub meters: Vec<MeterUsage>,
    /// The calling service's monthly budget and where its spend stands
    /// against it. `None` when the org has set no budget for this service, or
    /// from an older platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetStatus>,
    /// Why the calling service must refuse billable calls now, or `None`
    /// when it need not (and from an older platform):
    ///
    /// - [`BUDGET_EXCEEDED`]: the org's hard stop for this service is on and
    ///   its spend has reached its budget (as [`budget_exceeded`](Self::budget_exceeded));
    /// - [`PAYMENT_REQUIRED`]: the org is not in good standing to be billed
    ///   (no card on file, an unpaid subscription, or a failed payment past
    ///   its grace period), and this service's spend this month is above
    ///   zero, that is, past whatever its free tiers include. Only reported
    ///   when the platform has billing switched on.
    ///
    /// The budget wins when both apply. Read
    /// [`billable_blocked`](Self::billable_blocked) to decide whether to
    /// refuse a billable call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// The [`UsageStatus::blocked_reason`] of an org not in good standing to be
/// billed (no card on file, an unpaid subscription, or a failed payment past
/// its grace period) whose usage of the calling service this month is past
/// its free tiers, and the error code a resource server should refuse a
/// billable call with: an owner must add or fix the payment method in the
/// console. Only reported when the platform has billing switched on.
/// Spend is zero while no price is set, so no org is refused for this until
/// prices exist.
pub const PAYMENT_REQUIRED: &str = "payment_required";

/// The reason [`BudgetStatus::reason`] and [`UsageStatus::blocked_reason`]
/// give when the calling service's hard stop has refused billable work, and
/// the error code a resource server should refuse a billable call with.
pub const BUDGET_EXCEEDED: &str = "budget_exceeded";

/// The reason [`BudgetStatus::reason`] gives when the platform could not
/// compute this service's spend (a pricing fault on its side). The budget is
/// still reported, [`spend_cents`](BudgetStatus::spend_cents) and
/// [`percent_used`](BudgetStatus::percent_used) are `None`, and nothing is
/// blocked: enforcement fails open.
pub const SPEND_UNAVAILABLE: &str = "spend_unavailable";

/// The calling service's budget this billing month, in
/// [`UsageStatus::budget`].
///
/// A budget belongs to one service: another service's budget, spend or hard
/// stop never appears here and never blocks this one. Owners and admins set
/// budgets in the console; agents can read them (through each service's own
/// `usage` tool) but not change them.
///
/// **Enforcement fails open.** The platform never refuses usage; the resource
/// server refuses billable calls when [`blocked`](Self::blocked) is true. When
/// the platform cannot be reached, answers without a `budget`, or cannot
/// compute spend (reason [`SPEND_UNAVAILABLE`], `blocked` false), a resource
/// server must treat the service as not blocked. Free calls are never
/// refused, and reading usage is always free.
///
/// ```
/// let body = serde_json::json!({
///     "org_id": "8b5c6f8e-6a43-4f53-9a49-0f1f7a1d2b3c",
///     "plan": "free",
///     "period_start": "2026-10-01",
///     "billable_count": 0,
///     "total_count": 0,
///     "included_ops": 500,
///     "hard_stop": false,
///     "service": "otto-flags",
///     "budget": {
///         "monthly_budget_cents": 1000,
///         "spend_cents": 1250,
///         "percent_used": 125,
///         "thresholds_reached": [50, 80, 100],
///         "hard_stop": true,
///         "blocked": true,
///         "reason": "budget_exceeded"
///     }
/// });
/// let status: otto_resource::UsageStatus = serde_json::from_value(body).unwrap();
/// assert!(status.budget_exceeded());
/// assert_eq!(status.budget.unwrap().reason.as_deref(), Some(otto_resource::BUDGET_EXCEEDED));
///
/// // Spend the platform could not compute never blocks.
/// let unknown = serde_json::json!({
///     "monthly_budget_cents": 1000,
///     "spend_cents": null,
///     "percent_used": null,
///     "thresholds_reached": [],
///     "hard_stop": true,
///     "blocked": false,
///     "reason": "spend_unavailable"
/// });
/// let b: otto_resource::BudgetStatus = serde_json::from_value(unknown).unwrap();
/// assert_eq!((b.spend_cents, b.blocked), (None, false));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetStatus {
    /// The budget for one UTC calendar month, in US cents.
    pub monthly_budget_cents: i64,
    /// What this service's value meters have cost this month, in US cents,
    /// at the prices in effect. Unpriced meters and free calls add nothing.
    /// `None` when the platform could not compute it ([`SPEND_UNAVAILABLE`]).
    #[serde(default)]
    pub spend_cents: Option<i64>,
    /// Whole percent of the budget spent, rounded down. Can exceed 100.
    /// `None` when spend is unknown.
    #[serde(default)]
    pub percent_used: Option<i64>,
    /// The alert thresholds (50, 80, 100 percent) that have fired this month,
    /// ascending. Each fires once a month, with an email to the org's owners
    /// and admins.
    #[serde(default)]
    pub thresholds_reached: Vec<u8>,
    /// Whether the org opted in to refusing billable calls once spend reaches
    /// the budget.
    pub hard_stop: bool,
    /// Whether billable calls must be refused now: only with
    /// [`hard_stop`](Self::hard_stop) on and spend at or past the budget.
    pub blocked: bool,
    /// Why [`blocked`](Self::blocked) is true ([`BUDGET_EXCEEDED`]), or why
    /// spend is unknown ([`SPEND_UNAVAILABLE`], never blocked). `None`
    /// otherwise.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One declared meter's usage this billing month, in [`UsageStatus::meters`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterUsage {
    /// The meter's key, `<service>/<meter>`.
    pub meter: String,
    pub display_name: String,
    pub unit: String,
    /// The sum of the quantities shipped for this meter this month.
    pub quantity: u64,
}

impl UsageStatus {
    /// Whether the plan includes `feature`: only a JSON `true` counts, so a
    /// missing key, `false`, or any other value is off.
    pub fn feature_enabled(&self, feature: &str) -> bool {
        matches!(
            self.features.get(feature),
            Some(serde_json::Value::Bool(true))
        )
    }

    /// Whether the calling service's budget hard stop refuses billable calls
    /// now. `false` with no budget, when spend is unknown, and from a
    /// platform that sends none: see [`BudgetStatus`] on failing open.
    /// [`billable_blocked`](Self::billable_blocked) covers this and every
    /// other reason to refuse.
    pub fn budget_exceeded(&self) -> bool {
        self.budget.as_ref().is_some_and(|b| b.blocked)
    }

    /// Whether the calling service must refuse billable calls now, for any
    /// reason: [`blocked_reason`](Self::blocked_reason) is set
    /// ([`BUDGET_EXCEEDED`] or [`PAYMENT_REQUIRED`], refuse with that code),
    /// or the budget's hard stop says so (a platform that predates
    /// `blocked_reason`). Free calls are never refused, and reading usage is
    /// always free.
    ///
    /// **Enforcement fails open.** The platform never refuses usage itself;
    /// a resource server that cannot reach it, or gets an answer without
    /// these fields, treats the service as not blocked.
    ///
    /// ```
    /// let body = serde_json::json!({
    ///     "org_id": "8b5c6f8e-6a43-4f53-9a49-0f1f7a1d2b3c",
    ///     "plan": "free",
    ///     "period_start": "2026-10-01",
    ///     "billable_count": 0,
    ///     "total_count": 0,
    ///     "included_ops": 500,
    ///     "hard_stop": false,
    ///     "service": "otto-flags",
    ///     "blocked_reason": "payment_required"
    /// });
    /// let status: otto_resource::UsageStatus = serde_json::from_value(body).unwrap();
    /// assert!(status.billable_blocked());
    /// assert!(!status.budget_exceeded());
    /// assert_eq!(status.blocked_reason.as_deref(), Some(otto_resource::PAYMENT_REQUIRED));
    /// ```
    pub fn billable_blocked(&self) -> bool {
        self.blocked_reason.is_some() || self.budget_exceeded()
    }

    /// This month's usage of one of the caller's meters, by key.
    pub fn meter(&self, key: &str) -> Option<&MeterUsage> {
        self.meters.iter().find(|m| m.meter == key)
    }

    /// **Deprecated.** Whether the legacy family-wide bucket is spent.
    pub fn over_limit(&self) -> bool {
        self.billable_count >= self.included_ops
    }

    /// **Deprecated.** Whether billable work must be refused under the legacy
    /// family-wide bucket: it is spent and the plan does not allow overage.
    /// Never true against a platform that serves [`meters`](Self::meters),
    /// which always sends `hard_stop: false`.
    pub fn is_blocked(&self) -> bool {
        self.hard_stop && self.over_limit()
    }
}

/// The largest [`UsageEvent::quantity`] the platform accepts in one event.
pub const MAX_METER_QUANTITY: u64 = 1_000_000_000;

/// One metered call, as a resource server records it in its own outbox.
///
/// An event with no [`meter`](Self::meter) is *unmetered*: it is recorded and
/// counted (free) but adds to no meter. A metered event names one of the
/// caller's declared meters by key and carries a
/// [`quantity`](Self::quantity). The platform refuses, per event in
/// [`UsageReceipt::rejected`], a meter the caller has not declared
/// (`unknown_meter`), a `service` other than the caller's own
/// (`service_mismatch`), and a quantity of 0, above [`MAX_METER_QUANTITY`], or
/// without a meter (`invalid_quantity`).
///
/// ```
/// use otto_resource::UsageEvent;
///
/// let ev = UsageEvent {
///     event_id: uuid::Uuid::new_v4(),
///     org_id: uuid::Uuid::new_v4(),
///     user_id: None,
///     tool: "flag.evaluate".into(),
///     billable: true,
///     occurred_at: chrono::Utc::now(),
///     service: Some("otto-flags".into()),
///     meter: Some("otto-flags/evaluations".into()),
///     quantity: Some(40),
/// };
/// // Unset metering fields are left off the wire, so an older platform reads
/// // the event exactly as before.
/// let unmetered = UsageEvent { service: None, meter: None, quantity: None, ..ev };
/// let json = serde_json::to_value(&unmetered).unwrap();
/// assert!(json.get("meter").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvent {
    /// Minted once, when the outbox row is written, and reused on every
    /// retry: this is what makes shipping idempotent.
    pub event_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub tool: String,
    /// Feeds the legacy family-wide counters and this service's billable
    /// count. A metered event's quantity counts whatever this says.
    pub billable: bool,
    /// When the work happened, which decides the billing month while that
    /// month is open. A month closes 2 hours into the next UTC month; an
    /// event that arrives later is still accepted, and billed in the month it
    /// arrived in. Ship promptly.
    pub occurred_at: DateTime<Utc>,
    /// The shipping resource server's service slug. Optional: the platform
    /// knows who is calling, and only checks that this, when sent, matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The declared meter this event counts toward, by its full key
    /// `<service>/<meter>` (see [`MeterDeclaration::key`]). `None` for an
    /// unmetered (free) event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    /// How many units of [`meter`](Self::meter) this event used, 1 to
    /// [`MAX_METER_QUANTITY`]. Defaults to 1 when a meter is named without
    /// one; must be `None` when [`meter`](Self::meter) is. Out-of-range values
    /// are refused per event (`invalid_quantity`), but a JSON value that is not
    /// a `u64` at all (negative, fractional, a string) fails the *whole*
    /// request at parse time, like any other malformed body. This type cannot
    /// produce one; only a hand-built shipper can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantity: Option<u64>,
}

/// The most events one `POST /internal/usage` accepts.
pub const MAX_USAGE_BATCH: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBatch {
    pub events: Vec<UsageEvent>,
}

/// An event the platform refused outright (as opposed to one it had already
/// seen). Retrying it unchanged will fail again, so the shipper should drop it
/// from its outbox and log `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedEvent {
    pub event_id: Uuid,
    pub reason: String,
}

/// The platform's answer to a usage batch. Every event in the batch is in
/// exactly one of the three outcomes, so after a successful call the shipper
/// can delete the whole batch from its outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReceipt {
    /// Newly counted. Includes **late** events: an event whose billing month
    /// had already closed when it arrived (2 hours into the next UTC month)
    /// is still accepted, and counted in the month it arrived in.
    pub accepted: u32,
    /// Already counted by an earlier call; nothing changed.
    pub duplicates: u32,
    pub rejected: Vec<RejectedEvent>,
}

impl UsageReceipt {
    pub(crate) fn merge(&mut self, other: UsageReceipt) {
        self.accepted += other.accepted;
        self.duplicates += other.duplicates;
        self.rejected.extend(other.rejected);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgInfo {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub plan: String,
}

/// A user, the org, and the user's role in it: what a `whoami` needs, and what
/// "is this email a member of the org" returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub user: UserInfo,
    pub org: OrgInfo,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamInfo {
    pub id: Uuid,
    pub org_id: Uuid,
    pub slug: String,
    pub name: String,
}

/// The teams one member belongs to in one org, from
/// `GET /internal/orgs/{org}/members/{user}/teams`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberTeams {
    pub teams: Vec<TeamInfo>,
}

/// One value meter a resource server bills by, declared with
/// [`crate::PlatformClient::declare_meters`].
///
/// `key` is `<service>/<meter>`, where `<service>` is the service slug an
/// operator assigned this resource server (`otto-platform-server resource
/// set-service`) and `<meter>` matches `^[a-z][a-z0-9_]{0,62}$`.
/// `display_name` (at most 80 characters) is what usage pages and invoices
/// show; `unit` (at most 32) is what one unit of quantity is.
///
/// ```
/// use otto_resource::MeterDeclaration;
///
/// let m = MeterDeclaration::new("otto-flags/evaluations", "Flag evaluations", "evaluation");
/// assert_eq!(m.key, "otto-flags/evaluations");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterDeclaration {
    pub key: String,
    pub display_name: String,
    pub unit: String,
}

impl MeterDeclaration {
    pub fn new(
        key: impl Into<String>,
        display_name: impl Into<String>,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            display_name: display_name.into(),
            unit: unit.into(),
        }
    }
}

/// The most meters one `PUT /internal/meters` accepts.
/// [`crate::PlatformClient::declare_meters`] splits larger sets.
pub const MAX_METER_DECLARATIONS: usize = 50;

/// The body of `PUT /internal/meters`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterDeclarationBatch {
    pub meters: Vec<MeterDeclaration>,
}

/// A declaration the platform refused: a key outside this resource server's
/// service, a malformed field, or a key repeated in one request. Fix the
/// declaration and declare again; usage for a meter that was never declared
/// is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedMeter {
    /// The key as sent, truncated if it was absurdly long.
    pub key: String,
    pub reason: String,
}

/// The platform's answer to a meter declaration. Every meter sent is in
/// exactly one of `declared` and `rejected`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterDeclarationReceipt {
    /// Keys now declared as sent, whether new, updated, or unchanged.
    #[serde(default)]
    pub declared: Vec<String>,
    #[serde(default)]
    pub rejected: Vec<RejectedMeter>,
}

impl MeterDeclarationReceipt {
    /// Whether every meter was accepted.
    pub fn is_complete(&self) -> bool {
        self.rejected.is_empty()
    }

    pub(crate) fn merge(&mut self, other: MeterDeclarationReceipt) {
        self.declared.extend(other.declared);
        self.rejected.extend(other.rejected);
    }
}

#[cfg(test)]
mod tests {
    use super::looks_like_token;

    const BODY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_9";

    #[test]
    fn access_and_personal_tokens_pass_under_either_prefix() {
        for prefix in ["sav_at_", "sav_pat_", "otto_at_", "otto_pat_"] {
            let token = format!("{prefix}{BODY}");
            assert!(looks_like_token(&token), "{token}");
        }
    }

    #[test]
    fn other_kinds_and_malformed_bodies_do_not() {
        for prefix in ["sav_rt_", "otto_rt_", "sav_ss_", "sav_rs_", "sav_", "at_"] {
            let token = format!("{prefix}{BODY}");
            assert!(!looks_like_token(&token), "{token}");
        }
        for junk in [
            "",
            "sav_at_",
            "sav_at_short",
            &format!("sav_at_{BODY}A"),
            &format!("sav_pat_{}!", &BODY[..42]),
            &format!("SAV_AT_{BODY}"),
        ] {
            assert!(!looks_like_token(junk), "{junk:?}");
        }
    }
}
