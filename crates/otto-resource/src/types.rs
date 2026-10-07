//! Wire types shared by the platform's resource-server API and this crate.
//!
//! The platform serializes these and the client deserializes them, so the two
//! cannot drift. Ids are plain [`Uuid`]s: this crate has no dependency on the
//! platform's typed ids.

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
/// server: `otto_at_` (OAuth access) or `otto_pat_` (personal access) followed
/// by 43 base64url characters (32 random bytes, unpadded). Refresh tokens
/// (`otto_rt_`) are never presented to a resource server.
///
/// A pre-filter only: passing it says nothing about validity, but failing it
/// means the platform would answer inactive, so no call is needed. This
/// mirrors `otto_auth::crypto::generate`; the platform's test suite asserts
/// every token kind it mints passes.
pub fn looks_like_token(s: &str) -> bool {
    let Some(rest) = s
        .strip_prefix("otto_at_")
        .or_else(|| s.strip_prefix("otto_pat_"))
    else {
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

/// An org's usage this billing month against its plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageStatus {
    pub org_id: Uuid,
    /// `free`, `team`, `business`, or `enterprise`. A string so a new plan
    /// does not break older resource servers.
    pub plan: String,
    /// First day of the UTC billing month the counts are for.
    pub period_start: NaiveDate,
    pub billable_count: i64,
    pub total_count: i64,
    /// Billable operations the plan includes, after any negotiated override.
    pub included_ops: i64,
    /// Whether exceeding `included_ops` stops billable work (free plans)
    /// rather than metering overage.
    pub hard_stop: bool,
}

impl UsageStatus {
    /// Whether the bucket is spent.
    pub fn over_limit(&self) -> bool {
        self.billable_count >= self.included_ops
    }

    /// Whether billable work must be refused: the bucket is spent and the plan
    /// does not allow overage.
    pub fn is_blocked(&self) -> bool {
        self.hard_stop && self.over_limit()
    }
}

/// One metered call, as a resource server records it in its own outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvent {
    /// Minted once, when the outbox row is written, and reused on every
    /// retry: this is what makes shipping idempotent.
    pub event_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub tool: String,
    pub billable: bool,
    /// When the work happened (decides the billing month).
    pub occurred_at: DateTime<Utc>,
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
    /// Newly counted.
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
