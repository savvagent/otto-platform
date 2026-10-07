//! The platform client.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::{Method, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cache::TtlCache;
use crate::error::{Error, Result};
use crate::types::{
    looks_like_token, IntrospectionResponse, MemberInfo, MemberTeams, TeamInfo, TokenClaims,
    UsageBatch, UsageEvent, UsageReceipt, UsageStatus, MAX_USAGE_BATCH,
};

/// How long a positive introspection result is trusted, and so the longest a
/// revoked token keeps working at this resource server.
pub const INTROSPECTION_TTL: Duration = Duration::from_secs(60);
/// How long an inactive result is remembered: just enough that a client
/// hammering with a bad token does not turn into a request per call.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// How long an org's usage status is reused. Overrun of a quota is bounded by
/// this window.
pub const USAGE_STATUS_TTL: Duration = Duration::from_secs(60);

/// How long a member lookup ([`PlatformClient::member`],
/// [`PlatformClient::member_teams`]) is reused, and so the longest a role or
/// team change at the platform takes to apply at this resource server.
pub const MEMBER_TTL: Duration = Duration::from_secs(10);
/// How long "not a member" is remembered. Shorter than [`MEMBER_TTL`] so a
/// freshly invited user is not turned away for long.
pub const MEMBER_NEGATIVE_TTL: Duration = Duration::from_secs(2);

const MAX_POSITIVE_ENTRIES: u64 = 10_000;
/// Negatives are cheap to recompute and are the only thing junk input can
/// create, so they get their own small cache.
const MAX_NEGATIVE_ENTRIES: u64 = 1_000;

/// Configuration for a [`PlatformClient`].
#[derive(Clone)]
pub struct ClientConfig {
    /// The platform's origin, e.g. `https://otto.savvagent.com`.
    pub base_url: String,
    /// This resource server's registered `resource_uri`; the HTTP Basic
    /// username.
    pub resource_uri: String,
    /// The introspection credential issued at registration (`otto_rs_...`).
    pub secret: String,
    pub introspection_ttl: Duration,
    pub negative_ttl: Duration,
    pub usage_status_ttl: Duration,
    /// How long [`PlatformClient::member`] and [`PlatformClient::member_teams`]
    /// results are reused. [`Duration::ZERO`] disables member caching,
    /// negatives included.
    pub member_ttl: Duration,
    /// How long "not a member" is reused; capped at `member_ttl`.
    pub member_negative_ttl: Duration,
    pub timeout: Duration,
}

impl ClientConfig {
    pub fn new(
        base_url: impl Into<String>,
        resource_uri: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            resource_uri: resource_uri.into(),
            secret: secret.into(),
            introspection_ttl: INTROSPECTION_TTL,
            negative_ttl: NEGATIVE_TTL,
            usage_status_ttl: USAGE_STATUS_TTL,
            member_ttl: MEMBER_TTL,
            member_negative_ttl: MEMBER_NEGATIVE_TTL,
            timeout: Duration::from_secs(10),
        }
    }
}

// Not derived: the credential must never reach a log line.
impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("base_url", &self.base_url)
            .field("resource_uri", &self.resource_uri)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A resource server's handle on the platform. Cheap to clone-by-`Arc`, safe
/// to share across tasks, and caches internally: build one at startup.
///
/// ```no_run
/// # async fn demo() -> otto_resource::Result<()> {
/// use otto_resource::{ClientConfig, PlatformClient};
///
/// let platform = PlatformClient::new(ClientConfig::new(
///     "https://otto.savvagent.com",
///     "https://otto-flags.savvagent.com/mcp",
///     std::env::var("OTTO_INTROSPECTION_SECRET").unwrap(),
/// ))?;
///
/// match platform.introspect("otto_at_...").await? {
///     Some(claims) if claims.has_scope("flags:write") => { /* authorized */ }
///     Some(_) => { /* 403: valid token, missing scope */ }
///     None => { /* 401 */ }
/// }
/// # Ok(()) }
/// ```
pub struct PlatformClient {
    http: reqwest::Client,
    base: Url,
    /// `resource_uri`, percent-encoded as RFC 6749 §2.3.1 requires of a client
    /// id before it goes into HTTP Basic, since a URI contains `:`.
    basic_user: String,
    secret: String,
    cfg: ClientConfig,
    // Keyed by SHA-256 of the token so live bearer tokens are not held in
    // memory longer than the request that carried them.
    introspections: TtlCache<[u8; 32], TokenClaims>,
    inactive: TtlCache<[u8; 32], ()>,
    usage: TtlCache<Uuid, UsageStatus>,
    // Keyed by (org, user). Absences live in their own small caches so that
    // junk ids can only displace other junk.
    members: TtlCache<(Uuid, Uuid), MemberInfo>,
    members_absent: TtlCache<(Uuid, Uuid), ()>,
    member_teams: TtlCache<(Uuid, Uuid), Vec<TeamInfo>>,
    member_teams_absent: TtlCache<(Uuid, Uuid), ()>,
}

impl std::fmt::Debug for PlatformClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformClient")
            .field("base", &self.base.as_str())
            .field("resource_uri", &self.cfg.resource_uri)
            .finish_non_exhaustive()
    }
}

impl PlatformClient {
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        let base = Url::parse(&cfg.base_url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        if base.cannot_be_a_base() || !matches!(base.scheme(), "http" | "https") {
            return Err(Error::InvalidUrl(format!(
                "{} is not an http(s) URL",
                cfg.base_url
            )));
        }
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            // The platform never redirects its API. Following one would send
            // the credential wherever it pointed.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::Transport)?;
        Ok(Self {
            http,
            base,
            basic_user: utf8_percent_encode(&cfg.resource_uri, NON_ALPHANUMERIC).to_string(),
            secret: cfg.secret.clone(),
            cfg,
            introspections: TtlCache::new(MAX_POSITIVE_ENTRIES),
            inactive: TtlCache::new(MAX_NEGATIVE_ENTRIES),
            usage: TtlCache::new(MAX_POSITIVE_ENTRIES),
            members: TtlCache::new(MAX_POSITIVE_ENTRIES),
            members_absent: TtlCache::new(MAX_NEGATIVE_ENTRIES),
            member_teams: TtlCache::new(MAX_POSITIVE_ENTRIES),
            member_teams_absent: TtlCache::new(MAX_NEGATIVE_ENTRIES),
        })
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("checked in new()")
            .pop_if_empty()
            .extend(segments);
        url
    }

    fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.http
            .request(method, url)
            .basic_auth(&self.basic_user, Some(&self.secret))
    }

    async fn send(&self, req: RequestBuilder) -> Result<reqwest::Response> {
        let res = req.send().await.map_err(Error::Transport)?;
        match res.status() {
            s if s.is_success() => Ok(res),
            StatusCode::UNAUTHORIZED => Err(Error::Unauthorized),
            s => {
                let mut body = res.text().await.unwrap_or_default();
                body.truncate(512);
                Err(Error::Status {
                    status: s.as_u16(),
                    body,
                })
            }
        }
    }

    /// As [`Self::send`] and decode, mapping 404 to `Ok(None)`.
    async fn get_optional<T: DeserializeOwned>(&self, url: Url) -> Result<Option<T>> {
        match self.send(self.request(Method::GET, url)).await {
            Ok(res) => Ok(Some(res.json().await.map_err(decode)?)),
            Err(Error::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ---------------------------------------------------------- introspection

    /// Resolve a bearer token to its claims, or `None` if it is not active
    /// for this resource server (unknown, expired, revoked, minted for a
    /// different resource server, or its user left the org).
    ///
    /// Positive results are cached for up to [`INTROSPECTION_TTL`] (never past
    /// the token's own expiry), so a revoked token can keep working here for
    /// that long. Inactive results are cached for [`NEGATIVE_TTL`]. Failures
    /// are never cached, and are returned as errors rather than as `None`: a
    /// platform outage must not look like every token being revoked, and the
    /// caller decides whether that is a 503 or a 401.
    pub async fn introspect(&self, token: &str) -> Result<Option<TokenClaims>> {
        // Strings that cannot be a platform token are inactive without asking.
        // Besides saving the call, this keeps junk out of the caches: only
        // plausible tokens ever reach them.
        if !looks_like_token(token.trim()) {
            return Ok(None);
        }
        let key: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        if let Some(hit) = self.introspections.get(&key) {
            return Ok(Some(hit));
        }
        if self.inactive.get(&key).is_some() {
            return Ok(None);
        }

        let req = self
            .request(Method::POST, self.url(&["oauth", "introspect"]))
            .form(&[("token", token.trim())]);
        let body: IntrospectionResponse = self.send(req).await?.json().await.map_err(decode)?;
        let claims = body.into_claims(&self.cfg.resource_uri);

        match &claims {
            Some(c) => {
                let until_expiry = (c.expires_at - chrono::Utc::now())
                    .to_std()
                    .unwrap_or(Duration::ZERO);
                let ttl = self.cfg.introspection_ttl.min(until_expiry);
                self.introspections.insert(key, c.clone(), ttl);
            }
            None => self.inactive.insert(key, (), self.cfg.negative_ttl),
        }
        Ok(claims)
    }

    // ------------------------------------------------------------------ usage

    /// The org's usage this month against its plan, cached for
    /// [`USAGE_STATUS_TTL`]. Check [`UsageStatus::is_blocked`] before doing
    /// billable work.
    pub async fn usage_status(&self, org_id: Uuid) -> Result<UsageStatus> {
        if let Some(hit) = self.usage.get(&org_id) {
            return Ok(hit);
        }
        let url = self.url(&["internal", "orgs", &org_id.to_string(), "usage-status"]);
        let status: UsageStatus = self.get_optional(url).await?.ok_or(Error::NotFound)?;
        self.usage
            .insert(org_id, status.clone(), self.cfg.usage_status_ttl);
        Ok(status)
    }

    /// Ship usage events. Splits into batches of [`MAX_USAGE_BATCH`] and
    /// returns the merged receipt.
    ///
    /// Idempotent on [`UsageEvent::event_id`], so on any error simply call it
    /// again with the same events. Stops at the first failed batch: events in
    /// earlier batches are already counted, and resending them is harmless.
    pub async fn ship_usage(&self, events: &[UsageEvent]) -> Result<UsageReceipt> {
        let mut receipt = UsageReceipt::default();
        for chunk in events.chunks(MAX_USAGE_BATCH) {
            let req = self
                .request(Method::POST, self.url(&["internal", "usage"]))
                .json(&UsageBatch {
                    events: chunk.to_vec(),
                });
            receipt.merge(self.send(req).await?.json().await.map_err(decode)?);
        }
        Ok(receipt)
    }

    // --------------------------------------------------------------- identity

    /// The user, org, and role for a member of `org`; `None` if the user is
    /// not an active member (never a member, removed, disabled, or the org was
    /// deleted). What a `whoami` needs.
    ///
    /// Cached per `(org, user)` for [`ClientConfig::member_ttl`] (default
    /// [`MEMBER_TTL`]), and "not a member" for at most
    /// [`ClientConfig::member_negative_ttl`]. A role change or removal at the
    /// platform therefore takes up to that long to apply here. Errors are
    /// never cached.
    pub async fn member(&self, org_id: Uuid, user_id: Uuid) -> Result<Option<MemberInfo>> {
        let key = (org_id, user_id);
        if let Some(hit) = self.members.get(&key) {
            return Ok(Some(hit));
        }
        if self.members_absent.get(&key).is_some() {
            return Ok(None);
        }
        let found: Option<MemberInfo> = self
            .get_optional(self.url(&[
                "internal",
                "orgs",
                &org_id.to_string(),
                "members",
                &user_id.to_string(),
            ]))
            .await?;
        match &found {
            Some(m) => self.members.insert(key, m.clone(), self.cfg.member_ttl),
            None => self
                .members_absent
                .insert(key, (), self.negative_member_ttl()),
        }
        Ok(found)
    }

    /// The teams `user` belongs to in `org`, ordered by name; `None` if the
    /// user is not an active member of the org. A member on no team is
    /// `Some(vec![])`. Teams in other orgs are never included.
    ///
    /// Cached exactly as [`Self::member`] is, so a team change takes up to
    /// [`ClientConfig::member_ttl`] to apply here.
    pub async fn member_teams(&self, org_id: Uuid, user_id: Uuid) -> Result<Option<Vec<TeamInfo>>> {
        let key = (org_id, user_id);
        if let Some(hit) = self.member_teams.get(&key) {
            return Ok(Some(hit));
        }
        if self.member_teams_absent.get(&key).is_some() {
            return Ok(None);
        }
        let found: Option<Vec<TeamInfo>> = self
            .get_optional::<MemberTeams>(self.url(&[
                "internal",
                "orgs",
                &org_id.to_string(),
                "members",
                &user_id.to_string(),
                "teams",
            ]))
            .await?
            .map(|t| t.teams);
        match &found {
            Some(t) => self
                .member_teams
                .insert(key, t.clone(), self.cfg.member_ttl),
            None => self
                .member_teams_absent
                .insert(key, (), self.negative_member_ttl()),
        }
        Ok(found)
    }

    fn negative_member_ttl(&self) -> Duration {
        self.cfg.member_negative_ttl.min(self.cfg.member_ttl)
    }

    // ---------------------------------------------------------------- console

    /// The platform console's usage page for an org, `/o/{org_slug}/usage`
    /// under the platform origin: where to send a user whose org is over its
    /// plan ([`UsageStatus::is_blocked`]). Takes the org's slug
    /// ([`crate::OrgInfo::slug`]), not its id; the slug is percent-encoded.
    ///
    /// ```
    /// # use otto_resource::{ClientConfig, PlatformClient};
    /// let c = PlatformClient::new(ClientConfig::new(
    ///     "https://otto.savvagent.com", "https://x.example/mcp", "otto_rs_x",
    /// ))?;
    /// assert_eq!(c.usage_page_url("acme"), "https://otto.savvagent.com/o/acme/usage");
    /// # Ok::<(), otto_resource::Error>(())
    /// ```
    pub fn usage_page_url(&self, org_slug: &str) -> String {
        self.url(&["o", org_slug, "usage"]).into()
    }

    /// Resolve an email address to a member of `org`. `None` covers both "no
    /// such account" and "not in this org", deliberately not distinguished.
    pub async fn member_by_email(&self, org_id: Uuid, email: &str) -> Result<Option<MemberInfo>> {
        let mut url = self.url(&[
            "internal",
            "orgs",
            &org_id.to_string(),
            "members",
            "by-email",
        ]);
        url.query_pairs_mut().append_pair("email", email);
        self.get_optional(url).await
    }

    /// A team, if it exists in `org`. Doubles as "is team X in org Y".
    pub async fn team(&self, org_id: Uuid, team_id: Uuid) -> Result<Option<TeamInfo>> {
        self.get_optional(self.url(&[
            "internal",
            "orgs",
            &org_id.to_string(),
            "teams",
            &team_id.to_string(),
        ]))
        .await
    }

    pub async fn team_by_slug(&self, org_id: Uuid, slug: &str) -> Result<Option<TeamInfo>> {
        self.get_optional(self.url(&[
            "internal",
            "orgs",
            &org_id.to_string(),
            "teams",
            "by-slug",
            slug,
        ]))
        .await
    }
}

fn decode(e: reqwest::Error) -> Error {
    Error::Decode(e.to_string())
}
