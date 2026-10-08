//! The audit trail.
//!
//! ## Writers
//!
//! Matching the two transaction kinds, plus two control-plane variants:
//!
//! - [`Tx::audit`] for anything that happens inside an org — role changes, PAT
//!   mints, membership changes. Written in the *same* transaction as the
//!   change itself, so an action and its record commit or abort together and
//!   the trail can never disagree with reality.
//! - [`Db::audit_global`] for events that precede any org context: login
//!   attempts, passkey enrollment. Written with a `NULL` org.
//! - [`Db::audit_global_on`], the same `NULL`-org write for a caller that
//!   already holds an unpinned transaction open for something else and needs
//!   its audit write to commit or roll back with it, rather than best-effort
//!   on the pool.
//! - [`Db::audit_for_org`], an org-scoped write from the control plane, where
//!   no tenant transaction is open yet (signup, token issuance).
//!
//! ## Readers, and who sees which row
//!
//! Every row is either **org-scoped** (`org_id` set) or **global**
//! (`org_id IS NULL`), and the two halves have one reader each, which never
//! overlap:
//!
//! - [`Tx::audit_trail`] — an org's admins read their org's rows, through a
//!   pinned transaction. Row-level security (`audit_events_tenant_isolation`,
//!   `org_id = current_org()`) is what confines it; a global row can never
//!   match, because `NULL = anything` is not true, and the control-plane
//!   policy below is false whenever an org is pinned.
//! - [`Db::audit_trail_for_user`] — a signed-in user reads the global rows
//!   **they are the actor of**, and nothing else: no org-scoped row (those
//!   belong to the org's admins, who decide who reads them), and no row
//!   attributed to anybody else. Unpinned, because global rows are readable
//!   only from the unpinned control plane — see that method's doc comment for
//!   the rows it deliberately cannot show.
//!
//! **How global rows are reachable at all.** `0005_audit.sql` says `NULL`-org
//! rows are "reachable only from the unpinned control plane", but as 0005
//! shipped that was true only where the connecting role is exempt from RLS (a
//! superuser or `BYPASSRLS`): its one `SELECT` policy is the tenant one, which
//! no `NULL`-org row passes, so on managed Postgres — a non-exempt owner under
//! `FORCE ROW LEVEL SECURITY` — nobody could read them. `0015_audit_global_read.sql`
//! makes 0005's sentence true on every deployment shape with a second
//! `SELECT` policy, `audit_events_control_plane_read`:
//! `current_org() IS NULL AND org_id IS NULL`. Unpinned reads see global rows
//! and still no org's rows; pinned reads are unchanged. (0005 itself is never
//! edited — sqlx checksums applied migrations — so the correction lives here
//! and in 0015's header.)
//!
//! A global row with no actor — a failed sign-in that never identified an
//! account, a dynamic client registration — has no reader at all. Those are
//! forensic: operators query them in the database directly. That is a
//! consequence of attribution, not an oversight: a row nobody can be shown to
//! own is not shown to anybody.
//!
//! Actions are dotted and stable because they are queried by prefix and because
//! they end up in customers' SIEM exports. Renaming one is a breaking change.
//!
//! This is otto-platform's own `audit_events` table, scoped to identity/auth
//! events. Each otto-* service that builds a domain database on top of
//! `otto-tenant` owns its own separate `audit_events` table (and its own
//! action namespace) for its own domain events — this one is not shared.

use crate::db::{Db, Tx, Unpinned};
use crate::error::{Error, Result};
use crate::ids::{OrgId, UserId};
use serde::Serialize;
use sqlx::FromRow;

/// Stable action names. Use these constants rather than string literals at call
/// sites — a typo in a literal produces an event nobody will ever find.
pub mod action {
    // Authentication (usually global: no org context yet).
    pub const LOGIN_SUCCEEDED: &str = "auth.login.succeeded";
    pub const LOGIN_FAILED: &str = "auth.login.failed";
    pub const LOGOUT: &str = "auth.logout";
    pub const RECOVERY_CODE_USED: &str = "auth.recovery_code.used";
    pub const EMAIL_VERIFIED: &str = "auth.email.verified";
    pub const PASSKEY_REGISTERED: &str = "auth.passkey.registered";
    pub const PASSKEY_CLEARED: &str = "auth.passkey.cleared";
    pub const PASSKEY_REMOVED: &str = "auth.passkey.removed";
    pub const PASSKEY_RENAMED: &str = "auth.passkey.renamed";
    /// A registration ceremony refused for belonging to a different account
    /// than the caller expected: a substituted or hijacked ceremony.
    /// Best-effort, written outside the rolled-back transaction (see
    /// `otto_auth::passkeys::finish_registration`), so a hijack attempt leaves
    /// a trace even though nothing about the attempt itself is durable.
    pub const PASSKEY_REGISTRATION_REFUSED: &str = "auth.passkey.registration_refused";
    /// A `claim/finish` request that rolled back — a ceremony/claim ownership
    /// mismatch, or a failure partway through registration. Best-effort,
    /// written outside the rolled-back transaction, so the admin-assisted-
    /// recovery path still leaves a trace when a completion attempt is
    /// refused, not only when one succeeds (`PASSKEY_REGISTERED` with
    /// `via = "claim"`).
    pub const CLAIM_REFUSED: &str = "auth.claim.refused";

    // OAuth / tokens (org-scoped: the org is bound at authorization time).
    pub const CLIENT_REGISTERED: &str = "oauth.client.registered";
    pub const AUTHORIZATION_GRANTED: &str = "oauth.authorization.granted";
    pub const TOKEN_ISSUED: &str = "oauth.token.issued";
    pub const TOKEN_REFRESHED: &str = "oauth.token.refreshed";
    pub const TOKEN_REVOKED: &str = "oauth.token.revoked";
    /// A replayed refresh token. Treated as theft: the whole chain is revoked.
    /// This is the highest-signal line in the table — alert on it.
    pub const REFRESH_REUSE_DETECTED: &str = "oauth.refresh.reuse_detected";
    pub const PAT_MINTED: &str = "oauth.pat.minted";
    pub const PAT_REVOKED: &str = "oauth.pat.revoked";

    // Org administration.
    pub const MEMBER_INVITED: &str = "org.member.invited";
    pub const MEMBER_JOINED: &str = "org.member.joined";
    pub const MEMBER_ROLE_CHANGED: &str = "org.member.role_changed";
    pub const MEMBER_REMOVED: &str = "org.member.removed";
    pub const MEMBER_PASSKEYS_RESET: &str = "org.member.passkeys_reset";
    pub const IDP_CONNECTED: &str = "org.idp.connected";
    pub const IDP_DISCONNECTED: &str = "org.idp.disconnected";
    pub const DOMAIN_CLAIMED: &str = "org.domain.claimed";
    pub const DOMAIN_VERIFIED: &str = "org.domain.verified";
    pub const DOMAIN_UNCLAIMED: &str = "org.domain.unclaimed";
    pub const ENFORCE_SSO_CHANGED: &str = "org.enforce_sso.changed";
    pub const PLAN_CHANGED: &str = "org.plan.changed";
}

/// One recorded event. Built with the fluent constructors rather than a struct
/// literal so adding a field later does not break every call site.
#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub actor_user_id: Option<UserId>,
    pub actor_label: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<serde_json::Value>,
}

impl Entry {
    pub fn new(action: &str) -> Self {
        Self {
            action: action.to_string(),
            ..Default::default()
        }
    }

    pub fn actor(mut self, user: UserId) -> Self {
        self.actor_user_id = Some(user);
        self
    }

    pub fn actor_label(mut self, label: impl Into<String>) -> Self {
        self.actor_label = Some(label.into());
        self
    }

    pub fn target(mut self, kind: &str, id: impl Into<String>) -> Self {
        self.target_type = Some(kind.to_string());
        self.target_id = Some(id.into());
        self
    }

    /// Caller IP and user agent, as seen at the HTTP boundary.
    pub fn from_request(mut self, ip: Option<&str>, user_agent: Option<&str>) -> Self {
        self.ip = ip.map(str::to_string);
        self.user_agent = user_agent.map(str::to_string);
        self
    }

    /// Extra context. **Never put a secret, token, or credential here** — org
    /// admins read this table in the console.
    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

impl Entry {
    async fn write<'e, E>(self, org: Option<OrgId>, conn: E) -> Result<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(INSERT_SQL)
            .bind(org)
            .bind(self.actor_user_id)
            .bind(self.actor_label)
            .bind(self.action)
            .bind(self.target_type)
            .bind(self.target_id)
            .bind(self.ip)
            .bind(self.user_agent)
            .bind(self.detail.unwrap_or_else(|| serde_json::json!({})))
            .execute(conn)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    pub org_id: Option<OrgId>,
    pub actor_user_id: Option<UserId>,
    pub actor_label: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

const AUDIT_COLS: &str = "id, org_id, actor_user_id, actor_label, action, target_type, \
                          target_id, ip, user_agent, detail, created_at";

const INSERT_SQL: &str = "INSERT INTO audit_events \
     (org_id, actor_user_id, actor_label, action, target_type, target_id, ip, user_agent, detail) \
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)";

/// Most rows one call to either reader returns, whatever the caller asked for.
const MAX_TRAIL: i64 = 1000;

impl Tx<'_> {
    /// Record an org-scoped event **in the same transaction as the change it
    /// describes**. If the change rolls back, so does its record.
    pub async fn audit(&mut self, e: Entry) -> Result<()> {
        let org = self.org();
        e.write(Some(org), self.conn()).await
    }

    /// Read the org's audit trail, newest first. Powers the console's security
    /// page and any customer SIEM export.
    pub async fn audit_trail(
        &mut self,
        action_prefix: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        let org = self.org();
        let events = sqlx::query_as(&format!(
            "SELECT {AUDIT_COLS} FROM audit_events \
             WHERE org_id = $1 AND ($2::text IS NULL OR action LIKE $2 || '%') \
             ORDER BY created_at DESC, id DESC LIMIT $3"
        ))
        .bind(org)
        .bind(action_prefix)
        .bind(limit.clamp(1, MAX_TRAIL))
        .fetch_all(self.conn())
        .await?;
        Ok(events)
    }
}

/// Global actions whose row involves a **second account** besides its actor:
/// the actor is the account a ceremony or claim code proved, and the request
/// that was refused came from — or named — somebody else.
///
/// The actor still deserves to know the attempt happened, so the row is
/// returned to them, but with its `detail`, `ip` and `user_agent` emptied:
/// `detail` names the other account (`attemptedBy`, or a claim refusal's
/// reason, which embeds the claimed account's id), and the address and agent
/// are the other request's, not the actor's own.
const CROSS_ACCOUNT_ACTIONS: &[&str] =
    &[action::PASSKEY_REGISTRATION_REFUSED, action::CLAIM_REFUSED];

/// The `detail` keys a user may read back on their own global rows. An
/// allowlist rather than a denylist so a writer that later adds a key does not
/// silently publish it to the account holder: anything not named here is
/// dropped until somebody decides it is theirs to see.
///
/// - `method` — `passkey` or `sso`, on sign-in rows.
/// - `via` — how a passkey was registered (`signup`, `add`, `claim`).
/// - `reason` — why a sign-in was refused. A writer must never put another
///   account's identity in a `reason`; the one that does (`auth.claim.refused`)
///   is in [`CROSS_ACCOUNT_ACTIONS`] and loses its whole `detail`.
const SELF_VISIBLE_DETAIL: &[&str] = &["method", "via", "reason"];

impl AuditEvent {
    /// Narrow a global row to what its own actor may read. See
    /// [`CROSS_ACCOUNT_ACTIONS`] and [`SELF_VISIBLE_DETAIL`].
    fn redacted_for_actor(mut self) -> Self {
        if CROSS_ACCOUNT_ACTIONS.contains(&self.action.as_str()) {
            self.ip = None;
            self.user_agent = None;
            self.detail = serde_json::json!({});
            return self;
        }
        if let serde_json::Value::Object(map) = &mut self.detail {
            map.retain(|key, _| SELF_VISIBLE_DETAIL.contains(&key.as_str()));
        } else {
            self.detail = serde_json::json!({});
        }
        self
    }
}

impl Db {
    /// Read one user's **own global** audit trail, newest first: the rows with
    /// no org (`org_id IS NULL`) whose actor is `user`. Powers the console's
    /// account-level security activity page (`GET /api/me/audit`). Same
    /// columns, prefix filter and limit clamp as [`Tx::audit_trail`].
    ///
    /// **What "own" means.** Attribution is `actor_user_id`, and only that. So:
    ///
    /// - Sign-ins (succeeded, and refused once a credential had identified the
    ///   account), sign-outs, and passkey registration, removal and renaming
    ///   are all here.
    /// - A failed sign-in that never identified an account — an unknown
    ///   credential, a forged assertion — has no actor and so is **not
    ///   attributable**: it is nobody's to read, and it is not here. Neither is
    ///   anything else written with no actor (a dynamic client registration).
    /// - A row about this user that somebody else acted on is not here either:
    ///   an admin clearing this account's passkeys (`auth.passkey.cleared`) is
    ///   the admin's row, carrying the admin's address. The org-scoped record
    ///   of the same reset (`org.member.passkeys_reset`) is in that org's own
    ///   trail, which is the org admins' to read.
    /// - Org-scoped rows the user acted on are excluded even though they are
    ///   the actor: an org's trail is read through [`Tx::audit_trail`], by the
    ///   org's admins, and the console does not offer a second path around
    ///   that role check.
    ///
    /// Rows are narrowed before they are returned — `detail` to an allowlist
    /// of keys, and the cross-account refusals to no `detail`, `ip` or
    /// `user_agent` at all — so nothing about a second account reaches the
    /// first. See [`SELF_VISIBLE_DETAIL`] and [`CROSS_ACCOUNT_ACTIONS`].
    ///
    /// **Unpinned on purpose.** Global rows are readable only from the
    /// unpinned control plane (`audit_events_control_plane_read`, 0015), so
    /// this runs on the pool, never on a [`Tx`]: a pinned transaction sees
    /// only its own org's rows and never a `NULL`-org one. That policy admits
    /// *every* global row to the control plane — it has no per-request
    /// identity to filter on — so the `WHERE` clause, not RLS, is what
    /// confines the result to one user, which is why it names `user` and
    /// `org_id IS NULL` explicitly rather than trusting any policy to do it.
    /// The same holds where the connecting role is exempt from RLS altogether.
    ///
    /// Served by `audit_events_actor_idx (actor_user_id, created_at DESC)`.
    pub async fn audit_trail_for_user(
        &self,
        user: UserId,
        action_prefix: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        let events: Vec<AuditEvent> = sqlx::query_as(&format!(
            "SELECT {AUDIT_COLS} FROM audit_events \
             WHERE org_id IS NULL AND actor_user_id = $1 \
               AND ($2::text IS NULL OR action LIKE $2 || '%') \
             ORDER BY created_at DESC, id DESC LIMIT $3"
        ))
        .bind(user)
        .bind(action_prefix)
        .bind(limit.clamp(1, MAX_TRAIL))
        .fetch_all(self.pool())
        .await?;
        Ok(events
            .into_iter()
            .map(AuditEvent::redacted_for_actor)
            .collect())
    }

    /// Record an event with no org context — a login attempt, a passkey
    /// enrollment.
    ///
    /// Best-effort by design: this returns `Result`, but callers on the failed-
    /// login path should log an error and continue rather than turning an audit
    /// write failure into an authentication outage. Losing one audit row is bad;
    /// refusing every login because the audit table is unavailable is worse.
    pub async fn audit_global(&self, e: Entry) -> Result<()> {
        e.write(None, self.pool()).await
    }

    /// Record an org-scoped event from the control plane, where no tenant
    /// transaction is open (e.g. membership changes made during signup).
    pub async fn audit_for_org(&self, org: OrgId, e: Entry) -> Result<()> {
        e.write(Some(org), self.pool()).await
    }

    /// Record a global (no-org) event on an unpinned transaction the caller
    /// already holds open — typically one that also carries the change the
    /// event describes, so both commit or roll back together.
    ///
    /// Takes `&mut Unpinned` rather than a bare `E: sqlx::PgExecutor<'e>` on
    /// purpose: an earlier, more permissive signature compiled against a
    /// pinned [`Tx`]'s connection too. [`Unpinned`] is only ever produced by
    /// [`Db::begin_unpinned`], and a pinned `Tx` has no accessor that yields
    /// one — `Tx::conn()` hands out a bare `&mut PgConnection` — so passing a
    /// `Tx`'s connection directly is now a compile error the type catches
    /// wherever a caller reaches for it, not a policy `WITH CHECK` catching
    /// it at runtime or a doc comment asking nicely.
    ///
    /// That compile-time guarantee covers provenance, not session state: the
    /// caller could in principle run `set_config('app.org_id', …)` through
    /// `Unpinned::conn()` by hand between opening the transaction and calling
    /// this function, which the type alone cannot see. This function closes
    /// that residual gap itself, at runtime: it re-reads `app.org_id` at the
    /// start of every call and refuses — before writing anything — if the
    /// transaction has been pinned since it was opened. This is the only
    /// guard on the deployment shape that matters most where RLS is bypassed
    /// (the connecting role is a superuser or BYPASSRLS): the database itself
    /// would not have caught a `NULL`-org write on a pinned connection at
    /// all, so this check is not redundant with anything the database does.
    ///
    /// Unlike [`Self::audit_global`], a failure here is **not** swallowed: it
    /// propagates to the caller, who is expected to let it abort the
    /// transaction. Use this only when a lost audit row would be worse than
    /// failing the whole operation — `Db::audit_global`'s own doc comment
    /// explains why the *pool* variant is deliberately best-effort for the
    /// ordinary login/enrollment path; this is the exception for a caller
    /// that decided the tradeoff the other way. Use [`Tx::audit`] for
    /// anything running on a pinned connection.
    pub async fn audit_global_on(conn: &mut Unpinned, e: Entry) -> Result<()> {
        let pinned: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('app.org_id', true), '')")
                .fetch_one(conn.conn())
                .await?;
        if pinned.is_some() {
            return Err(Error::Invalid(
                "audit_global_on was called on a transaction with app.org_id set — \
                 it was opened via begin_unpinned but has since been pinned to an \
                 org, so writing a NULL-org audit row through it would be silently \
                 wrong on a deployment where RLS is bypassed. Use Tx::audit for an \
                 org-scoped write, or call audit_global_on before pinning the \
                 transaction."
                    .to_string(),
            ));
        }
        e.write(None, conn.conn()).await
    }
}
