//! The registry of resource servers this authorization server mints tokens
//! for (`resource_servers`, migration 0007).
//!
//! Each otto-* service is a resource server: it owns an RFC 8707 resource
//! indicator (the audience its tokens are bound to) and the scopes that mean
//! something to it. The AS used to serve exactly one audience with
//! otto-factory's scope list compiled in; now every authorize, code
//! redemption, refresh, and PAT is checked against the row for the resource it
//! names, so otto-flags can register its own scopes without otto-factory's
//! leaking into its tokens or consent screens.
//!
//! An operator registers a resource server with `otto-platform-server
//! resource register`, which calls [`register`]: an idempotent upsert of its
//! name and scopes, safe to run again whenever the service's scopes change.
//! The services themselves run against their own databases and never call it.
//! Disabling a resource server, issuing its introspection credential, and
//! assigning or renaming its service slug ([`set_service`],
//! [`rename_service`]) are separate operator actions and are never touched by
//! `register`.
//!
//! So is moving a server to a new canonical URI ([`rename`]). The old URI
//! stays behind as a time-boxed alias (`resource_server_aliases`, migration
//! 0026) that [`resolve`] and introspection authentication still accept until
//! its sunset or [`drop_alias`]. Alias rows are tombstones: neither
//! `register` nor `rename` ever hands out a URI that is, or was, an alias.
//!
//! # Lock order
//!
//! The one statement of the lock order of every path that writes a resource
//! server's rows or the rows keyed by it. Migrations 0024 and 0026 and
//! `otto_billing::usage` point here; change them together. Each path takes
//! its locks in the order listed.
//!
//! - **Usage ingest** (`POST /internal/usage`, one transaction per org, run
//!   with `lock_timeout = 5s`): the org's ingest lock (advisory
//!   `(0x0055_1001, hashtext(org))`, `otto_billing::usage::lock_org_ingest`);
//!   then, per event, the usage-ledger lock of the caller's URI, shared
//!   (advisory `(USAGE_LEDGER_LOCK_NAMESPACE, hashtext(uri))`, taken by
//!   `claim_usage_event`); then the ingest statement's rows. Its pool, budget
//!   and alert writes take `ROW EXCLUSIVE` on their tables and `FOR KEY
//!   SHARE` on the caller's `resource_servers` row (the service foreign keys
//!   of 0024). A lost lock wait, a deadlock or a cancel
//!   ([`otto_tenant::is_retryable_lock_failure`]) is a retriable 503.
//! - **`rename-service`** ([`rename_service`], the SQL function of 0024):
//!   `SHARE ROW EXCLUSIVE` on `org_service_period_usage`, `service_budgets`
//!   and `budget_alerts`; then the server's row, `FOR UPDATE`; then its meters
//!   and price versions, and the cascades into the three tables. 2 s lock
//!   timeout, 30 s statement timeout.
//! - **`set-service`** ([`set_service`]): `SHARE ROW EXCLUSIVE` on the same
//!   three tables, as rename-service takes them (so it waits for every open
//!   ingest transaction that has written one, and for a running
//!   rename-service); then the server's row (the update); then the cascades
//!   into the tables. 5 s lock timeout.
//! - **`rename`** ([`rename`]): the URI-namespace advisory lock; then the
//!   alias row of the new URI, if any, `FOR UPDATE` (the swap check); then the
//!   rows of the server's usable access tokens, refresh tokens and
//!   authorization codes (the rewrites); then the usage-ledger lock of every URI of the
//!   server (old, new and each alias), exclusive, in key order; then the
//!   server's row (the key update, whose cascades take its webhook deliveries
//!   and alias rows); then its usage dedupe entries. 5 s lock timeout, 30 s
//!   statement timeout.
//! - **`register`** ([`register`]): the URI-namespace lock; then the URI's
//!   alias row, if any; then the server's row (the upsert, which changes no
//!   key and so does not conflict with `FOR KEY SHARE`).
//! - **`drop-alias`** ([`drop_alias`]): the URI-namespace lock; then the alias
//!   row; then the token and code rows still bound to the alias.
//! - **User paths** (org deletion in `otto_core::orgs`, member removal in
//!   `otto-web`): token and code rows first (the revocations); then `FOR KEY
//!   SHARE` on every resource server row with a webhook, through
//!   `otto_core::lifecycle::enqueue`'s insert into `webhook_deliveries`. A
//!   path that revokes tokens and enqueues an event does it in that order.
//!   Team deletion revokes nothing and takes only the enqueue's `FOR KEY
//!   SHARE`.
//! - **Token refresh** ([`crate::tokens::redeem_refresh`], one transaction):
//!   the presented refresh token's row, `FOR UPDATE`; then the new token rows
//!   it inserts. It only reads `resource_servers`, so it waits on nothing a
//!   rename holds; a rename rewriting that refresh row waits for it.
//! - **Code redemption** ([`crate::oauth::redeem_code`], one transaction):
//!   the code's row (the claim); then the new token rows. Like refresh, it
//!   reads `resource_servers` and waits on nothing else. Both run entirely on
//!   their transaction's connection (never a second pool connection under
//!   the row lock, which lets concurrent redemptions of one grant exhaust the
//!   pool), with a 5 s lock timeout that the token endpoint answers with a
//!   retriable 503.
//! - **Revocations** (member removal and replay detection in
//!   [`crate::tokens`], org deletion, `drop-alias`): first the matching live
//!   refresh rows, then the matching unredeemed code rows, `FOR UPDATE`;
//!   then the updates of access tokens, refresh tokens and codes. The locks
//!   make a revocation wait for any refresh or code redemption in flight, so
//!   its updates (each a fresh snapshot) see and revoke the pair it minted.
//!   A redemption holds one row and waits for nothing, so this cannot cycle
//!   with it. Two revocations of overlapping rows (two replay detections in
//!   one family, a removal and a deletion) can deadlock at the row level;
//!   Postgres detects it and fails one.
//!
//! Why none of them deadlock:
//!
//! - `rename` and the user paths both take token rows before resource server
//!   rows. (Taking the server's row first deadlocks against an org deletion
//!   that holds the org's token rows and waits to enqueue its event.) Inside
//!   one token table they can still deadlock at the row level: the rename's
//!   rewrite and an org deletion's revocation lock overlapping sets of rows in
//!   no agreed order. Postgres detects it and aborts one; the rename reports
//!   that as busy, run it again, and the user path may surface a server
//!   error. It needs a rename and a revocation of the same tokens in the same
//!   instant, so it is rare.
//! - `rename` and ingest both take the ledger lock before the server's row.
//!   While `rename` waits for a ledger lock it holds only the namespace lock
//!   and token rows, which ingest never takes. Ingest of every other server
//!   takes other ledger keys and never waits for it.
//! - `rename-service` and `set-service` take `SHARE ROW EXCLUSIVE` on the
//!   service tables before the server's row. That conflicts with ingest's
//!   `ROW EXCLUSIVE`, so they wait, holding no row, until every ingest that
//!   has written the tables commits, and ingest arriving later waits for
//!   them. (A weaker lock deadlocks: an ingest holding an existing pool row
//!   then needs `FOR KEY SHARE` on the server's row for a new period's pool,
//!   while `set-service` holds that row and its cascade waits for the pool
//!   row.) The two conflict with each other too, so one waits for the other
//!   before touching the row.
//! - `register`, `rename` and `drop-alias` are serialized by the namespace
//!   lock, and `drop-alias` takes no resource server row.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;
use serde::Serialize;

use crate::crypto::{self, Secret};
use crate::error::{AuthError, Result};

/// Prefix for a resource server's introspection credential.
pub const INTROSPECTION_SECRET_PREFIX: &str = "otto_rs_";

/// Prefix for the key a resource server verifies lifecycle webhooks with.
pub const WEBHOOK_SECRET_PREFIX: &str = "otto_whsec_";

/// Longest scope description accepted, in characters. A description is one
/// line on a consent screen, not documentation; a cap keeps a registry typo
/// (or a pasted README) from turning the screen into a wall of text.
pub const MAX_SCOPE_DESCRIPTION_CHARS: usize = 200;

/// What a resource server declares about itself.
#[derive(Debug, Clone, Copy)]
pub struct ResourceServerSpec<'a> {
    /// Its RFC 8707 resource indicator, e.g. `https://otto-factory.savvagent.com/mcp`.
    pub resource_uri: &'a str,
    /// Shown on the consent screen.
    pub name: &'a str,
    /// Every scope it understands.
    pub scopes: &'a [&'a str],
    /// Granted when a client asks for none. Must be a subset of `scopes`.
    pub default_scopes: &'a [&'a str],
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ResourceServer {
    pub resource_uri: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    /// Optional human-readable text for some of `scopes`, keyed by scope name,
    /// shown on the consent screen in place of the bare name. Every key is
    /// one of `scopes` (enforced by [`set_scope_descriptions`] and by a CHECK
    /// constraint). Single-language: the consent screen's own text is
    /// localized, these are shown exactly as registered.
    pub scope_descriptions: sqlx::types::Json<BTreeMap<String, String>>,
    pub disabled: bool,
    /// Where lifecycle webhooks are delivered, if configured. The signing
    /// secret is never part of this struct; see [`set_webhook`].
    pub webhook_url: Option<String>,
    /// The service slug its value meters, usage pools and budgets are keyed
    /// by (`<service>/<meter>`), assigned by an operator with [`set_service`].
    /// `None` until then, and a server without one cannot declare meters.
    pub service: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLS: &str = "resource_uri, name, scopes, default_scopes, scope_descriptions, disabled, \
                    webhook_url, service, created_at, updated_at";

/// [`COLS`] qualified by the alias `rs`, for queries that join another table.
static RS_COLS: LazyLock<String> = LazyLock::new(|| {
    COLS.split(',')
        .map(|c| format!("rs.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
});

/// Longest service slug accepted, matching the `resource_servers_service_slug`
/// CHECK (migration 0017).
pub const MAX_SERVICE_SLUG_LEN: usize = 63;

/// Whether `slug` is a valid service slug: `^[a-z][a-z0-9-]{0,62}$`, the same
/// rule as the CHECK constraint, so a bad one is refused with a readable
/// message before it reaches the database.
pub fn is_service_slug(slug: &str) -> bool {
    let mut bytes = slug.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && slug.len() <= MAX_SERVICE_SLUG_LEN
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

impl ResourceServer {
    /// The registered description of `scope`, if it has one.
    pub fn scope_description(&self, scope: &str) -> Option<&str> {
        self.scope_descriptions.get(scope).map(String::as_str)
    }

    /// The scopes a request for `requested` on this resource server is
    /// granted: its defaults when nothing is requested, otherwise exactly what
    /// was asked for, provided every one is a scope this server defines.
    ///
    /// An unknown scope is rejected rather than dropped. Silently dropping a
    /// requested scope hands a client a token that does less than it
    /// believes, which fails later and confusingly.
    pub fn grant_scopes(&self, requested: &[String]) -> Result<Vec<String>> {
        if requested.is_empty() {
            return Ok(self.default_scopes.clone());
        }
        let mut granted: Vec<String> = Vec::with_capacity(requested.len());
        for s in requested {
            if !self.scopes.iter().any(|known| known == s) {
                return Err(AuthError::InvalidScope(format!(
                    "unknown scope {s:?} for {}; supported scopes are {}",
                    self.resource_uri,
                    self.scopes.join(" ")
                )));
            }
            if !granted.contains(s) {
                granted.push(s.clone());
            }
        }
        Ok(granted)
    }

    /// The refusal for a request that named no scope on a resource server
    /// with no default scopes, i.e. one [`Self::grant_scopes`] resolved to
    /// nothing. Both issuance paths that resolve an empty request
    /// (`oauth::validate_authorize` and `tokens::mint_pat`) refuse with this,
    /// so the two cannot drift apart. Kept out of `grant_scopes` because
    /// "empty means the defaults" is that method's contract for every caller.
    pub(crate) fn no_scope_requested(&self) -> AuthError {
        AuthError::InvalidScope(format!(
            "no scope was requested and {} has no default scopes; request one of: {}",
            self.resource_uri,
            self.scopes.join(" ")
        ))
    }
}

/// Register a resource server, or update the name and scopes of one already
/// registered. Idempotent, so a service can call it at every startup with the
/// scopes compiled into it.
///
/// Leaves `disabled` and the introspection credential alone: re-registering
/// must never re-enable a server an operator disabled. It also keeps scope
/// descriptions (see [`set_scope_descriptions`]), dropping only those of
/// scopes the new list no longer contains, so a service that re-registers at
/// startup does not erase what an operator wrote.
///
/// A URI that is an alias of a resource server, live, expired or dropped, is
/// refused (see [`rename`]): a retired URI is never reused.
pub async fn register(db: &Db, spec: ResourceServerSpec<'_>) -> Result<ResourceServer> {
    validate_resource_uri(spec.resource_uri)?;
    let name = spec.name.trim();
    if name.is_empty() {
        return Err(AuthError::InvalidRequest(
            "a resource server needs a name".into(),
        ));
    }
    let scopes = validate_scope_list("scopes", spec.scopes)?;
    if scopes.is_empty() {
        return Err(AuthError::InvalidRequest(
            "a resource server must define at least one scope".into(),
        ));
    }
    let default_scopes = validate_scope_list("default_scopes", spec.default_scopes)?;
    if let Some(stray) = default_scopes.iter().find(|d| !scopes.contains(d)) {
        return Err(AuthError::InvalidRequest(format!(
            "default scope {stray:?} is not one of the resource server's scopes"
        )));
    }

    // A retired URI, in any state, is never given to a server again: not
    // even to the one it names, which is registered under its canonical URI.
    let mut tx = db.begin_unpinned().await?;
    lock_uri_namespace(tx.conn()).await?;
    if let Some(alias) = alias_row(tx.conn(), spec.resource_uri).await? {
        return Err(alias_taken(spec.resource_uri, &alias));
    }
    let row = sqlx::query_as(&format!(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (resource_uri) DO UPDATE SET \
           name = EXCLUDED.name, \
           scopes = EXCLUDED.scopes, \
           default_scopes = EXCLUDED.default_scopes, \
           scope_descriptions = COALESCE(( \
             SELECT jsonb_object_agg(d.key, d.value) \
             FROM jsonb_each(resource_servers.scope_descriptions) d \
             WHERE d.key = ANY(EXCLUDED.scopes)), '{{}}'::jsonb), \
           updated_at = now() \
         RETURNING {COLS}"
    ))
    .bind(spec.resource_uri)
    .bind(name)
    .bind(&scopes)
    .bind(&default_scopes)
    .fetch_one(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Replace the whole set of scope descriptions of a resource server; an empty
/// slice clears them. Replacing rather than merging keeps removal possible
/// without a second verb, and a caller that wants to change one description
/// reads [`ResourceServer::scope_descriptions`] first.
///
/// Every key must be a scope the server defines, and every description
/// non-empty after trimming, at most [`MAX_SCOPE_DESCRIPTION_CHARS`]
/// characters, and free of control characters (it is rendered on one line).
/// Markup is fine to store: the consent screen escapes it.
pub async fn set_scope_descriptions(
    db: &Db,
    resource_uri: &str,
    descriptions: &[(&str, &str)],
) -> Result<ResourceServer> {
    let rs = get(db, resource_uri).await?.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })?;
    let map = validate_scope_descriptions(&rs.scopes, descriptions)?;

    // Written against the scopes as they are now, not as read above: a
    // concurrent re-register that dropped a scope trips the CHECK instead of
    // leaving an orphan description.
    let row = sqlx::query_as(&format!(
        "UPDATE resource_servers SET scope_descriptions = $2, updated_at = now() \
         WHERE resource_uri = $1 RETURNING {COLS}"
    ))
    .bind(resource_uri)
    .bind(sqlx::types::Json(&map))
    .fetch_one(db.pool())
    .await?;
    Ok(row)
}

/// Assign a resource server's service slug: the name its value meters are
/// declared under (`<service>/<meter>`) and its usage pools and budgets are
/// keyed by. An operator action, never part of [`register`], so a service
/// cannot pick (or take over) a name for itself.
///
/// Setting the slug it already has is a no-op. A slug held by another resource
/// server is refused, and so is renaming a service that has declared meters:
/// everything keyed by the old name would be stranded (use [`rename_service`]).
///
/// Changing the slug carries the service's unmetered usage pools with it (a
/// cascading foreign key, migration 0024); before 0024 they stayed under the
/// old slug. A pool an earlier service of the target name left behind would
/// collide with a moved one, and that is refused too.
///
/// It locks the service tables against writes before it touches the server's
/// row, as [`rename_service`] does (see the module's lock order), so neither
/// that nor usage ingest can deadlock with it; usage ingest waits for it. A
/// lost lock wait (5 s) or a deadlock all the same changes nothing and says
/// to run it again.
pub async fn set_service(db: &Db, resource_uri: &str, service: &str) -> Result<ResourceServer> {
    if !is_service_slug(service) {
        return Err(AuthError::InvalidRequest(format!(
            "service {service:?} must be a lower-case slug: a letter, then up to 62 \
             letters, digits or hyphens"
        )));
    }
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(tx.conn())
        .await?;
    // SHARE ROW EXCLUSIVE, as rename-service takes it: it waits for every
    // ingest that has written these tables, so none can hold a pool row this
    // cascade needs while waiting for the server row this update holds.
    sqlx::query(
        "LOCK TABLE org_service_period_usage, service_budgets, budget_alerts \
         IN SHARE ROW EXCLUSIVE MODE",
    )
    .execute(tx.conn())
    .await
    .map_err(|e| set_service_error(e, resource_uri, service))?;
    let row: Option<ResourceServer> = sqlx::query_as(&format!(
        "UPDATE resource_servers SET service = $2, updated_at = now() \
         WHERE resource_uri = $1 RETURNING {COLS}"
    ))
    .bind(resource_uri)
    .bind(service)
    .fetch_optional(tx.conn())
    .await
    .map_err(|e| set_service_error(e, resource_uri, service))?;
    tx.commit().await?;
    row.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })
}

fn set_service_error(e: sqlx::Error, resource_uri: &str, service: &str) -> AuthError {
    match &e {
        sqlx::Error::Database(d)
            if d.is_unique_violation()
                && d.constraint() == Some("resource_servers_service_key") =>
        {
            AuthError::InvalidRequest(format!(
                "service {service:?} is already assigned to another resource server"
            ))
        }
        // The cascade moving the pools hit one already under the new slug.
        sqlx::Error::Database(d) if d.is_unique_violation() => AuthError::InvalidRequest(format!(
            "service {service:?} still has usage pools from an earlier service of that name; \
             {resource_uri:?} cannot be moved onto them"
        )),
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
            AuthError::InvalidRequest(format!(
                "{resource_uri:?} has declared meters under its current service; \
                 it cannot be renamed to {service:?}"
            ))
        }
        _ if otto_tenant::is_retryable_lock_failure(&e) => AuthError::InvalidRequest(format!(
            "{resource_uri:?} was busy (a rename-service or usage ingest held its rows) and \
             set-service gave up waiting; nothing changed, run it again"
        )),
        _ => AuthError::Db(e),
    }
}

/// What [`rename_service`] did.
#[derive(Debug, Clone)]
pub struct ServiceRename {
    /// The slug the resource server had.
    pub previous_service: String,
    /// The resource server as it is now.
    pub resource: ResourceServer,
    /// How many rows of each kind moved to the new slug.
    pub moved: ServiceRenameCounts,
}

/// Rows [`rename_service`] re-keyed, by kind. All zero when the slug did not
/// change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceRenameCounts {
    pub meters: i64,
    pub price_versions: i64,
    /// `org_service_period_usage` rows, every org's.
    pub service_pools: i64,
    pub service_budgets: i64,
    pub budget_alerts: i64,
}

/// Rename a resource server's service slug after it has declared meters: the
/// one change [`set_service`] refuses. Its meters (`<old>/<m>` becomes
/// `<new>/<m>`), their price versions, and every org's service pools, budgets
/// and budget alerts move to the new slug in one transaction.
///
/// Allowed only while nothing under the old meters records money: no metered
/// usage events or per-meter totals, no Stripe meter or price, no queued Stripe
/// meter event. Otherwise it is refused with every blocker and its count
/// named. Unmetered usage does not block; its pool moves.
///
/// **Pause the service's usage shipping first.** A batch in flight cannot
/// strand rows under the old slug (foreign keys and a table lock in migration
/// 0024 see to that), but it is refused with a retriable 503, and on retry a
/// metered event naming an old meter key is rejected as `unknown_meter` for
/// good. While the rename runs, all usage ingest waits for it. It gives up,
/// changing nothing, after a 2 s lock wait or a 30 s statement.
///
/// [`rename_service_dry_run`] runs the same checks and changes nothing, and
/// [`service_blockers`] reads the blocker counts alone.
///
/// The checks and the re-keys run in the `rename_service` SQL function
/// (migration 0024), a SECURITY DEFINER that sees every org's rows. A plain
/// transaction on a role that is neither superuser nor BYPASSRLS would see
/// none of the row-level-secured ones, find no blockers and move nothing.
///
/// Renaming to the slug it already has is a no-op. A resource server with no
/// slug yet is refused: [`set_service`] assigns the first one.
pub async fn rename_service(db: &Db, resource_uri: &str, service: &str) -> Result<ServiceRename> {
    rename_service_tx(db, resource_uri, service, Finish::Commit)
        .await
        .map_err(|f| f.error)
}

/// What [`rename_service_dry_run`] found.
#[derive(Debug)]
pub enum ServiceRenameDryRun {
    /// It would succeed, moving this much.
    WouldRename(Box<ServiceRename>),
    /// The data refuses it (billing data under the meters, the slug taken, no
    /// service yet); the error says what. Running it again changes nothing.
    Refused(AuthError),
    /// It gave up waiting for a lock or ran past its statement timeout:
    /// usage ingest was writing. Run it again once shipping is paused.
    Busy(AuthError),
}

/// [`rename_service`] in a transaction that is always rolled back: the same
/// checks and the same refusals, and on success the counts it would move,
/// with nothing changed. It takes the same locks for as long as it runs, so
/// usage ingest waits for it as it would for the rename.
///
/// An unknown resource server or a malformed slug is an `Err`, as for the
/// rename; what the rename's own checks decide is an `Ok` answer.
pub async fn rename_service_dry_run(
    db: &Db,
    resource_uri: &str,
    service: &str,
) -> Result<ServiceRenameDryRun> {
    match rename_service_tx(db, resource_uri, service, Finish::RollBack).await {
        Ok(r) => Ok(ServiceRenameDryRun::WouldRename(Box::new(r))),
        Err(RenameServiceFailure { busy: true, error }) => Ok(ServiceRenameDryRun::Busy(error)),
        Err(RenameServiceFailure {
            error: error @ AuthError::InvalidRequest(_),
            ..
        }) if is_service_slug(service) => Ok(ServiceRenameDryRun::Refused(error)),
        Err(f) => Err(f.error),
    }
}

/// A failed rename-service, and whether it was a lost lock wait or a
/// statement timeout rather than a refusal.
struct RenameServiceFailure {
    busy: bool,
    error: AuthError,
}

impl<E: Into<AuthError>> From<E> for RenameServiceFailure {
    fn from(e: E) -> Self {
        Self {
            busy: false,
            error: e.into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Finish {
    Commit,
    RollBack,
}

async fn rename_service_tx(
    db: &Db,
    resource_uri: &str,
    service: &str,
    finish: Finish,
) -> std::result::Result<ServiceRename, RenameServiceFailure> {
    if !is_service_slug(service) {
        return Err(AuthError::InvalidRequest(format!(
            "service {service:?} must be a lower-case slug: a letter, then up to 62 \
             letters, digits or hyphens"
        ))
        .into());
    }
    // Unpinned on purpose: the function refuses an org-pinned transaction,
    // where the tenant policy would show it one org's rows.
    let mut tx = db.begin_unpinned().await?;
    // Here, not on the function: a function's own `SET statement_timeout`
    // does not bound the statement that calls it.
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(tx.conn())
        .await?;
    let row: (String, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT previous_service, meters, price_versions, service_pools, service_budgets, \
                budget_alerts \
         FROM rename_service($1, $2)",
    )
    .bind(resource_uri)
    .bind(service)
    .fetch_one(tx.conn())
    .await
    .map_err(|e| RenameServiceFailure {
        busy: otto_tenant::is_retryable_lock_failure(&e),
        error: rename_error(e, service),
    })?;
    let resource = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE resource_uri = $1"
    ))
    .bind(resource_uri)
    .fetch_one(tx.conn())
    .await?;
    match finish {
        Finish::Commit => tx.commit().await?,
        Finish::RollBack => tx.rollback().await?,
    }
    let (previous_service, meters, price_versions, service_pools, service_budgets, budget_alerts) =
        row;
    Ok(ServiceRename {
        previous_service,
        resource,
        moved: ServiceRenameCounts {
            meters,
            price_versions,
            service_pools,
            service_budgets,
            budget_alerts,
        },
    })
}

/// Rows under a service's meters that record money, by table: each one makes
/// [`rename_service`] refuse. All zero means nothing blocks it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceBlockers {
    pub usage_events: i64,
    pub org_meter_period_usage: i64,
    pub stripe_meters: i64,
    pub stripe_prices: i64,
    pub stripe_meter_outbox: i64,
}

impl ServiceBlockers {
    /// `(table, count)` for each kind, in a fixed order.
    pub fn by_table(&self) -> [(&'static str, i64); 5] {
        [
            ("usage_events", self.usage_events),
            ("org_meter_period_usage", self.org_meter_period_usage),
            ("stripe_meters", self.stripe_meters),
            ("stripe_prices", self.stripe_prices),
            ("stripe_meter_outbox", self.stripe_meter_outbox),
        ]
    }

    pub fn is_empty(&self) -> bool {
        self.by_table().iter().all(|(_, n)| *n == 0)
    }
}

/// What blocks renaming `service` with [`rename_service`], counted across
/// every org (`service_rename_blockers`, migration 0024, a SECURITY DEFINER
/// for the reason `rename_service` is one). Read-only: it takes no lock
/// beyond what a read does, and it changes nothing.
pub async fn service_blockers(db: &Db, service: &str) -> Result<ServiceBlockers> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(tx.conn())
        .await?;
    let (usage_events, org_meter_period_usage, stripe_meters, stripe_prices, stripe_meter_outbox) =
        sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            "SELECT usage_events, org_meter_period_usage, stripe_meters, stripe_prices, \
                    stripe_meter_outbox \
             FROM service_rename_blockers($1)",
        )
        .bind(service)
        .fetch_one(tx.conn())
        .await?;
    tx.rollback().await?;
    Ok(ServiceBlockers {
        usage_events,
        org_meter_period_usage,
        stripe_meters,
        stripe_prices,
        stripe_meter_outbox,
    })
}

/// The `rename_service` function reports each refusal under its own SQLSTATE
/// (see migration 0024) with an operator-readable message, passed on as is.
/// A violation raised by a constraint instead (a race the function's own
/// checks lost) is reworded: its raw text names an index, not the mistake.
fn rename_error(e: sqlx::Error, service: &str) -> AuthError {
    if otto_tenant::is_retryable_lock_failure(&e) {
        return AuthError::InvalidRequest(
            "the rename gave up waiting: usage ingest was writing while it waited, or it ran \
             past its statement timeout, so the service's usage shipping is not paused; \
             nothing changed. Pause it, then run this again"
                .into(),
        );
    }
    let sqlx::Error::Database(d) = &e else {
        return AuthError::Db(e);
    };
    let raised_by_function = d.constraint().is_none();
    let msg = d.message().to_owned();
    match d.code().as_deref() {
        Some("P0002") => AuthError::InvalidTarget(msg),
        // Not a slug; no service yet, or billing data blocks it.
        Some("22023" | "55000") => AuthError::InvalidRequest(msg),
        Some("23505") if raised_by_function => AuthError::InvalidRequest(msg),
        Some("23505") => AuthError::InvalidRequest(format!(
            "service {service:?} is already assigned to another resource server, or has \
             usage pools or budgets left from an earlier service of that name"
        )),
        // A Stripe meter or price created for an old meter after the blocker
        // count; nothing changed, and running it again names the blocker.
        Some("23503") => AuthError::InvalidRequest(format!(
            "billing data appeared under the service's meters while renaming it to \
             {service:?}; nothing changed, run it again to see what blocks it"
        )),
        _ => AuthError::Db(e),
    }
}

/// A retired resource URI that still names its resource server until its
/// sunset, unless dropped first (`resource_server_aliases`, migration 0026).
/// Rows are tombstones: never deleted, so the URI is never reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAlias {
    pub alias_uri: String,
    /// The canonical URI of the server it names.
    pub resource_uri: String,
    pub sunset_at: DateTime<Utc>,
    pub dropped_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Whether it still names its server, by the database's clock when it
    /// was read, the clock every reader of aliases uses.
    pub live: bool,
}

/// Whether an alias works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasState {
    /// Names its server.
    Live,
    /// Past its sunset: a client or server naming it is refused like an
    /// unknown URI.
    Expired,
    /// Ended by an operator: refused like an unknown URI, and the grants
    /// still bound to it were revoked ([`drop_alias`]).
    Dropped,
}

impl AliasState {
    pub fn as_str(self) -> &'static str {
        match self {
            AliasState::Live => "live",
            AliasState::Expired => "expired",
            AliasState::Dropped => "dropped",
        }
    }
}

impl ResourceAlias {
    /// Its state when it was read. Dropped wins over expired.
    pub fn state(&self) -> AliasState {
        if self.dropped_at.is_some() {
            AliasState::Dropped
        } else if self.live {
            AliasState::Live
        } else {
            AliasState::Expired
        }
    }
}

/// The live-alias condition on `resource_server_aliases` named `a`, in SQL:
/// the one definition of [`AliasState::Live`]. Every query here names the
/// alias table `a`.
const LIVE_ALIAS: &str = "(a.dropped_at IS NULL AND a.sunset_at > now())";

/// The columns of a [`ResourceAlias`] (table `a`), `live` computed by the
/// database.
static ALIAS_COLS: LazyLock<String> = LazyLock::new(|| {
    format!("a.alias_uri, a.resource_uri, a.sunset_at, a.dropped_at, a.created_at, {LIVE_ALIAS} AS live")
});

/// SQL for "a token bound to `column` is good for the resource server whose
/// canonical URI is `canonical`": an exact match, or `column` is an alias of
/// that server. Any alias state counts: alias rows are tombstones that only
/// ever name their own server, and the rename rewrites tokens bound to the
/// old URI anyway; this covers one minted under the old URI by a transaction
/// that raced the rename. Both arguments are SQL expressions (a column, a
/// `$n` placeholder), `'static` so they are written in the source and never
/// come from input.
pub fn audience_matches_sql(column: &'static str, canonical: &'static str) -> String {
    format!(
        "({column} = {canonical} OR EXISTS (SELECT 1 FROM resource_server_aliases a_aud \
          WHERE a_aud.alias_uri = {column} AND a_aud.resource_uri = {canonical}))"
    )
}

/// A resource server found by a URI that names it: its canonical URI or a
/// live alias.
#[derive(Debug, Clone)]
pub struct ResolvedResource {
    /// The canonical row. Everything stored or compared (tokens, usage,
    /// dedupe) uses `server.resource_uri`.
    pub server: ResourceServer,
    /// The URI it was named by, exactly as given: the canonical URI or the
    /// alias. Never store or compare by it; only introspection answers with
    /// it, as the `aud` of the server that authenticated as it.
    pub named_as: String,
    /// The alias it was named by, when it was not its canonical URI.
    pub alias: Option<ResourceAlias>,
}

/// [`ResolvedResource`] plus the server's introspection credential hash, read
/// in one statement so a concurrent rename cannot fall between the two.
#[derive(sqlx::FromRow)]
struct ResolvedRow {
    #[sqlx(flatten)]
    server: ResourceServer,
    secret_hash: Option<Vec<u8>>,
    alias_uri: Option<String>,
    alias_sunset_at: Option<DateTime<Utc>>,
    alias_dropped_at: Option<DateTime<Utc>>,
    alias_created_at: Option<DateTime<Utc>>,
}

async fn resolve_row(db: &Db, uri: &str) -> Result<Option<(ResolvedResource, Option<Vec<u8>>)>> {
    let rs_cols = &*RS_COLS;
    // At most one row: a URI is never both canonical and an alias.
    let row: Option<ResolvedRow> = sqlx::query_as(&format!(
        "SELECT {rs_cols}, rs.introspection_secret_hash AS secret_hash, \
                NULL::text AS alias_uri, NULL::timestamptz AS alias_sunset_at, \
                NULL::timestamptz AS alias_dropped_at, NULL::timestamptz AS alias_created_at \
           FROM resource_servers rs WHERE rs.resource_uri = $1 \
         UNION ALL \
         SELECT {rs_cols}, rs.introspection_secret_hash, \
                a.alias_uri, a.sunset_at, a.dropped_at, a.created_at \
           FROM resource_server_aliases a \
           JOIN resource_servers rs ON rs.resource_uri = a.resource_uri \
          WHERE a.alias_uri = $1 AND {LIVE_ALIAS} \
         LIMIT 1"
    ))
    .bind(uri)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(|r| {
        let alias = match (r.alias_uri, r.alias_sunset_at, r.alias_created_at) {
            (Some(alias_uri), Some(sunset_at), Some(created_at)) => Some(ResourceAlias {
                alias_uri,
                resource_uri: r.server.resource_uri.clone(),
                sunset_at,
                dropped_at: r.alias_dropped_at,
                created_at,
                // Only a live alias resolves.
                live: true,
            }),
            _ => None,
        };
        (
            ResolvedResource {
                server: r.server,
                named_as: uri.to_owned(),
                alias,
            },
            r.secret_hash,
        )
    }))
}

/// Find the resource server `uri` names: the one whose canonical URI it is,
/// or the one it is a live alias of. An expired or dropped alias names
/// nothing, exactly like a URI never registered. Disabled servers are
/// returned; callers decide what that means.
pub async fn resolve(db: &Db, uri: &str) -> Result<Option<ResolvedResource>> {
    Ok(resolve_row(db, uri).await?.map(|(r, _)| r))
}

/// Every alias, live or not, by alias URI.
pub async fn aliases(db: &Db) -> Result<Vec<ResourceAlias>> {
    let rows = sqlx::query_as(&format!(
        "SELECT {} FROM resource_server_aliases a ORDER BY a.alias_uri",
        *ALIAS_COLS
    ))
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// The aliases of the resource server whose canonical URI is `resource_uri`,
/// live or not, by alias URI.
pub async fn aliases_of(db: &Db, resource_uri: &str) -> Result<Vec<ResourceAlias>> {
    let rows = sqlx::query_as(&format!(
        "SELECT {} FROM resource_server_aliases a WHERE a.resource_uri = $1 \
         ORDER BY a.alias_uri",
        *ALIAS_COLS
    ))
    .bind(resource_uri)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Serializes every change to the resource-URI namespace ([`register`],
/// [`rename`], [`drop_alias`]) so the "not already a canonical URI or an
/// alias" checks cannot race each other, and so the set of a server's aliases
/// is fixed while a rename runs. Transaction-scoped.
const URI_NAMESPACE_LOCK: i64 = 0x6f74_746f_5f75_7269; // "otto_uri"

/// The first key of the usage-ledger advisory lock, two-key form
/// `(USAGE_LEDGER_LOCK_NAMESPACE, hashtext(uri))`: one lock per resource URI.
/// Taken shared by every usage dedupe claim (`claim_usage_event`, migration
/// 0026, which spells the same number) and exclusively by [`rename`] for every
/// URI of the server it moves, so a rename's ledger rewrite and that server's
/// claims never interleave while every other server's ingest carries on.
/// Distinct from `otto_billing::usage::INGEST_LOCK_NAMESPACE` (`0x0055_1001`),
/// the other two-key advisory lock. Transaction-scoped.
pub const USAGE_LEDGER_LOCK_NAMESPACE: i32 = 0x0055_1002;

async fn lock_uri_namespace(conn: &mut sqlx::PgConnection) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(URI_NAMESPACE_LOCK)
        .execute(conn)
        .await?;
    Ok(())
}

/// Take the usage-ledger lock of every one of `uris` exclusively, in key
/// order (one statement, so the order is the database's), for the rest of the
/// transaction.
async fn lock_usage_ledgers(conn: &mut sqlx::PgConnection, uris: &[String]) -> Result<()> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock($1, k.key) \
           FROM (SELECT DISTINCT hashtext(u) AS key FROM unnest($2::text[]) u) k \
          ORDER BY k.key",
    )
    .bind(USAGE_LEDGER_LOCK_NAMESPACE)
    .bind(uris)
    .execute(conn)
    .await?;
    Ok(())
}

/// The alias row for `uri`, whatever its state, locked.
async fn alias_row(conn: &mut sqlx::PgConnection, uri: &str) -> Result<Option<ResourceAlias>> {
    let row = sqlx::query_as(&format!(
        "SELECT {} FROM resource_server_aliases a WHERE a.alias_uri = $1 FOR UPDATE",
        *ALIAS_COLS
    ))
    .bind(uri)
    .fetch_optional(conn)
    .await?;
    Ok(row)
}

fn alias_taken(uri: &str, alias: &ResourceAlias) -> AuthError {
    let state = match alias.state() {
        AliasState::Live => "a live",
        AliasState::Expired => "an expired",
        AliasState::Dropped => "a dropped",
    };
    AuthError::InvalidRequest(format!(
        "{uri:?} is {state} alias of {:?}; a retired resource URI is never reused",
        alias.resource_uri
    ))
}

/// What [`rename`] did.
#[derive(Debug, Clone)]
pub struct ResourceRename {
    /// The canonical URI it had.
    pub previous_uri: String,
    /// The resource server as it is now, under its new canonical URI.
    pub resource: ResourceServer,
    /// The alias the previous URI now is.
    pub alias: ResourceAlias,
    /// Whether this swapped the URI back from a live alias (the rollback).
    pub swapped: bool,
    pub rewritten: UriRewrites,
}

/// Rows [`rename`] moved from the previous URI to the new one, by table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UriRewrites {
    pub access_tokens: u64,
    pub refresh_tokens: u64,
    pub authorization_codes: u64,
    /// Usage dedupe ledger entries (`usage_event_ids`).
    pub usage_event_ids: u64,
}

/// Move a resource server from its canonical URI `old_uri` to `new_uri`, and
/// keep `old_uri` as an alias of it until `alias_until`, in one transaction:
///
/// - the canonical URI changes, and everything keyed by it follows (webhook
///   deliveries and older aliases, by cascading foreign keys);
/// - `old_uri` becomes an alias, live until `alias_until`;
/// - `resource` on access tokens, refresh tokens and authorization codes is
///   rewritten to `new_uri`, so issued tokens stay valid past the sunset;
/// - the usage dedupe ledger is rewritten, so an event shipped before the
///   rename is still a duplicate after it;
/// - with `name`, the name shown on the consent screen changes too.
///
/// `new_uri` must not be in use: not a canonical URI, and not an alias in any
/// state, so a retired URI is never given out again. The one exception is the
/// rollback: when `new_uri` is a **live** alias of this same server, the two
/// URIs swap. `old_uri` becomes the alias, keeping the sunset the alias had
/// unless `alias_until` gives a new one. Otherwise `alias_until` is required
/// and must be in the future.
///
/// Concurrency (see the module's lock order). The rename rewrites the
/// server's tokens before it touches the server's row, the order the user
/// paths (org deletion, member removal) take them in. It then takes the
/// usage-ledger lock of every URI of the server exclusively
/// ([`USAGE_LEDGER_LOCK_NAMESPACE`]). Every usage claim holds the lock of the
/// URI it names, shared, until its transaction ends (`claim_usage_event`,
/// 0026), so the rename waits for the server's claims in flight and its
/// ledger rewrite sees them, and claims arriving later wait for the rename and
/// then resolve the old URI to the new one. Only this server's ingest waits;
/// every other server's carries on. It gives up after a 5 s lock wait, a
/// statement that runs past 30 seconds, or a deadlock, with nothing changed
/// and a message to run it again. Run it when the server's traffic is low:
/// that only makes a busy refusal less likely, nothing is lost either way.
pub async fn rename(
    db: &Db,
    old_uri: &str,
    new_uri: &str,
    alias_until: Option<DateTime<Utc>>,
    name: Option<&str>,
) -> Result<ResourceRename> {
    validate_resource_uri(new_uri)?;
    if old_uri == new_uri {
        return Err(AuthError::InvalidRequest(format!(
            "{old_uri:?} is already the resource's URI"
        )));
    }
    let name = name.map(str::trim);
    if name == Some("") {
        return Err(AuthError::InvalidRequest(
            "a resource server needs a name".into(),
        ));
    }
    if let Some(until) = alias_until {
        if until <= Utc::now() {
            return Err(AuthError::InvalidRequest(format!(
                "the alias sunset {} is not in the future",
                until.to_rfc3339()
            )));
        }
    }

    // Unpinned: none of these tables is row-level secured, and the ledger is
    // reachable only outside the tenant role.
    let mut tx = db.begin_unpinned().await?;
    let renamed = rename_in(tx.conn(), old_uri, new_uri, alias_until, name)
        .await
        .map_err(busy_error)?;
    tx.commit().await?;
    Ok(renamed)
}

/// A rename that lost a lock wait or a deadlock changed nothing, and running
/// it again is the remedy.
fn busy_error(e: AuthError) -> AuthError {
    match &e {
        AuthError::Db(d) if otto_tenant::is_retryable_lock_failure(d) => AuthError::InvalidRequest(
            "the resource server's rows were busy (usage ingest, token traffic or another \
                 rename) and the rename gave up waiting; nothing changed, run it again (when \
                 the server's traffic is lower, if it keeps happening)"
                .into(),
        ),
        _ => e,
    }
}

async fn rename_in(
    conn: &mut sqlx::PgConnection,
    old_uri: &str,
    new_uri: &str,
    alias_until: Option<DateTime<Utc>>,
    name: Option<&str>,
) -> Result<ResourceRename> {
    // Waiting long on a busy row would queue the server's claims and sign-ins
    // behind this; better to give up and be run again. The statement timeout
    // bounds the rewrites too: each holds the server's claims (through the
    // ledger locks) for as long as it runs.
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *conn)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(&mut *conn)
        .await?;
    lock_uri_namespace(&mut *conn).await?;

    // Checked without locking the server's row: only a rename changes a
    // canonical URI, and it holds the namespace lock, which this one now does.
    let found: Option<(String,)> =
        sqlx::query_as("SELECT resource_uri FROM resource_servers WHERE resource_uri = $1")
            .bind(old_uri)
            .fetch_optional(&mut *conn)
            .await?;
    if found.is_none() {
        return Err(match alias_row(&mut *conn, old_uri).await? {
            Some(a) => AuthError::InvalidRequest(format!(
                "{old_uri:?} is an alias of {:?}; rename the resource by its canonical URI",
                a.resource_uri
            )),
            None => AuthError::InvalidTarget(format!("{old_uri:?} is not a registered resource")),
        });
    }
    let taken: Option<(String,)> =
        sqlx::query_as("SELECT resource_uri FROM resource_servers WHERE resource_uri = $1")
            .bind(new_uri)
            .fetch_optional(&mut *conn)
            .await?;
    if taken.is_some() {
        return Err(AuthError::InvalidRequest(format!(
            "{new_uri:?} is another resource server's URI"
        )));
    }

    // Live by the database's clock, the one every reader of aliases uses.
    let existing = alias_row(&mut *conn, new_uri).await?;
    let swap = match &existing {
        None => None,
        Some(a) if a.live && a.resource_uri == old_uri => Some(a.sunset_at),
        Some(a) => return Err(alias_taken(new_uri, a)),
    };
    let sunset_at = match (alias_until, swap) {
        (Some(until), _) => until,
        (None, Some(kept)) => kept,
        (None, None) => {
            return Err(AuthError::InvalidRequest(
                "--alias-until is required: when the old URI stops working".into(),
            ))
        }
    };

    // Tokens before the server's row: an org deletion holds the org's token
    // rows and then takes the row `FOR KEY SHARE` (its lifecycle event), so
    // holding the row while waiting for tokens would deadlock with it. No
    // foreign key ties a token to the row.
    //
    // Only rows that can still be used: rewriting (and so locking) every
    // historical token would stall introspection and sign-in for longer. A
    // row left under the old URI still matches the server's audience
    // ([`audience_matches_sql`]).
    let mut rewritten = UriRewrites::default();
    for (table, usable, count) in [
        (
            "access_tokens",
            "revoked_at IS NULL AND expires_at > now()",
            &mut rewritten.access_tokens,
        ),
        (
            "refresh_tokens",
            "revoked_at IS NULL AND consumed_at IS NULL AND expires_at > now()",
            &mut rewritten.refresh_tokens,
        ),
        (
            "authorization_codes",
            "consumed_at IS NULL AND expires_at > now()",
            &mut rewritten.authorization_codes,
        ),
    ] {
        *count = sqlx::query(&format!(
            "UPDATE {table} SET resource = $2 WHERE resource = $1 AND {usable}"
        ))
        .bind(old_uri)
        .bind(new_uri)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    }

    // Every URI a claim for this server can name: the canonical one, the new
    // one (in the swap, a live alias now), and every older alias. The set
    // cannot grow while the namespace lock is held.
    let mut uris: Vec<String> =
        sqlx::query_scalar("SELECT alias_uri FROM resource_server_aliases WHERE resource_uri = $1")
            .bind(old_uri)
            .fetch_all(&mut *conn)
            .await?;
    uris.extend([old_uri.to_owned(), new_uri.to_owned()]);
    lock_usage_ledgers(&mut *conn, &uris).await?;

    // The canonical key: its cascade carries every alias of the server,
    // including the one being swapped back, to `new_uri`.
    sqlx::query(
        "UPDATE resource_servers SET resource_uri = $2, name = COALESCE($3, name), \
                updated_at = now() \
         WHERE resource_uri = $1",
    )
    .bind(old_uri)
    .bind(new_uri)
    .bind(name)
    .execute(&mut *conn)
    .await?;
    let alias: ResourceAlias = if swap.is_some() {
        // The alias row of `new_uri` becomes the alias row of `old_uri`, as
        // of now: `created_at` is when this URI became an alias.
        sqlx::query_as(&format!(
            "UPDATE resource_server_aliases a SET alias_uri = $2, sunset_at = $3, \
                    created_at = now() \
             WHERE a.alias_uri = $1 RETURNING {}",
            *ALIAS_COLS
        ))
        .bind(new_uri)
        .bind(old_uri)
        .bind(sunset_at)
        .fetch_one(&mut *conn)
        .await?
    } else {
        sqlx::query_as(&format!(
            "INSERT INTO resource_server_aliases AS a (alias_uri, resource_uri, sunset_at) \
             VALUES ($1, $2, $3) RETURNING {}",
            *ALIAS_COLS
        ))
        .bind(old_uri)
        .bind(new_uri)
        .bind(sunset_at)
        .fetch_one(&mut *conn)
        .await?
    };

    // Claims in flight have committed by now (see the function's docs), and
    // later ones file under `new_uri`, so every entry under `old_uri` moves.
    // `new_uri` has none of its own: it was never canonical, or (the swap) its
    // entries were moved off it when it last stopped being. The guard only
    // keeps a stray duplicate from failing the whole rename on the primary
    // key; the entry under `new_uri` is the one claims read.
    rewritten.usage_event_ids = sqlx::query(
        "UPDATE usage_event_ids u SET resource_uri = $2 \
         WHERE u.resource_uri = $1 \
           AND NOT EXISTS (SELECT 1 FROM usage_event_ids n \
                            WHERE n.resource_uri = $2 AND n.event_id = u.event_id)",
    )
    .bind(old_uri)
    .bind(new_uri)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    let resource = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE resource_uri = $1"
    ))
    .bind(new_uri)
    .fetch_one(&mut *conn)
    .await?;
    Ok(ResourceRename {
        previous_uri: old_uri.to_owned(),
        resource,
        alias,
        swapped: swap.is_some(),
        rewritten,
    })
}

/// What [`drop_alias`] did.
#[derive(Debug, Clone)]
pub struct DroppedAlias {
    /// The alias as it is now: dropped.
    pub alias: ResourceAlias,
    /// Grants still bound to the alias that the drop revoked.
    pub revoked: GrantRevocations,
}

/// Grants [`drop_alias`] revoked, by table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GrantRevocations {
    pub access_tokens: u64,
    pub refresh_tokens: u64,
    pub authorization_codes: u64,
}

/// End an alias before its sunset. From then on a client or resource server
/// naming it is refused like an unknown URI, and the row stays, so the URI is
/// never reused.
///
/// In the same transaction it revokes every access token and refresh token,
/// and consumes every authorization code, still bound to the alias string:
/// grants minted under the old URI by a request that raced the rename (the
/// rename rewrote every other usable one to the canonical URI). Such a grant
/// otherwise stays good for its server ([`audience_matches_sql`]), so without
/// this a dropped alias would still have live credentials. Grants bound to
/// the canonical URI are untouched.
///
/// Dropping one already dropped keeps its `dropped_at` and revokes anything
/// still bound to it, so running it again is safe.
pub async fn drop_alias(db: &Db, alias_uri: &str) -> Result<DroppedAlias> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(tx.conn())
        .await?;
    let dropped = drop_alias_in(tx.conn(), alias_uri)
        .await
        .map_err(|e| match &e {
            AuthError::Db(d) if otto_tenant::is_retryable_lock_failure(d) => {
                AuthError::InvalidRequest(format!(
                    "the grants bound to {alias_uri:?} were busy and drop-alias gave up \
                     waiting; nothing changed, run it again"
                ))
            }
            _ => e,
        })?;
    tx.commit().await?;
    Ok(dropped)
}

async fn drop_alias_in(conn: &mut sqlx::PgConnection, alias_uri: &str) -> Result<DroppedAlias> {
    lock_uri_namespace(&mut *conn).await?;
    let alias: Option<ResourceAlias> = sqlx::query_as(&format!(
        "UPDATE resource_server_aliases a SET dropped_at = COALESCE(a.dropped_at, now()) \
         WHERE a.alias_uri = $1 RETURNING {}",
        *ALIAS_COLS
    ))
    .bind(alias_uri)
    .fetch_optional(&mut *conn)
    .await?;
    let alias = alias.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{alias_uri:?} is not a resource server alias"))
    })?;

    // Wait for a refresh or code redemption of an alias-bound grant in
    // flight, so its grant is revoked or consumed consistently. (Its
    // successor is bound to the canonical URI and stays, exactly as if the
    // refresh had finished before the drop.)
    for sql in [
        "SELECT 1 FROM refresh_tokens WHERE resource = $1 AND revoked_at IS NULL \
         AND consumed_at IS NULL FOR UPDATE",
        "SELECT 1 FROM authorization_codes WHERE resource = $1 AND consumed_at IS NULL \
         FOR UPDATE",
    ] {
        sqlx::query(sql).bind(alias_uri).execute(&mut *conn).await?;
    }

    let mut revoked = GrantRevocations::default();
    for (sql, count) in [
        (
            "UPDATE access_tokens SET revoked_at = now() \
             WHERE resource = $1 AND revoked_at IS NULL AND expires_at > now()",
            &mut revoked.access_tokens,
        ),
        (
            "UPDATE refresh_tokens SET revoked_at = now() \
             WHERE resource = $1 AND revoked_at IS NULL AND consumed_at IS NULL \
               AND expires_at > now()",
            &mut revoked.refresh_tokens,
        ),
        (
            "UPDATE authorization_codes SET consumed_at = now() \
             WHERE resource = $1 AND consumed_at IS NULL AND expires_at > now()",
            &mut revoked.authorization_codes,
        ),
    ] {
        *count = sqlx::query(sql)
            .bind(alias_uri)
            .execute(&mut *conn)
            .await?
            .rows_affected();
    }
    Ok(DroppedAlias { alias, revoked })
}

/// Look up a resource server that may currently be issued tokens, by a URI
/// a client named: its canonical URI or a live alias ([`resolve`]). The
/// canonical row is returned, so everything the caller stores or compares
/// uses the canonical URI. For an exact canonical match only, see [`get`].
///
/// An unknown resource and a disabled one are both
/// [`AuthError::InvalidTarget`] (RFC 8707 §2), and say which, because the
/// resource indicator is public and a client integrating against the AS needs
/// to know which mistake it made. An expired or dropped alias is refused
/// exactly like an unknown URI.
pub async fn resolve_active(db: &Db, resource_uri: &str) -> Result<ResourceServer> {
    let rs = resolve(db, resource_uri)
        .await?
        .ok_or_else(|| not_registered(resource_uri))?
        .server;
    active(rs, resource_uri)
}

/// What [`resolve_active_grant`] found.
#[derive(Debug, Clone)]
pub enum GrantResource {
    /// The active server the grant is bound to (the canonical row), which
    /// the requested resource, if any, also names.
    Bound(ResourceServer),
    /// The requested resource names a different server than the grant's:
    /// the caller refuses with `invalid_grant`.
    OtherServer,
}

/// Look up the resource server a stored grant (an authorization code or a
/// refresh token) is bound to, when it may currently be issued tokens, and
/// check the `resource` the client repeated in the token request against it
/// (RFC 8707 §2.2), in one statement, so a rename committing alongside cannot
/// fall between the two lookups.
///
/// `stored` is the grant's `resource`. It is normally canonical, since the
/// rename rewrites usable grants, but one minted under the old URI by a
/// transaction that raced the rename is bound to an alias. Such a grant still
/// belongs to its server whatever state the alias is in, by the same rule as
/// [`audience_matches_sql`]: alias rows are tombstones that only ever name
/// their own server.
///
/// `requested` is client-named, so it resolves like [`resolve_active`]: the
/// canonical URI or a live alias of the grant's server is that server, and
/// the comparison is canonical to canonical. Refusals:
///
/// - the grant's server is gone or disabled: [`AuthError::InvalidTarget`];
/// - `requested` names no server (unknown, or an expired or dropped alias):
///   [`AuthError::InvalidTarget`];
/// - `requested` names another server: [`GrantResource::OtherServer`].
///
/// It runs on `conn`, the redemption's own transaction connection: a
/// redemption holds its grant's row lock while it calls this, and taking a
/// second pool connection under that lock lets concurrent redemptions of one
/// grant exhaust the pool.
pub async fn resolve_active_grant(
    conn: &mut sqlx::PgConnection,
    stored: &str,
    requested: Option<&str>,
) -> Result<GrantResource> {
    #[derive(sqlx::FromRow)]
    struct Row {
        #[sqlx(flatten)]
        server: ResourceServer,
        /// `same`, `other` or `none`: what `requested` names.
        requested: String,
    }
    let rs_cols = &*RS_COLS;
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {rs_cols}, \
                CASE WHEN $2::text IS NULL OR $2::text = rs.resource_uri \
                       OR EXISTS (SELECT 1 FROM resource_server_aliases a \
                                   WHERE a.alias_uri = $2::text \
                                     AND a.resource_uri = rs.resource_uri AND {LIVE_ALIAS}) \
                     THEN 'same' \
                     WHEN EXISTS (SELECT 1 FROM resource_servers o \
                                   WHERE o.resource_uri = $2::text) \
                       OR EXISTS (SELECT 1 FROM resource_server_aliases a \
                                   WHERE a.alias_uri = $2::text AND {LIVE_ALIAS}) \
                     THEN 'other' \
                     ELSE 'none' END AS requested \
           FROM resource_servers rs WHERE {}",
        audience_matches_sql("$1", "rs.resource_uri")
    ))
    .bind(stored)
    .bind(requested)
    .fetch_optional(conn)
    .await?;
    let row = row.ok_or_else(|| not_registered(stored))?;
    let server = active(row.server, stored)?;
    match (row.requested.as_str(), requested) {
        ("same", _) => Ok(GrantResource::Bound(server)),
        ("other", _) => Ok(GrantResource::OtherServer),
        // `none`: only ever with a requested URI, since an absent one is `same`.
        (_, named) => Err(not_registered(named.unwrap_or(stored))),
    }
}

fn not_registered(uri: &str) -> AuthError {
    AuthError::InvalidTarget(format!("{uri:?} is not a registered resource"))
}

fn active(rs: ResourceServer, named: &str) -> Result<ResourceServer> {
    if rs.disabled {
        return Err(AuthError::InvalidTarget(format!("{named:?} is disabled")));
    }
    Ok(rs)
}

/// Look up a resource server, enabled or not, by exact canonical match: an
/// alias finds nothing. Client-named URIs go through [`resolve_active`].
pub async fn get(db: &Db, resource_uri: &str) -> Result<Option<ResourceServer>> {
    let row = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE resource_uri = $1"
    ))
    .bind(resource_uri)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// Every registered resource server, enabled or not, by URI.
pub async fn list(db: &Db) -> Result<Vec<ResourceServer>> {
    let rows = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers ORDER BY resource_uri"
    ))
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Enable or disable a resource server. Disabling stops new authorization
/// codes, token redemptions, refreshes, and PATs for it; tokens already
/// issued run to their expiry.
pub async fn set_disabled(db: &Db, resource_uri: &str, disabled: bool) -> Result<ResourceServer> {
    let row = sqlx::query_as(&format!(
        "UPDATE resource_servers SET disabled = $2, updated_at = now() \
         WHERE resource_uri = $1 RETURNING {COLS}"
    ))
    .bind(resource_uri)
    .bind(disabled)
    .fetch_optional(db.pool())
    .await?;
    row.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })
}

/// Issue a new introspection credential for a resource server, replacing any
/// previous one. The plaintext is returned once and only its hash is stored.
pub async fn rotate_introspection_secret(db: &Db, resource_uri: &str) -> Result<String> {
    let secret = crypto::generate(INTROSPECTION_SECRET_PREFIX);
    let updated = sqlx::query(
        "UPDATE resource_servers SET introspection_secret_hash = $2, updated_at = now() \
         WHERE resource_uri = $1",
    )
    .bind(resource_uri)
    .bind(&secret.hash)
    .execute(db.pool())
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AuthError::InvalidTarget(format!(
            "{resource_uri:?} is not a registered resource"
        )));
    }
    Ok(secret.into_plaintext())
}

/// Authenticate a resource server calling the introspection endpoint as
/// `resource_uri`: its canonical URI or a live alias of it ([`resolve`]).
///
/// The result keeps the canonical row and, apart from it, the URI the caller
/// authenticated as, which is the `aud` introspection answers with. So a
/// server still configured with its old URI keeps working through the alias
/// until the sunset, and is told about tokens in the terms it expects.
///
/// Every failure, whether an unknown resource, an expired or dropped alias, no
/// credential issued, a wrong credential, or a disabled server, is the same
/// [`AuthError::InvalidClient`], so the endpoint cannot be used to probe which
/// resources exist or hold a credential.
pub async fn authenticate_introspection(
    db: &Db,
    resource_uri: &str,
    presented: &str,
) -> Result<ResolvedResource> {
    let refused = || AuthError::InvalidClient("resource server authentication failed".into());

    let presented_hash = crypto::hash(presented.trim());
    // The row and its credential in one read, so a rename committing in
    // between cannot turn a good credential into a spurious refusal.
    let (resolved, stored) = resolve_row(db, resource_uri).await?.ok_or_else(refused)?;
    let Some(stored) = stored else {
        return Err(refused());
    };
    if !crypto::verify(&stored, &presented_hash) {
        return Err(refused());
    }
    if resolved.server.disabled {
        return Err(refused());
    }
    Ok(resolved)
}

/// Authenticate a resource server by its credential alone, for callers that
/// present `Authorization: Bearer <secret>` and so do not say who they are.
///
/// The credential is a 256-bit random value with a unique index on its hash
/// (migration 0007), so the secret identifies the server. The same single
/// refusal as [`authenticate_introspection`] covers every failure.
pub async fn authenticate_secret(db: &Db, presented: &str) -> Result<ResourceServer> {
    let hash = crypto::hash(presented.trim());
    let row: Option<ResourceServer> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE introspection_secret_hash = $1 AND NOT disabled"
    ))
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;
    row.ok_or_else(|| AuthError::InvalidClient("resource server authentication failed".into()))
}

/// Configure (or, with `url: None`, clear) the lifecycle webhook of a resource
/// server. Setting one always issues a fresh signing secret, returned once as
/// plaintext; only its sealed form is stored. Re-running with the same URL is
/// how the secret is rotated.
///
/// The URL is admin-provisioned, so unlike the IdP URLs in [`crate::oidc`] it
/// is not run through the SSRF guard in [`crate::ssrf`], which would refuse
/// the private and loopback addresses resource servers legitimately sit on
/// (a Fly private network, a local test). It still has to be `https`, or
/// `http` on loopback, with no credentials or fragment, so a typo cannot send
/// signed event bodies over plaintext.
pub async fn set_webhook(
    db: &Db,
    cipher: &Cipher,
    resource_uri: &str,
    url: Option<&str>,
) -> Result<Option<String>> {
    let (url, secret) = match url {
        Some(u) => {
            validate_webhook_url(u)?;
            (Some(u), Some(crypto::generate(WEBHOOK_SECRET_PREFIX)))
        }
        None => (None, None),
    };
    let sealed = secret
        .as_ref()
        .map(|s| cipher.seal(s.expose().as_bytes()))
        .transpose()?;

    let updated = sqlx::query(
        "UPDATE resource_servers SET webhook_url = $2, webhook_secret_ciphertext = $3, \
                webhook_secret_nonce = $4, updated_at = now() \
         WHERE resource_uri = $1",
    )
    .bind(resource_uri)
    .bind(url)
    .bind(sealed.as_ref().map(|s| s.ciphertext.as_slice()))
    .bind(sealed.as_ref().map(|s| s.nonce.as_slice()))
    .execute(db.pool())
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AuthError::InvalidTarget(format!(
            "{resource_uri:?} is not a registered resource"
        )));
    }
    Ok(secret.map(Secret::into_plaintext))
}

fn validate_webhook_url(url: &str) -> Result<()> {
    let bad = |why: &str| AuthError::InvalidRequest(format!("webhook url {url:?} {why}"));
    let parsed = url::Url::parse(url).map_err(|_| bad("is not an absolute URL"))?;
    if parsed.fragment().is_some() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad("must not contain a fragment or credentials"));
    }
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    );
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(bad("must be https (http is allowed only on loopback)")),
    }
}

/// Every scope any enabled resource server defines, sorted and deduplicated,
/// for the AS metadata's `scopes_supported`.
pub fn all_scopes(servers: &[ResourceServer]) -> Vec<String> {
    let mut scopes: Vec<String> = servers
        .iter()
        .filter(|rs| !rs.disabled)
        .flat_map(|rs| rs.scopes.iter().cloned())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Whether `scope` only reads.
///
/// A naming convention, not a registry flag: a scope is read-only exactly when
/// it ends in `:read`. Every other scope counts as non-read: `*:write`,
/// `*:admin`, `org:admin`, and names that follow neither pattern, such as
/// otto-factory's `messages` and `trackers`. The consent screen's "Read only"
/// button unchecks everything this returns `false` for, so a scope that breaks
/// the convention errs toward *not* being granted, and the person can still
/// check it again by hand.
pub fn is_read_scope(scope: &str) -> bool {
    scope.ends_with(":read")
}

/// A resource indicator must be an absolute URI without a fragment
/// (RFC 8707 §2). It must also be `https`, except on loopback for local
/// development, because it is the audience every token for it carries.
fn validate_resource_uri(uri: &str) -> Result<()> {
    let bad = |why: &str| AuthError::InvalidRequest(format!("resource_uri {uri:?} {why}"));
    let parsed = url::Url::parse(uri).map_err(|_| bad("is not an absolute URI"))?;
    if parsed.fragment().is_some() {
        return Err(bad("must not contain a fragment"));
    }
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    );
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("must be https (http is allowed only on loopback)")),
    }
    // Exact-match comparison is the whole audience check, so refuse a value
    // that would not round-trip: what a client sends must be what we stored.
    if parsed.as_str() != uri && parsed.as_str() != format!("{uri}/") {
        return Err(bad("is not in canonical form"));
    }
    Ok(())
}

fn validate_scope_descriptions(
    scopes: &[String],
    descriptions: &[(&str, &str)],
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (scope, text) in descriptions {
        if !scopes.iter().any(|s| s == scope) {
            return Err(AuthError::InvalidRequest(format!(
                "cannot describe {scope:?}: not one of the resource server's scopes ({})",
                scopes.join(" ")
            )));
        }
        let text = text.trim();
        if text.is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} is empty"
            )));
        }
        if text.chars().count() > MAX_SCOPE_DESCRIPTION_CHARS {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} is longer than {MAX_SCOPE_DESCRIPTION_CHARS} characters"
            )));
        }
        if text.chars().any(char::is_control) {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} contains control characters"
            )));
        }
        if out.insert((*scope).to_owned(), text.to_owned()).is_some() {
            return Err(AuthError::InvalidRequest(format!(
                "{scope:?} is described twice"
            )));
        }
    }
    Ok(out)
}

/// RFC 6749 §3.3 scope-token: one or more of %x21 / %x23-5B / %x5D-7E, so no
/// spaces, quotes, or backslashes. Duplicates are dropped, order kept.
fn validate_scope_list(field: &str, scopes: &[&str]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(scopes.len());
    for s in scopes {
        let ok = !s.is_empty()
            && s.bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b));
        if !ok {
            return Err(AuthError::InvalidRequest(format!(
                "{field} contains an invalid scope token {s:?}"
            )));
        }
        if !out.iter().any(|o| o == s) {
            out.push((*s).to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `busy_error` maps `query_canceled` (what a statement timeout raises)
    /// to the busy message with the "run it again" remedy, like a lost lock
    /// wait. It does not drive a rename into its own timeout.
    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn busy_error_maps_query_canceled(pool: sqlx::PgPool) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL statement_timeout = '10ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let err = sqlx::query("SELECT pg_sleep(1)")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        let mapped = busy_error(AuthError::Db(err));
        assert!(
            matches!(&mapped, AuthError::InvalidRequest(m) if m.contains("nothing changed") && m.contains("run it again")),
            "{mapped:?}"
        );
    }

    fn rs(scopes: &[&str], defaults: &[&str]) -> ResourceServer {
        ResourceServer {
            resource_uri: "https://svc.example/mcp".into(),
            name: "svc".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            default_scopes: defaults.iter().map(|s| s.to_string()).collect(),
            scope_descriptions: Default::default(),
            disabled: false,
            webhook_url: None,
            service: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn empty_request_gets_the_defaults() {
        let r = rs(&["read", "write"], &["read"]);
        assert_eq!(r.grant_scopes(&[]).unwrap(), vec!["read"]);
    }

    #[test]
    fn known_scopes_are_granted_once_each() {
        let r = rs(&["read", "write"], &["read"]);
        let granted = r
            .grant_scopes(&["write".into(), "read".into(), "write".into()])
            .unwrap();
        assert_eq!(granted, vec!["write", "read"]);
    }

    #[test]
    fn a_scope_from_another_resource_server_is_refused() {
        let r = rs(&["flags:read"], &["flags:read"]);
        let err = r.grant_scopes(&["jobs:write".into()]).unwrap_err();
        assert!(matches!(err, AuthError::InvalidScope(m) if m.contains("jobs:write")));
    }

    #[test]
    fn resource_uri_rules() {
        assert!(validate_resource_uri("https://otto-factory.savvagent.com/mcp").is_ok());
        assert!(validate_resource_uri("http://127.0.0.1:8080/mcp").is_ok());
        assert!(validate_resource_uri("http://localhost:8080/mcp").is_ok());

        for bad in [
            "otto-factory.savvagent.com/mcp",
            "http://otto-factory.savvagent.com/mcp",
            "https://otto-factory.savvagent.com/mcp#frag",
            "ftp://otto-factory.savvagent.com/mcp",
            "HTTPS://Otto-Factory.savvagent.com/mcp",
        ] {
            assert!(
                validate_resource_uri(bad).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn scope_token_rules() {
        assert_eq!(
            validate_scope_list("scopes", &["jobs:read", "org:admin", "jobs:read"]).unwrap(),
            vec!["jobs:read", "org:admin"]
        );
        for bad in ["", "has space", "quo\"te", "back\\slash"] {
            assert!(validate_scope_list("scopes", &[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn scope_description_rules() {
        let scopes: Vec<String> = vec!["a".into(), "b".into()];
        let ok = validate_scope_descriptions(&scopes, &[("a", "  Read things  ")]).unwrap();
        assert_eq!(ok["a"], "Read things");
        assert!(validate_scope_descriptions(&scopes, &[])
            .unwrap()
            .is_empty());

        let long = "x".repeat(MAX_SCOPE_DESCRIPTION_CHARS + 1);
        let at_cap = "x".repeat(MAX_SCOPE_DESCRIPTION_CHARS);
        assert!(validate_scope_descriptions(&scopes, &[("a", &at_cap)]).is_ok());
        for bad in [
            vec![("zzz", "unknown scope")],
            vec![("a", "   ")],
            vec![("a", long.as_str())],
            vec![("a", "two\nlines")],
            vec![("a", "one"), ("a", "two")],
        ] {
            assert!(
                matches!(
                    validate_scope_descriptions(&scopes, &bad),
                    Err(AuthError::InvalidRequest(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn service_slug_rules() {
        let longest = format!("a{}", "b".repeat(MAX_SERVICE_SLUG_LEN - 1));
        for ok in ["otto-flags", "a", "cxp2", "a-b-c", longest.as_str()] {
            assert!(is_service_slug(ok), "{ok:?} should be accepted");
        }
        let too_long = format!("{longest}c");
        for bad in [
            "",
            "Otto",
            "1otto",
            "-otto",
            "otto_flags",
            "otto/flags",
            "otto flags",
            "ottö",
            too_long.as_str(),
        ] {
            assert!(!is_service_slug(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn all_scopes_skips_disabled_servers() {
        let mut a = rs(&["b", "a"], &[]);
        let mut b = rs(&["c", "a"], &[]);
        assert_eq!(all_scopes(&[a.clone(), b.clone()]), vec!["a", "b", "c"]);
        b.disabled = true;
        a.scopes.push("d".into());
        assert_eq!(all_scopes(&[a, b]), vec!["a", "b", "d"]);
    }

    /// Read-only exactly when the name ends in `:read`. Everything else,
    /// including names that follow neither pattern, is non-read, so "Read
    /// only" errs toward not granting it.
    #[test]
    fn is_read_scope_only_for_colon_read() {
        for read in ["cxp:read", "jobs:read", "flags:read", "things:read"] {
            assert!(is_read_scope(read), "{read} should be read-only");
        }
        for not_read in [
            "cxp:write",
            "apps:admin",
            "org:admin",
            "messages",
            "trackers",
            "read",
            "cxp:reader",
            "",
        ] {
            assert!(
                !is_read_scope(not_read),
                "{not_read:?} must not count as read-only"
            );
        }
    }
}
