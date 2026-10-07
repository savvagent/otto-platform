//! The connection pool and the tenant-pinned transaction.
//!
//! [`Tx`] is the only way to reach tenant data, and it cannot be constructed
//! without an [`OrgId`]. That is the crate's central invariant: "which tenant?"
//! is answered once, at transaction open, instead of being re-answered (and
//! occasionally forgotten) in every individual query. [`Unpinned`] mirrors
//! that discipline for the opposite case — a transaction that must carry no
//! org at all — so [`Db::audit_global_on`] can require one specifically
//! rather than accepting anything that can run a query.

use crate::error::{Error, Result};
use crate::ids::OrgId;
use crate::isolation::IsolationReport;
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::{PgPool, Transaction};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// The tenant migrations, exposed so a consumer's tests can hand them to
/// `#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The application role that tenant transactions run as. Must match migration
/// `0004_rls.sql`.
const TENANT_ROLE: &str = "otto_app";

#[derive(Clone, Debug)]
pub struct Db {
    pool: PgPool,
    /// Whether this connection can `SET LOCAL ROLE otto_app`, resolved once and
    /// shared by every clone.
    ///
    /// Resolved lazily rather than in `connect`, because `from_pool` is sync and
    /// is what `#[sqlx::test]` uses — making the probe eager would mean either an
    /// async `from_pool` (rippling through every test) or two constructors that
    /// disagree about a security-relevant fact. `verify_tenant_isolation` forces
    /// it at startup, so a server never reaches its first tenant query without
    /// having answered this.
    tenant_role_assumable: Arc<OnceCell<bool>>,
}

impl Db {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            tenant_role_assumable: Arc::new(OnceCell::new()),
        }
    }

    /// Whether `SET LOCAL ROLE otto_app` will succeed on this connection.
    ///
    /// Two conditions, and asking the catalog is the only honest way to know
    /// both: the role has to exist, and the connecting role has to be a member of
    /// it. `pg_has_role(…, 'USAGE')` answers exactly the question `SET ROLE`
    /// asks, including membership held indirectly.
    ///
    /// A `false` here is not a failure. On managed Postgres `CREATE ROLE` needs a
    /// cluster-level privilege the application role does not have, and isolation
    /// rests on `FORCE ROW LEVEL SECURITY` instead — which is a real guarantee,
    /// but only for a connecting role that is neither a superuser nor BYPASSRLS.
    /// Nothing here assumes that; [`Self::verify_tenant_isolation`] checks it.
    async fn tenant_role_assumable(&self) -> Result<bool> {
        self.tenant_role_assumable
            .get_or_try_init(|| async {
                let assumable: bool = sqlx::query_scalar(
                    "SELECT EXISTS ( \
                       SELECT 1 FROM pg_catalog.pg_roles r \
                       WHERE r.rolname = $1 \
                         AND pg_catalog.pg_has_role(current_user, r.oid, 'USAGE') \
                     )",
                )
                .bind(TENANT_ROLE)
                .fetch_one(&self.pool)
                .await?;
                Ok(assumable)
            })
            .await
            .copied()
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply all migrations. Safe to run from several replicas at once: sqlx
    /// takes a Postgres advisory lock for the duration, so the losers wait
    /// rather than racing each other through the same DDL.
    pub async fn migrate(&self) -> Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
        Ok(())
    }

    /// Open a transaction pinned to `org`.
    ///
    /// Two statements run before the caller gets control, and both are load-bearing:
    ///
    /// - `SET LOCAL ROLE otto_app` drops out of any superuser/owner identity for
    ///   the rest of the transaction. **Where the connecting role is exempt, RLS
    ///   does nothing without this** — Postgres exempts superusers and table
    ///   owners from their own policies, and the connecting user is frequently
    ///   one or both. This was verified empirically against a live database, not
    ///   assumed.
    ///
    ///   Issued only when the role can actually be assumed. A managed Postgres
    ///   deployment is routinely handed a database-scoped role with no
    ///   CREATEROLE, so `otto_app` never gets created and this statement would
    ///   abort every tenant transaction; there, `FORCE ROW LEVEL SECURITY`
    ///   carries the guarantee instead. Skipping it is safe *only* under
    ///   conditions this function cannot check per-transaction without paying
    ///   for it on every call, so [`Self::verify_tenant_isolation`] checks them
    ///   once at startup and refuses to serve when they do not hold. Calling
    ///   `begin` without ever calling that is how a deployment ends up with one
    ///   guard while believing it has two.
    /// - `set_config('app.org_id', …, true)` supplies the value every policy
    ///   compares against. `set_config` rather than `SET LOCAL` because `SET`
    ///   takes no bind parameters, and interpolating a tenant id into DDL-ish
    ///   SQL is not a thing worth doing carefully when a parameterized
    ///   equivalent exists.
    ///
    /// Both are transaction-local, so returning the connection to the pool
    /// cannot carry one tenant's identity into the next request.
    pub async fn begin(&self, org: OrgId) -> Result<Tx<'static>> {
        let mut tx = self.pool.begin().await?;

        if self.tenant_role_assumable().await? {
            sqlx::query(&format!("SET LOCAL ROLE {TENANT_ROLE}"))
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("SELECT set_config('app.org_id', $1, true)")
            .bind(org.to_string())
            .execute(&mut *tx)
            .await?;

        Ok(Tx { tx, org })
    }

    /// Read back, from the catalog, whether tenant isolation is actually in
    /// force — as the role a tenant transaction actually runs as, in a
    /// transaction shaped exactly like [`Self::begin`].
    ///
    /// Call this once at startup, before serving. It exists because guard 2 is
    /// the one guard the environment can switch off: the same migrations isolate
    /// perfectly under one database role and not at all under another, and
    /// nothing in this repository can tell which one a deployment connects as.
    /// See [`crate::isolation`] for the shapes that pass and the one that does not.
    ///
    /// The transaction is rolled back — this only reads catalogs.
    pub async fn verify_tenant_isolation(&self) -> Result<IsolationReport> {
        let assumed = self.tenant_role_assumable().await?;
        let mut tx = self.pool.begin().await?;
        if assumed {
            sqlx::query(&format!("SET LOCAL ROLE {TENANT_ROLE}"))
                .execute(&mut *tx)
                .await?;
        }
        let report = crate::isolation::gather(&mut tx, assumed).await?;
        tx.rollback().await?;

        let problems = report.problems();
        if !problems.is_empty() {
            return Err(Error::IsolationNotEnforced {
                problems: problems.join("; "),
            });
        }
        Ok(report)
    }

    /// Open an **unpinned** transaction for the control plane — authentication,
    /// signup, org lookup — where the org is not yet known and RLS-protected
    /// tables are not touched.
    ///
    /// Named to be conspicuous at call sites. Anything reaching for this to get
    /// at tenant data is a bug, and what it actually returns depends on which
    /// deployment shape it runs against. Where the connecting role is neither a
    /// superuser nor BYPASSRLS, `FORCE ROW LEVEL SECURITY` applies with no
    /// `app.org_id` set, so `org_id = current_org()` is never true and tenant
    /// tables return zero rows. Where the connecting role *is* a superuser or
    /// BYPASSRLS, RLS does not apply at all, `FORCE` included, so an unscoped
    /// read or write against a tenant table returns or affects everything, not
    /// nothing.
    pub async fn begin_unpinned(&self) -> Result<Unpinned> {
        Ok(Unpinned {
            tx: self.pool.begin().await?,
        })
    }
}

/// A transaction opened via [`Db::begin_unpinned`] — no [`OrgId`] is attached
/// and `begin_unpinned` never sets `app.org_id` on it. Exists so
/// [`Db::audit_global_on`] can require one specifically, the same way [`Tx`]
/// cannot be constructed without an `OrgId` in the first place: [`Tx::conn`]
/// hands out a bare `&mut PgConnection`, never an `Unpinned`, and this type's
/// own field is private, so nothing outside this module can wrap one around a
/// pinned connection either.
///
/// What this type proves is provenance, not current session state: `conn()`
/// hands out the same bare `&mut PgConnection` a pinned transaction's `conn()`
/// would, so a caller who runs `set_config('app.org_id', …)` through it by
/// hand is holding a value that is still an `Unpinned` but is no longer
/// actually unpinned. That residual gap is why `audit_global_on` itself
/// re-checks `app.org_id` at call time rather than trusting the type alone —
/// see its doc comment. Neither this type nor `Tx` implements `Deref` to
/// `PgConnection` — collapsing either back down to "anything that can run a
/// query" is exactly what this type exists to rule out.
pub struct Unpinned {
    tx: Transaction<'static, Postgres>,
}

impl Unpinned {
    /// Borrow the underlying executor for a query. Mirrors [`Tx::conn`]
    /// exactly.
    pub fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await?;
        Ok(())
    }
}

/// A transaction pinned to exactly one org.
///
/// Holds the [`OrgId`] so query methods can bind it explicitly, *in addition to*
/// the RLS policy that would already filter the rows. The redundancy is
/// intentional: the explicit predicate keeps the query plans index-friendly and
/// keeps intent legible, while RLS catches the query where someone forgot.
pub struct Tx<'a> {
    tx: Transaction<'a, Postgres>,
    org: OrgId,
}

impl<'a> Tx<'a> {
    pub fn org(&self) -> OrgId {
        self.org
    }

    /// Borrow the underlying executor for a query.
    pub fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await?;
        Ok(())
    }
}
