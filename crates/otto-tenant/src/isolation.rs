//! Proving, at startup, that tenant isolation is actually in force.
//!
//! Two independent guards protect tenant data: the [`crate::Tx`] API shape,
//! and row-level security. Guard 2 has a property guard 1 does not — it can be
//! **switched off by the environment** rather than by a code change. Postgres
//! exempts three kinds of caller from a table's policies:
//!
//! 1. superusers,
//! 2. roles with `BYPASSRLS`,
//! 3. the table's owner, unless the table is `FORCE ROW LEVEL SECURITY`.
//!
//! Which of those applies is a fact about the deployment's database role, not
//! about this crate, and it is invisible from the code. A test suite running
//! as a superuser and a production database running as a schema owner disagree
//! about whether the same migration isolates anything.
//!
//! [`IsolationReport`] reads those facts back out of the catalog **as the role a
//! tenant transaction actually runs as**, and [`IsolationReport::problems`]
//! judges them. A server should call this after migrating and refuse to bind a
//! port when isolation is not enforced, so the failure is a startup error
//! naming the remediation rather than a cross-tenant leak discovered later.
//!
//! The two shapes that pass, and why both are legitimate:
//!
//! - **`SET LOCAL ROLE otto_app` succeeded.** The effective role is `otto_app`,
//!   which owns nothing and holds no exemption. This is local development and
//!   `#[sqlx::test]`, where the connecting role is the superuser Postgres was
//!   initialised with and dropping out of it is the only thing that makes the
//!   policies bite.
//! - **The role could not be assumed, and the connecting role is neither a
//!   superuser nor `BYPASSRLS`.** Every tenant table is `FORCE ROW LEVEL
//!   SECURITY`, so owning them buys no exemption. This is managed Postgres,
//!   where `CREATE ROLE` needs a cluster-level privilege the application role
//!   does not have.
//!
//! What does **not** pass is the combination those two hide: no `otto_app`, and
//! a connecting role that is exempt anyway. That deployment has one guard, not
//! two, and nothing in the SQL would have told anyone.

use crate::error::Result;

/// One tenant table's row-level-security state, as seen by the effective role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantTable {
    pub name: String,
    /// `ALTER TABLE … ENABLE ROW LEVEL SECURITY` has been issued.
    pub rls_enabled: bool,
    /// `ALTER TABLE … FORCE ROW LEVEL SECURITY` has been issued. This is what
    /// makes the policies apply to the table's owner.
    pub rls_forced: bool,
    /// Whether the effective role owns this table, **including** ownership held
    /// through role membership — which is how Postgres itself decides the
    /// owner exemption, so anything narrower would report a false pass.
    pub owned_by_effective_role: bool,
}

impl TenantTable {
    /// Whether this table's policies actually apply to the effective role.
    ///
    /// Deliberately does not consider superuser/`BYPASSRLS`: those are
    /// properties of the role rather than the table, and folding them in here
    /// would report every table as broken for one role-level reason, burying
    /// the single line that says what to fix.
    fn isolated(&self) -> bool {
        self.rls_enabled && (self.rls_forced || !self.owned_by_effective_role)
    }
}

/// What the database says about isolation, gathered as the role a tenant
/// transaction runs as. Facts only — [`Self::problems`] does the judging, so the
/// judgement is unit-testable without a database in the states that matter
/// (which are the states a healthy test database cannot be put into).
#[derive(Debug, Clone)]
pub struct IsolationReport {
    /// `current_user` inside a transaction shaped exactly like [`crate::Db::begin`].
    pub effective_role: String,
    /// Whether `SET LOCAL ROLE otto_app` was issued. False means the role does
    /// not exist or is not assumable — legitimate on managed Postgres.
    pub tenant_role_assumed: bool,
    /// The effective role is a superuser. Bypasses RLS unconditionally.
    pub role_is_superuser: bool,
    /// The effective role holds `BYPASSRLS`. Bypasses RLS unconditionally.
    pub role_bypasses_rls: bool,
    /// Every table carrying a `<table>_tenant_isolation` policy — that is, every
    /// table migration `0004_rls.sql` declared to be tenant-scoped.
    pub tables: Vec<TenantTable>,
}

impl IsolationReport {
    /// Everything wrong with this deployment's isolation, in the order an
    /// operator should read it. Empty means both guards are real.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        // Ordered before the per-table checks on purpose: a role-level exemption
        // makes every table's state irrelevant, and listing thirteen broken
        // tables would bury the one sentence that explains why.
        if self.role_is_superuser || self.role_bypasses_rls {
            let why = if self.role_is_superuser {
                "is a superuser"
            } else {
                "holds BYPASSRLS"
            };
            problems.push(format!(
                "tenant transactions run as {:?}, which {why}, so row-level security \
                 is bypassed on every table and one org can read another's data. \
                 {}",
                self.effective_role,
                if self.tenant_role_assumed {
                    "SET LOCAL ROLE otto_app succeeded but landed on an exempt role: \
                     revoke SUPERUSER/BYPASSRLS from otto_app."
                } else {
                    "Either grant the application an otto_app role to drop into \
                     (CREATE ROLE otto_app NOLOGIN; GRANT otto_app TO CURRENT_USER), \
                     or connect as a role that is neither."
                }
            ));
        }

        if self.tables.is_empty() {
            problems.push(
                "no table carries a tenant-isolation policy, so migration 0004_rls.sql \
                 either has not run or did not complete. Run migrations against this \
                 database before serving."
                    .to_string(),
            );
        }

        for t in self.tables.iter().filter(|t| !t.isolated()) {
            let why = if !t.rls_enabled {
                "row-level security is not enabled on it"
            } else {
                "it is owned by the effective role and is not FORCE ROW LEVEL SECURITY"
            };
            problems.push(format!(
                "table {:?} has a tenant-isolation policy but {why}, so the policy does \
                 not apply and a query missing its org_id predicate would return every \
                 tenant's rows",
                t.name
            ));
        }

        problems
    }

    /// A one-line summary for the startup log, so a healthy boot still records
    /// *which* of the two legitimate shapes it is running in. An operator who
    /// cannot tell those apart cannot tell when one has silently become the
    /// other.
    pub fn summary(&self) -> String {
        format!(
            "tenant isolation enforced as role {:?} ({}); {} tenant tables, {} forced",
            self.effective_role,
            if self.tenant_role_assumed {
                "assumed via SET LOCAL ROLE"
            } else {
                "connecting role, not exempt from RLS"
            },
            self.tables.len(),
            self.tables.iter().filter(|t| t.rls_forced).count(),
        )
    }
}

/// Reads the isolation facts inside `tx`, which the caller must already have
/// shaped like a tenant transaction (`SET LOCAL ROLE` issued or deliberately
/// not). Kept separate from opening the transaction so the query runs against
/// exactly the session a real tenant query would.
pub(crate) async fn gather(
    tx: &mut sqlx::PgConnection,
    tenant_role_assumed: bool,
) -> Result<IsolationReport> {
    let (effective_role, role_is_superuser, role_bypasses_rls): (String, bool, bool) =
        sqlx::query_as(
            "SELECT current_user::text, \
                    COALESCE(r.rolsuper, false), \
                    COALESCE(r.rolbypassrls, false) \
             FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(&mut *tx)
        .await?;

    // The tenant tables are the ones 0004_rls.sql gave a `<table>_tenant_isolation`
    // policy, read back from the catalog rather than listed again here. A third
    // copy of that list would be a third thing to forget to update, and the copy
    // that matters is the one the database actually holds.
    //
    // `pg_has_role(current_user, relowner, 'USAGE')` rather than a plain
    // `relowner = current_user::regrole`: Postgres grants the owner exemption to
    // members of the owning role too, so testing for identity alone would call a
    // leaking deployment healthy.
    let tables: Vec<TenantTable> = sqlx::query_as(
        "SELECT c.relname::text, \
                c.relrowsecurity, \
                c.relforcerowsecurity, \
                pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE') \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' \
           AND c.relkind = 'r' \
           AND EXISTS ( \
             SELECT 1 FROM pg_catalog.pg_policy p \
             WHERE p.polrelid = c.oid AND p.polname = c.relname || '_tenant_isolation' \
           ) \
         ORDER BY c.relname",
    )
    .fetch_all(&mut *tx)
    .await?;

    Ok(IsolationReport {
        effective_role,
        tenant_role_assumed,
        role_is_superuser,
        role_bypasses_rls,
        tables,
    })
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for TenantTable {
    fn from_row(row: &sqlx::postgres::PgRow) -> std::result::Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            name: row.try_get(0)?,
            rls_enabled: row.try_get(1)?,
            rls_forced: row.try_get(2)?,
            owned_by_effective_role: row.try_get(3)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str, enabled: bool, forced: bool, owned: bool) -> TenantTable {
        TenantTable {
            name: name.to_string(),
            rls_enabled: enabled,
            rls_forced: forced,
            owned_by_effective_role: owned,
        }
    }

    fn report(tables: Vec<TenantTable>) -> IsolationReport {
        IsolationReport {
            effective_role: "otto_app".to_string(),
            tenant_role_assumed: true,
            role_is_superuser: false,
            role_bypasses_rls: false,
            tables,
        }
    }

    /// Local development and `#[sqlx::test]`: the connecting role is the
    /// superuser Postgres was initialised with, and `SET LOCAL ROLE otto_app` is
    /// the whole reason the policies apply.
    #[test]
    fn assuming_otto_app_is_enough() {
        let r = report(vec![table("teams", true, true, false)]);
        assert!(r.problems().is_empty());
    }

    /// Managed Postgres: no CREATEROLE, so no `otto_app`. The connecting role
    /// owns the tables but is neither a superuser nor BYPASSRLS, and FORCE
    /// makes the policies apply to the owner.
    #[test]
    fn forced_rls_is_enough_without_the_role() {
        let r = IsolationReport {
            effective_role: "schema_admin".to_string(),
            tenant_role_assumed: false,
            ..report(vec![table("teams", true, true, true)])
        };
        assert!(r.problems().is_empty(), "{:?}", r.problems());
    }

    /// The combination the two passing shapes hide between them: the role was
    /// not assumed *and* the connecting role is exempt anyway. Nothing in the
    /// migration would have reported this.
    #[test]
    fn superuser_without_the_role_is_refused() {
        let r = IsolationReport {
            effective_role: "postgres".to_string(),
            tenant_role_assumed: false,
            role_is_superuser: true,
            ..report(vec![table("teams", true, true, true)])
        };
        let problems = r.problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("superuser"), "{problems:?}");
        assert!(problems[0].contains("CREATE ROLE otto_app"), "{problems:?}");
    }

    #[test]
    fn bypassrls_is_refused_and_names_itself() {
        let r = IsolationReport {
            effective_role: "replicator".to_string(),
            tenant_role_assumed: false,
            role_bypasses_rls: true,
            ..report(vec![table("teams", true, true, true)])
        };
        let problems = r.problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("BYPASSRLS"), "{problems:?}");
    }

    /// Owning the table without FORCE is the exemption people forget, because
    /// every policy is present and `\d` looks correct.
    #[test]
    fn owner_without_force_is_refused() {
        let r = IsolationReport {
            effective_role: "schema_admin".to_string(),
            tenant_role_assumed: false,
            ..report(vec![table("teams", true, false, true)])
        };
        let problems = r.problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("FORCE ROW LEVEL SECURITY"),
            "{problems:?}"
        );
        assert!(problems[0].contains("teams"), "{problems:?}");
    }

    /// Not owning it makes FORCE irrelevant — this is why `otto_app` works at all.
    #[test]
    fn force_is_irrelevant_when_the_role_does_not_own_the_table() {
        let r = report(vec![table("teams", true, false, false)]);
        assert!(r.problems().is_empty());
    }

    #[test]
    fn a_policy_on_a_table_with_rls_off_is_refused() {
        let r = report(vec![table("teams", false, false, false)]);
        let problems = r.problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("not enabled"), "{problems:?}");
    }

    /// An unmigrated database must not read as a healthy one. Every other check
    /// here iterates `tables`, so an empty list would otherwise pass silently.
    #[test]
    fn no_tenant_tables_at_all_is_refused() {
        let r = report(vec![]);
        let problems = r.problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("0004_rls.sql"), "{problems:?}");
    }

    /// A role-level exemption is reported once, not once per table.
    #[test]
    fn a_role_exemption_does_not_bury_itself_under_every_table() {
        let r = IsolationReport {
            effective_role: "postgres".to_string(),
            tenant_role_assumed: false,
            role_is_superuser: true,
            ..report(vec![
                table("teams", true, true, true),
                table("org_invites", true, true, true),
                table("usage_events", true, true, true),
            ])
        };
        assert_eq!(r.problems().len(), 1);
    }
}
