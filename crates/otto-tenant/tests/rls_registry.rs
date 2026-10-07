//! Every table with an `org_id` column is either under row-level security or
//! on an explicit allowlist of global tables, so a new table cannot quietly
//! ship holding cross-tenant rows that tenant-pinned code can read.

use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use sqlx::PgPool;

/// Tables that carry an `org_id` but are deliberately not tenant-scoped, each
/// because it is read or written before an org is pinned (authentication, the
/// AS, the delivery task) or is a cross-tenant ledger. Adding a table here is a
/// decision that its access by `otto_app` has been thought through: see the
/// test below for the ones `otto_app` must not touch at all.
const GLOBAL_TABLES: &[&str] = &[
    // Authentication resolves these before an org is known (0004's comment).
    "access_tokens",
    "refresh_tokens",
    "authorization_codes",
    "sso_ceremonies",
    "idp_connections",
    "claimed_domains",
    // The tenant boundary itself.
    "org_members",
    // Cross-tenant outbox and ledger (0009, 0011): `otto_app` has no read access.
    "lifecycle_events",
    "usage_event_ids",
];

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn every_org_scoped_table_is_rls_protected_or_explicitly_global(pool: PgPool) {
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity \
           FROM pg_class c \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
           JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped \
          WHERE n.nspname = 'public' AND c.relkind = 'r' \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(rows.len() > 5, "the catalog query found nothing: {rows:?}");

    let mut problems = Vec::new();
    for (table, rls, forced) in &rows {
        let global = GLOBAL_TABLES.contains(&table.as_str());
        match (*rls && *forced, global) {
            (true, false) | (false, true) => {}
            (true, true) => problems.push(format!("{table} is RLS-protected but allowlisted as global")),
            (false, false) => problems.push(format!(
                "{table} has an org_id column but neither RLS (enabled and forced) nor a place in GLOBAL_TABLES"
            )),
        }
    }
    // A stale allowlist entry hides nothing today but would excuse a future table of that name.
    for g in GLOBAL_TABLES {
        if !rows.iter().any(|(t, _, _)| t == g) {
            problems.push(format!(
                "GLOBAL_TABLES lists {g}, which has no org_id column or does not exist"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_cannot_read_the_cross_tenant_tables(pool: PgPool) {
    let db = Db::from_pool(pool);
    for table in ["lifecycle_events", "webhook_deliveries", "usage_event_ids"] {
        let mut tx = db.begin(OrgId::new()).await.unwrap();
        let read = sqlx::query(&format!("SELECT * FROM {table}"))
            .fetch_all(tx.conn())
            .await;
        let err = read.expect_err(&format!("otto_app read {table}"));
        assert!(
            err.to_string().contains("permission denied"),
            "{table}: {err}"
        );
    }

    // The one thing it may do to the outbox: append.
    let org = OrgId::new();
    let mut tx = db.begin(org).await.unwrap();
    sqlx::query(
        "INSERT INTO lifecycle_events (kind, org_id, data) VALUES ('org.deleted', $1, '{}')",
    )
    .bind(org.as_uuid())
    .execute(tx.conn())
    .await
    .unwrap();
    tx.rollback().await.unwrap();
}
