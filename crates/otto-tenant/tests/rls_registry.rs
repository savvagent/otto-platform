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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_reads_plans_but_cannot_change_them(pool: PgPool) {
    let db = Db::from_pool(pool.clone());

    // Plans, and the capabilities they unlock, are readable from a tenant
    // transaction (plan_limits joins them) ...
    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let features: serde_json::Value =
        sqlx::query_scalar("SELECT features FROM plans WHERE plan = 'team'")
            .fetch_one(tx.conn())
            .await
            .unwrap();
    assert_eq!(features, serde_json::json!({"auto_rollback": true}));
    drop(tx);

    // ... but not writable: one org's transaction must not grant a capability
    // to every org on a tier.
    for stmt in [
        "UPDATE plans SET features = '{\"auto_rollback\": true}' WHERE plan = 'free'",
        "INSERT INTO plans (plan, display_name, included_ops) VALUES ('free', 'x', 1)",
        "DELETE FROM plans WHERE plan = 'free'",
    ] {
        let mut tx = db.begin(OrgId::new()).await.unwrap();
        let err = sqlx::query(stmt).execute(tx.conn()).await.expect_err(stmt);
        assert!(
            err.to_string().contains("permission denied"),
            "{stmt}: {err}"
        );
    }

    // Features are always a JSON object, so a consumer never has to guess
    // what an array or a scalar would mean.
    for bad in ["[]", "true", "null"] {
        let err = sqlx::query(&format!(
            "UPDATE plans SET features = '{bad}'::jsonb WHERE plan = 'free'"
        ))
        .execute(&pool)
        .await
        .expect_err(bad);
        assert!(
            err.to_string().contains("check constraint") || err.to_string().contains("null value"),
            "{bad}: {err}"
        );
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_reads_meters_but_cannot_change_them(pool: PgPool) {
    let db = Db::from_pool(pool.clone());

    // A declaration, written the way the platform writes one: unpinned, as the
    // connecting role.
    sqlx::query(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
         VALUES ('https://svc.example/mcp', 'svc', '{a}', '{}', 'svc')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut tx = db.begin_unpinned().await.unwrap();
    sqlx::query(
        "INSERT INTO meters (key, service, meter, display_name, unit) \
         VALUES ('svc/calls', 'svc', 'calls', 'Calls', 'call')",
    )
    .execute(tx.conn())
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Meters are readable from a tenant transaction (usage ingest checks an
    // event's meter against them) ...
    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let unit: String = sqlx::query_scalar("SELECT unit FROM meters WHERE key = 'svc/calls'")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(unit, "call");
    drop(tx);

    // ... but not writable: one org's transaction must not invent, rename, or
    // remove what every org is charged for.
    for stmt in [
        "INSERT INTO meters (key, service, meter, display_name, unit) \
         VALUES ('svc/free', 'svc', 'free', 'Free', 'x')",
        "UPDATE meters SET unit = 'byte' WHERE key = 'svc/calls'",
        "DELETE FROM meters WHERE key = 'svc/calls'",
        "TRUNCATE meters",
    ] {
        let mut tx = db.begin(OrgId::new()).await.unwrap();
        let err = sqlx::query(stmt).execute(tx.conn()).await.expect_err(stmt);
        assert!(
            err.to_string().contains("permission denied"),
            "{stmt}: {err}"
        );
    }

    // The key is always `<service>/<meter>`, and both parts are slugs.
    for (key, service, meter) in [
        ("svc/other", "svc", "calls"),
        ("svc/Calls", "svc", "Calls"),
        ("svc/1calls", "svc", "1calls"),
        ("nope/calls", "nope", "calls"),
    ] {
        let err = sqlx::query(
            "INSERT INTO meters (key, service, meter, display_name, unit) \
             VALUES ($1, $2, $3, 'X', 'x')",
        )
        .bind(key)
        .bind(service)
        .bind(meter)
        .execute(&pool)
        .await
        .expect_err(key);
        let msg = err.to_string();
        assert!(
            msg.contains("check constraint") || msg.contains("foreign key"),
            "{key}: {msg}"
        );
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_reads_the_price_book_but_cannot_change_it(pool: PgPool) {
    let db = Db::from_pool(pool.clone());

    // A meter and a price, written the way the operator CLI writes them:
    // unpinned, as the connecting role. A fixture, not a real rate.
    sqlx::query(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
         VALUES ('https://svc.example/mcp', 'svc', '{a}', '{}', 'svc')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut tx = db.begin_unpinned().await.unwrap();
    sqlx::query(
        "INSERT INTO meters (key, service, meter, display_name, unit) \
         VALUES ('svc/calls', 'svc', 'calls', 'Calls', 'call')",
    )
    .execute(tx.conn())
    .await
    .unwrap();
    let version: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ('svc/calls', '2026-11-01') RETURNING id",
    )
    .fetch_one(tx.conn())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, 100, 0), ($1, 1, NULL, 7)",
    )
    .bind(version)
    .execute(tx.conn())
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // The price book is readable from a tenant transaction (billing rates an
    // org's usage against it) ...
    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let amounts: Vec<i64> = sqlx::query_scalar(
        "SELECT t.unit_amount_ucents FROM price_tiers t \
         JOIN price_versions v ON v.id = t.version_id \
         WHERE v.meter = 'svc/calls' ORDER BY t.position",
    )
    .fetch_all(tx.conn())
    .await
    .unwrap();
    assert_eq!(amounts, [0, 7]);
    drop(tx);

    // ... but not writable: one org's transaction must not reprice a meter for
    // every org.
    let insert_version = "INSERT INTO price_versions (meter, effective_month) \
                          VALUES ('svc/calls', '2026-12-01')";
    let insert_tier = format!(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ('{version}', 2, NULL, 1)"
    );
    for stmt in [
        insert_version,
        "UPDATE price_versions SET effective_month = '2027-01-01'",
        "DELETE FROM price_versions",
        "TRUNCATE price_versions CASCADE",
        insert_tier.as_str(),
        "UPDATE price_tiers SET unit_amount_ucents = 0",
        "DELETE FROM price_tiers",
        "TRUNCATE price_tiers",
    ] {
        let mut tx = db.begin(OrgId::new()).await.unwrap();
        let err = sqlx::query(stmt).execute(tx.conn()).await.expect_err(stmt);
        assert!(
            err.to_string().contains("permission denied"),
            "{stmt}: {err}"
        );
    }

    // What a row can state alone is enforced by the schema: first-of-month
    // versions, positive bounds, non-negative amounts, one unbounded tier, and
    // only existing meters.
    for stmt in [
        "INSERT INTO price_versions (meter, effective_month) VALUES ('svc/calls', '2026-12-02')",
        "INSERT INTO price_versions (meter, effective_month) VALUES ('svc/nope', '2026-12-01')",
        "INSERT INTO price_versions (meter, effective_month) VALUES ('svc/calls', '2026-11-01')",
    ] {
        let err = sqlx::query(stmt).execute(&pool).await.expect_err(stmt);
        let msg = err.to_string();
        assert!(
            msg.contains("check constraint")
                || msg.contains("foreign key")
                || msg.contains("duplicate key"),
            "{stmt}: {msg}"
        );
    }
    for (position, up_to, amount) in [
        (2_i16, Some(0_i64), 1_i64),
        (2, None, -1),
        (-1, Some(500), 1),
        (2, None, 1),
    ] {
        let err = sqlx::query(
            "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(version)
        .bind(position)
        .bind(up_to)
        .bind(amount)
        .execute(&pool)
        .await
        .expect_err("a malformed tier");
        let msg = err.to_string();
        assert!(
            msg.contains("check constraint") || msg.contains("duplicate key"),
            "{position} {up_to:?} {amount}: {msg}"
        );
    }
}
