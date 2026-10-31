//! A rolled-back release boots against the schema a newer release migrated:
//! `Db::migrate` ignores applied migrations it does not know, while still
//! refusing a known migration whose applied checksum differs.

use savvagent_tenant::Db;
use sqlx::migrate::MigrateError;
use sqlx::PgPool;

/// Far beyond any real migration number, so it can only be "a newer release's".
const FUTURE_VERSION: i64 = 99_990_001;

/// Record `FUTURE_VERSION` as applied, as a newer release's migrator would.
async fn apply_a_newer_release(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'from a newer release', true, '\\x00'::bytea, 0)",
    )
    .bind(FUTURE_VERSION)
    .execute(pool)
    .await
    .unwrap();
    // And the kind of thing it would do: an additive change this binary
    // knows nothing about.
    sqlx::query("ALTER TABLE orgs ADD COLUMN from_the_future text")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_older_release_boots_against_a_newer_schema(pool: PgPool) {
    apply_a_newer_release(&pool).await;

    // sqlx's default would refuse to boot: this is what the setting changes.
    let strict = sqlx::migrate!("./migrations");
    let err = strict.run(&pool).await.expect_err("strict migrator booted");
    assert!(
        matches!(err, MigrateError::VersionMissing(v) if v == FUTURE_VERSION),
        "{err}"
    );

    // The release's own migrator boots, twice (a restart), and leaves the
    // newer release's record and change alone.
    let db = Db::from_pool(pool.clone());
    db.migrate().await.unwrap();
    db.migrate().await.unwrap();
    let still_there: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
            .bind(FUTURE_VERSION)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(still_there);
    sqlx::query("SELECT from_the_future FROM orgs LIMIT 1")
        .fetch_all(&pool)
        .await
        .unwrap();
    db.verify_tenant_isolation().await.unwrap();
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_edited_known_migration_is_still_refused(pool: PgPool) {
    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00'::bytea WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let err = Db::from_pool(pool)
        .migrate()
        .await
        .expect_err("a changed checksum was accepted");
    assert!(
        err.to_string()
            .contains("was previously applied but has been modified"),
        "{err}"
    );
}
