//! A configured tenant role is the one `begin`, the assumability probe and
//! `verify_tenant_isolation` actually use.

use savvagent_tenant::ids::OrgId;
use savvagent_tenant::{Db, Error};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

/// Roles are cluster-wide, so this name is unique to this test file and the
/// creation is idempotent (a test database is dropped, the role is not).
const CUSTOM_ROLE: &str = "otto_tenant_test_role";

async fn ensure_custom_role(pool: &PgPool) {
    sqlx::query(&format!(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CUSTOM_ROLE}') THEN \
             CREATE ROLE {CUSTOM_ROLE} NOLOGIN; \
           END IF; END $$"
    ))
    .execute(pool)
    .await
    .unwrap();
    for stmt in [
        format!("GRANT {CUSTOM_ROLE} TO CURRENT_USER"),
        format!("GRANT USAGE ON SCHEMA public TO {CUSTOM_ROLE}"),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {CUSTOM_ROLE}"
        ),
    ] {
        sqlx::query(&stmt).execute(pool).await.unwrap();
    }
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn the_default_role_is_otto_app(pool: PgPool) {
    let db = Db::from_pool(pool);
    assert_eq!(db.tenant_role(), "otto_app");

    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(who, "otto_app");

    let report = db.verify_tenant_isolation().await.unwrap();
    assert_eq!(report.tenant_role, "otto_app");
    assert_eq!(report.effective_role, "otto_app");
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_custom_role_is_assumed_and_reported(pool: PgPool) {
    ensure_custom_role(&pool).await;
    let db = Db::from_pool(pool).with_tenant_role(CUSTOM_ROLE).unwrap();
    assert_eq!(db.tenant_role(), CUSTOM_ROLE);

    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(who, CUSTOM_ROLE);
    tx.rollback().await.unwrap();

    let report = db.verify_tenant_isolation().await.unwrap();
    assert_eq!(report.tenant_role, CUSTOM_ROLE);
    assert_eq!(report.effective_role, CUSTOM_ROLE);
    assert!(report.tenant_role_assumed);
    assert!(
        report
            .summary()
            .contains(&format!("SET LOCAL ROLE {CUSTOM_ROLE}")),
        "{}",
        report.summary()
    );
}

/// A configured role that does not exist is not assumed, and on a superuser
/// connection that is refused with a message naming the configured role.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_missing_custom_role_is_not_assumed(pool: PgPool) {
    let db = Db::from_pool(pool)
        .with_tenant_role("otto_tenant_no_such_role")
        .unwrap();
    match db.verify_tenant_isolation().await {
        Err(Error::IsolationNotEnforced { problems }) => {
            assert!(problems.contains("otto_tenant_no_such_role"), "{problems}");
            assert!(!problems.contains("otto_app"), "{problems}");
        }
        other => panic!("expected IsolationNotEnforced, got {other:?}"),
    }
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_invalid_role_is_rejected_before_use(pool: PgPool) {
    let r = Db::from_pool(pool).with_tenant_role("otto_app; DROP TABLE users");
    assert!(matches!(r, Err(Error::Invalid(_))));
}

/// A pool of one connection with a short acquire timeout, so a `begin` that
/// holds its connection while acquiring another fails fast instead of hanging.
async fn single_connection_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn the_first_begin_needs_only_one_connection(pool: PgPool) {
    let db = Db::from_pool(single_connection_pool(&pool).await);

    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(who, "otto_app");
    tx.rollback().await.unwrap();
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn concurrent_first_begins_share_one_connection_pool(pool: PgPool) {
    let db = Db::from_pool(single_connection_pool(&pool).await);

    let begins: Vec<_> = (0..4)
        .map(|_| {
            let db = db.clone();
            tokio::spawn(async move {
                let tx = db.begin(OrgId::new()).await.unwrap();
                tx.rollback().await.unwrap();
            })
        })
        .collect();
    for begin in begins {
        begin.await.unwrap();
    }
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn verify_tenant_isolation_needs_only_one_connection(pool: PgPool) {
    let db = Db::from_pool(single_connection_pool(&pool).await);
    db.verify_tenant_isolation().await.unwrap();
}
