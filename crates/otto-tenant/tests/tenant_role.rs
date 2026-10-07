//! A configured tenant role is the one `begin`, the assumability probe and
//! `verify_tenant_isolation` actually use.

use otto_tenant::ids::OrgId;
use otto_tenant::{Db, Error};
use sqlx::PgPool;

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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
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
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_invalid_role_is_rejected_before_use(pool: PgPool) {
    let r = Db::from_pool(pool).with_tenant_role("otto_app; DROP TABLE users");
    assert!(matches!(r, Err(Error::Invalid(_))));
}
