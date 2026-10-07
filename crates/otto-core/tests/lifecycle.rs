//! The lifecycle outbox: an event row exists if and only if the mutation that
//! caused it committed, and fans out only to enabled resource servers that
//! have a webhook.

mod common;

use common::{db, tenant};
use otto_core::lifecycle;
use otto_core::orgs::{OrgsExt, OrgsTxExt, Role};
use otto_core::teams::TeamsExt;
use otto_tenant::Db;
use sqlx::PgPool;

const WITH_HOOK: &str = "https://hooked.example/mcp";
const NO_HOOK: &str = "https://plain.example/mcp";
const DISABLED: &str = "https://off.example/mcp";

/// Registry rows written directly: `otto-core` cannot depend on `otto-auth`'s
/// `resources` module, and the outbox only reads these columns.
async fn registry(pool: &PgPool) {
    for (uri, hook, disabled) in [
        (WITH_HOOK, Some("https://hooked.example/hook"), false),
        (NO_HOOK, None, false),
        (DISABLED, Some("https://off.example/hook"), true),
    ] {
        sqlx::query(
            "INSERT INTO resource_servers \
               (resource_uri, name, scopes, default_scopes, disabled, \
                webhook_url, webhook_secret_ciphertext, webhook_secret_nonce) \
             VALUES ($1, $1, '{a}', '{a}', $2, $3::text, \
                     CASE WHEN $3::text IS NULL THEN NULL ELSE '\\x00'::bytea END, \
                     CASE WHEN $3::text IS NULL THEN NULL ELSE '\\x00'::bytea END)",
        )
        .bind(uri)
        .bind(disabled)
        .bind(hook)
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn events(db: &Db) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as("SELECT kind, data FROM lifecycle_events ORDER BY created_at, kind")
        .fetch_all(db.pool())
        .await
        .unwrap()
}

async fn deliveries(db: &Db) -> Vec<String> {
    sqlx::query_scalar("SELECT resource_uri FROM webhook_deliveries ORDER BY resource_uri")
        .fetch_all(db.pool())
        .await
        .unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn org_deletion_queues_an_event_for_enabled_hooked_servers_only(pool: PgPool) {
    registry(&pool).await;
    let db = db(pool);
    let t = tenant(&db, "acme").await;

    db.delete_org(t.org).await.unwrap();

    let ev = events(&db).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, "org.deleted");
    assert_eq!(ev[0].1["org_id"], t.org.to_string());
    assert_eq!(deliveries(&db).await, [WITH_HOOK]);

    assert!(db.get_active_org(t.org).await.unwrap().is_none());
    assert!(db.get_org(t.org).await.unwrap().is_some());
    assert!(db
        .active_member_role(t.org, t.user)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn deleting_an_org_twice_queues_nothing_the_second_time(pool: PgPool) {
    registry(&pool).await;
    let db = db(pool);
    let t = tenant(&db, "acme").await;

    db.delete_org(t.org).await.unwrap();
    assert!(db.delete_org(t.org).await.is_err());
    assert_eq!(events(&db).await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn team_deletion_queues_an_event_in_the_same_transaction(pool: PgPool) {
    registry(&pool).await;
    let db = db(pool);
    let t = tenant(&db, "acme").await;

    let mut tx = db.begin(t.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.commit().await.unwrap();

    // Rolled back: the team survives, so no event may exist.
    let mut tx = db.begin(t.org).await.unwrap();
    tx.delete_team(team.id).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(
        events(&db).await.is_empty(),
        "a rolled-back delete queued an event"
    );
    assert!(deliveries(&db).await.is_empty());

    let mut tx = db.begin(t.org).await.unwrap();
    tx.delete_team(team.id).await.unwrap();
    tx.commit().await.unwrap();

    let ev = events(&db).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, "team.deleted");
    assert_eq!(ev[0].1["team_id"], team.id.to_string());
    assert_eq!(ev[0].1["org_id"], t.org.to_string());
    assert_eq!(deliveries(&db).await, [WITH_HOOK]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn member_removal_queues_an_event_only_when_a_member_was_removed(pool: PgPool) {
    registry(&pool).await;
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let other = db.upsert_user("dev@acme.test", None).await.unwrap();
    db.add_member(t.org, other.id, Role::Member).await.unwrap();

    // Pinned-transaction path, rolled back.
    let mut tx = db.begin(t.org).await.unwrap();
    tx.remove_member(other.id).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(events(&db).await.is_empty());
    assert!(db.member_role(t.org, other.id).await.unwrap().is_some());

    // Pinned-transaction path, committed.
    let mut tx = db.begin(t.org).await.unwrap();
    tx.remove_member(other.id).await.unwrap();
    tx.commit().await.unwrap();
    let ev = events(&db).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, "member.removed");
    assert_eq!(ev[0].1["user_id"], other.id.to_string());

    // Removing someone who is not a member is not news.
    db.remove_member(t.org, other.id).await.unwrap();
    assert_eq!(events(&db).await.len(), 1);

    // The unpinned path queues too.
    db.add_member(t.org, other.id, Role::Member).await.unwrap();
    db.remove_member(t.org, other.id).await.unwrap();
    assert_eq!(events(&db).await.len(), 2);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn failed_deliveries_back_off_and_are_eventually_abandoned(pool: PgPool) {
    registry(&pool).await;
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    db.delete_org(t.org).await.unwrap();

    let due = lifecycle::claim_due(&db, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    // Claiming leased the row: a second claim sees nothing.
    assert!(lifecycle::claim_due(&db, 10).await.unwrap().is_empty());

    let mut d = due.into_iter().next().unwrap();
    assert!(
        !lifecycle::mark_attempt_failed(&db, &d, Some(500), "HTTP 500")
            .await
            .unwrap()
    );
    let (attempts, last_error, wait): (i32, String, f64) = sqlx::query_as(
        "SELECT attempts, last_error, extract(epoch FROM next_attempt_at - now())::float8 \
         FROM webhook_deliveries",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((attempts, last_error.as_str()), (1, "HTTP 500"));
    assert!(
        (5.0..=10.0).contains(&wait),
        "first retry in ~10 s, got {wait}"
    );

    d.attempts = lifecycle::MAX_ATTEMPTS - 1;
    assert!(lifecycle::mark_attempt_failed(&db, &d, None, "gone")
        .await
        .unwrap());
    sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        lifecycle::claim_due(&db, 10).await.unwrap().is_empty(),
        "an abandoned delivery must not be claimed again"
    );
}
