//! The email outbox: a row exists if and only if the transaction that queued
//! it committed, each org sees only its own mail, and the delivery task (and
//! nothing else unpinned) reaches every org's rows.

mod common;

use common::{db, tenant};
use otto_core::notifications::{self, DueEmail, MAX_ATTEMPTS};
use otto_tenant::Db;
use sqlx::PgPool;

async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM notification_outbox")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_enqueue_in_a_rolled_back_transaction_leaves_nothing(pool: PgPool) {
    let db = db(pool.clone());
    let t = tenant(&db, "acme").await;

    let mut tx = db.begin(t.org).await.unwrap();
    notifications::enqueue_email(&mut tx, "owner@acme.test", "Budget at 50%", "Half spent.")
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(count(&pool).await, 0);

    // Dropped without commit is a rollback too.
    let mut tx = db.begin(t.org).await.unwrap();
    notifications::enqueue_email(&mut tx, "owner@acme.test", "Budget at 50%", "Half spent.")
        .await
        .unwrap();
    drop(tx);
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_committed_enqueue_is_queued_in_its_own_org_only(pool: PgPool) {
    let db = db(pool.clone());
    let acme = tenant(&db, "acme").await;
    let globex = tenant(&db, "globex").await;

    let mut tx = db.begin(acme.org).await.unwrap();
    let id = notifications::enqueue_email(
        &mut tx,
        "  owner@acme.test ",
        "Budget at 80%",
        "Four fifths.",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let row: (uuid::Uuid, String, i32, bool) = sqlx::query_as(
        "SELECT org_id, recipient, attempts, sent_at IS NULL FROM notification_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (acme.org.as_uuid(), "owner@acme.test".into(), 0, true));

    let visible = |org| {
        let db = db.clone();
        async move {
            let mut tx = db.begin(org).await.unwrap();
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_outbox")
                .fetch_one(tx.conn())
                .await
                .unwrap();
            n
        }
    };
    assert_eq!(visible(acme.org).await, 1);
    assert_eq!(visible(globex.org).await, 0, "another org's mail leaked");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_malformed_recipient_or_subject_is_refused_and_writes_nothing(pool: PgPool) {
    let db = db(pool.clone());
    let t = tenant(&db, "acme").await;

    let mut tx = db.begin(t.org).await.unwrap();
    for (to, subject) in [
        ("not-an-address", "ok"),
        ("owner@acme.test\r\nBcc: x@evil.test", "ok"),
        ("owner@acme.test", "line\r\nBcc: x@evil.test"),
    ] {
        let err = notifications::enqueue_email(&mut tx, to, subject, "body")
            .await
            .expect_err(to);
        assert_eq!(err.code(), "invalid_argument", "{err}");
    }
    tx.commit().await.unwrap();
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_outbox_is_a_verified_tenant_table(pool: PgPool) {
    let report = db(pool).verify_tenant_isolation().await.unwrap();
    assert!(
        report
            .tables
            .iter()
            .any(|t| t.name == "notification_outbox"),
        "the boot isolation check does not cover notification_outbox: {:?}",
        report.tables
    );
}

/// The managed-Postgres shape, where the delivery task's role is subject to
/// row-level security: simulated by dropping into `otto_app` (neither owner
/// nor superuser) without pinning an org.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn only_an_opted_in_unpinned_transaction_reaches_every_org(pool: PgPool) {
    let db = db(pool.clone());
    for slug in ["acme", "globex"] {
        let t = tenant(&db, slug).await;
        let mut tx = db.begin(t.org).await.unwrap();
        notifications::enqueue_email(&mut tx, "owner@x.test", "s", "b")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn seen(pool: &PgPool, pin: Option<uuid::Uuid>, opt_in: bool) -> i64 {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE otto_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        if let Some(org) = pin {
            sqlx::query("SELECT set_config('app.org_id', $1, true)")
                .bind(org.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        if opt_in {
            sqlx::query("SELECT set_config('app.notification_delivery', 'on', true)")
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox")
            .fetch_one(&mut *tx)
            .await
            .unwrap()
    }

    // Ordinary unpinned control-plane code sees nothing, as with every tenant table.
    assert_eq!(seen(&pool, None, false).await, 0);
    // The delivery task sees both orgs.
    assert_eq!(seen(&pool, None, true).await, 2);
    // A pinned transaction cannot widen its view by opting in.
    let some_org: uuid::Uuid = sqlx::query_scalar("SELECT org_id FROM notification_outbox LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(seen(&pool, Some(some_org), true).await, 1);
}

async fn queue_one(db: &Db) -> uuid::Uuid {
    let t = tenant(db, "acme").await;
    let mut tx = db.begin(t.org).await.unwrap();
    let id = notifications::enqueue_email(&mut tx, "owner@acme.test", "s", "b")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_claim_leases_the_row_so_it_is_not_claimed_twice(pool: PgPool) {
    let db = db(pool);
    let id = queue_one(&db).await;

    let first = notifications::claim_due(&db, 10).await.unwrap();
    assert_eq!(first.iter().map(|d| d.id).collect::<Vec<_>>(), vec![id]);
    assert!(notifications::claim_due(&db, 10).await.unwrap().is_empty());

    notifications::mark_sent(&db, id).await.unwrap();
    let (sent, attempts): (bool, i32) = sqlx::query_as(
        "SELECT sent_at IS NOT NULL, attempts FROM notification_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(sent);
    assert_eq!(attempts, 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn failures_back_off_and_give_up_after_the_budget(pool: PgPool) {
    let db = db(pool);
    let id = queue_one(&db).await;
    let due = notifications::claim_due(&db, 10).await.unwrap().remove(0);

    let gave_up = notifications::mark_attempt_failed(&db, &due, "smtp: timed out", false)
        .await
        .unwrap();
    assert!(!gave_up);
    let (attempts, error, delay, failed): (i32, String, f64, bool) = sqlx::query_as(
        "SELECT attempts, last_error, \
                extract(epoch FROM next_attempt_at - now())::float8, failed_at IS NOT NULL \
           FROM notification_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        (attempts, error.as_str(), failed),
        (1, "smtp: timed out", false)
    );
    assert!(
        (5.0..=10.5).contains(&delay),
        "first retry in ~10 s, got {delay}"
    );

    let last = DueEmail {
        attempts: MAX_ATTEMPTS - 1,
        ..due.clone()
    };
    assert!(
        notifications::mark_attempt_failed(&db, &last, "smtp: timed out", false)
            .await
            .unwrap()
    );

    // A permanent refusal gives up at once.
    let id2 = {
        let t = tenant(&db, "globex").await;
        let mut tx = db.begin(t.org).await.unwrap();
        let id = notifications::enqueue_email(&mut tx, "nobody@globex.test", "s", "b")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        id
    };
    let due2 = notifications::claim_due(&db, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.id == id2)
        .unwrap();
    assert!(
        notifications::mark_attempt_failed(&db, &due2, "smtp 550", true)
            .await
            .unwrap()
    );
    assert!(notifications::claim_due(&db, 10).await.unwrap().is_empty());
}
