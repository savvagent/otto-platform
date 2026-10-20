//! The email outbox: a row exists if and only if the transaction that queued
//! it committed, each org sees only its own mail, and the delivery task (and
//! nothing else unpinned) reaches every org's rows.

mod common;

use common::{db, tenant};
use otto_core::notifications::{self, DueEmail, FailureRecorded, MAX_ATTEMPTS};
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

    assert!(notifications::mark_sent(&db, &first[0]).await.unwrap());
    assert!(
        !notifications::mark_sent(&db, &first[0]).await.unwrap(),
        "a second result for a sent row was recorded"
    );
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

    let recorded = notifications::mark_attempt_failed(&db, &due, "smtp: timed out", false)
        .await
        .unwrap();
    assert_eq!(recorded, FailureRecorded::Retrying);
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

    // The last attempt in the budget gives up. Claimed afresh: the first
    // claim's result is recorded, so its token no longer holds the row.
    sqlx::query(
        "UPDATE notification_outbox SET next_attempt_at = now(), attempts = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(MAX_ATTEMPTS - 1)
    .execute(db.pool())
    .await
    .unwrap();
    let last: DueEmail = notifications::claim_due(&db, 10).await.unwrap().remove(0);
    assert_eq!(last.attempts, MAX_ATTEMPTS - 1);
    assert_eq!(
        notifications::mark_attempt_failed(&db, &last, "smtp: timed out", false)
            .await
            .unwrap(),
        FailureRecorded::GaveUp
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
    assert_eq!(
        notifications::mark_attempt_failed(&db, &due2, "smtp 550", true)
            .await
            .unwrap(),
        FailureRecorded::GaveUp
    );
    assert!(notifications::claim_due(&db, 10).await.unwrap().is_empty());
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct State {
    attempts: i32,
    sent: bool,
    failed: bool,
    last_error: Option<String>,
    /// Seconds until the row is due again (negative: overdue).
    due_in: f64,
    sending: bool,
}

async fn state(db: &Db, id: uuid::Uuid) -> State {
    sqlx::query_as(
        "SELECT attempts, sent_at IS NOT NULL AS sent, failed_at IS NOT NULL AS failed, \
                last_error, extract(epoch FROM next_attempt_at - now())::float8 AS due_in, \
                sending_since IS NOT NULL AS sending \
           FROM notification_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// Let `id`'s current claim lapse, as a task stalled past its lease would.
async fn lapse(db: &Db, id: uuid::Uuid) {
    sqlx::query("UPDATE notification_outbox SET next_attempt_at = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await
        .unwrap();
}

/// A task whose lease lapsed (row claimed again by a second task) reports a
/// failure: it must not reschedule the row under the second claim, which
/// would make it due, and sendable by a third task, while the second task's
/// send is still in flight.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_lapsed_claims_failure_cannot_overwrite_the_newer_claim(pool: PgPool) {
    let db = db(pool);
    let id = queue_one(&db).await;

    let stale = notifications::claim_due(&db, 10).await.unwrap().remove(0);
    lapse(&db, id).await;
    let fresh = notifications::claim_due(&db, 10).await.unwrap().remove(0);
    assert_eq!(fresh.id, id);
    assert_ne!(fresh.claimed_at, stale.claimed_at, "claims share a token");
    let before = state(&db, id).await;
    assert!(before.sending && before.due_in > 60.0, "{before:?}");

    for permanent in [false, true] {
        assert_eq!(
            notifications::mark_attempt_failed(&db, &stale, "smtp: timed out", permanent)
                .await
                .unwrap(),
            FailureRecorded::Superseded
        );
    }
    let after = state(&db, id).await;
    assert_eq!(
        (
            after.attempts,
            after.sent,
            after.failed,
            after.last_error.as_deref(),
            after.sending
        ),
        (0, false, false, None, true),
        "the stale claim wrote over the fresh one"
    );
    assert!(
        after.due_in > 60.0,
        "the fresh claim's lease was cut short: {after:?}"
    );
    assert!(
        notifications::claim_due(&db, 10).await.unwrap().is_empty(),
        "a third task could claim the row mid-send"
    );

    // The fresh claim's own result is recorded as usual.
    assert_eq!(
        notifications::mark_attempt_failed(&db, &fresh, "smtp: 451", false)
            .await
            .unwrap(),
        FailureRecorded::Retrying
    );
    let s = state(&db, id).await;
    assert_eq!((s.attempts, s.sending), (1, false));
    assert_eq!(s.last_error.as_deref(), Some("smtp: 451"));
}

/// A delivered message is a fact whichever claim delivered it: a lapsed
/// claim's successful send finishes the row, and the newer claim's result
/// then changes nothing, so a failed duplicate cannot schedule yet another.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_lapsed_claims_success_finishes_the_row_for_good(pool: PgPool) {
    let db = db(pool);
    let id = queue_one(&db).await;

    let stale = notifications::claim_due(&db, 10).await.unwrap().remove(0);
    lapse(&db, id).await;
    let fresh = notifications::claim_due(&db, 10).await.unwrap().remove(0);

    assert!(notifications::mark_sent(&db, &stale).await.unwrap());
    assert_eq!(
        notifications::mark_attempt_failed(&db, &fresh, "smtp: 451", false)
            .await
            .unwrap(),
        FailureRecorded::Superseded
    );
    assert!(!notifications::mark_sent(&db, &fresh).await.unwrap());

    let s = state(&db, id).await;
    assert_eq!(
        (s.attempts, s.sent, s.failed, s.last_error, s.sending),
        (1, true, false, None, false)
    );
    lapse(&db, id).await;
    assert!(notifications::claim_due(&db, 10).await.unwrap().is_empty());
}

/// The real delivery functions, on a pool whose every connection runs as
/// `otto_app` (neither owner nor superuser), so FORCE ROW LEVEL SECURITY and
/// the delivery policies are what decide, exactly as for a schema-owner
/// connection on managed Postgres.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn delivery_works_across_orgs_under_row_level_security(pool: PgPool) {
    let owner = db(pool.clone());
    let mut ids = Vec::new();
    for slug in ["acme", "globex", "initech"] {
        let t = tenant(&owner, slug).await;
        let mut tx = owner.begin(t.org).await.unwrap();
        ids.push(
            notifications::enqueue_email(&mut tx, "owner@x.test", "s", "b")
                .await
                .unwrap(),
        );
        tx.commit().await.unwrap();
    }
    // Old enough to sweep once finished.
    sqlx::query("UPDATE notification_outbox SET created_at = now() - interval '30 days'")
        .execute(&pool)
        .await
        .unwrap();

    let restricted = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE otto_app").execute(conn).await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&restricted)
        .await
        .unwrap();
    assert_eq!(who, "otto_app");
    let app = Db::from_pool(restricted.clone());

    let mut due = notifications::claim_due(&app, 10).await.unwrap();
    due.sort_by_key(|d| ids.iter().position(|i| *i == d.id));
    assert_eq!(
        due.iter().map(|d| d.id).collect::<Vec<_>>(),
        ids,
        "every org's row is claimed"
    );

    assert!(notifications::mark_sent(&app, &due[0]).await.unwrap());
    assert_eq!(
        notifications::mark_attempt_failed(&app, &due[1], "smtp: 451", false)
            .await
            .unwrap(),
        FailureRecorded::Retrying
    );
    assert_eq!(
        notifications::mark_attempt_failed(&app, &due[2], "smtp: 550", true)
            .await
            .unwrap(),
        FailureRecorded::GaveUp
    );

    let states: Vec<(bool, bool, i32)> = sqlx::query_as(
        "SELECT sent_at IS NOT NULL, failed_at IS NOT NULL, attempts \
           FROM notification_outbox WHERE id = ANY($1) ORDER BY array_position($1, id)",
    )
    .bind(&ids)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        states,
        vec![(true, false, 1), (false, false, 1), (false, true, 1)]
    );

    // A finished row is final: a late duplicate result does not touch it.
    assert_eq!(
        notifications::mark_attempt_failed(&app, &due[0], "late", false)
            .await
            .unwrap(),
        FailureRecorded::Superseded
    );
    let sent_err: Option<String> =
        sqlx::query_scalar("SELECT last_error FROM notification_outbox WHERE id = $1")
            .bind(ids[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sent_err, None);

    // Sweep removes the sent and the failed row, never the queued one.
    assert_eq!(notifications::sweep(&app, 14).await.unwrap(), 2);
    let left: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM notification_outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![ids[1]]);

    // Opted in and unpinned, it still cannot create a row for any org.
    let mut tx = restricted.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.notification_delivery', 'on', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let org: uuid::Uuid = sqlx::query_scalar("SELECT id FROM orgs LIMIT 1")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let err = sqlx::query(
        "INSERT INTO notification_outbox (org_id, recipient, subject, body_text) \
         VALUES ($1, 'x@y.test', 's', 'b')",
    )
    .bind(org)
    .execute(&mut *tx)
    .await
    .expect_err("an unpinned insert was admitted");
    assert!(err.to_string().contains("row-level security"), "{err}");
}
