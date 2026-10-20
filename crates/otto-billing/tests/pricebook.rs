//! `pricebook`: versions by effective month, written unpinned, read anywhere.
//!
//! Prices here are fixtures, not rates anyone is charged. `set_version` only
//! writes future months, so versions already in effect are inserted directly,
//! as the test pool's superuser.

use std::time::Duration;

use otto_billing::pricebook::{
    book_in_effect, current_month, list_versions, rate, set_version, tiers_in_effect, Error,
    LineAmount, Month, Tier, Tiers,
};
use otto_tenant::{Db, OrgId};
use sqlx::PgPool;
use uuid::Uuid;

/// Registers a resource server for `svc` and declares `svc/calls` and
/// `svc/bytes`, as the test pool's superuser.
async fn seed_meters(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
         VALUES ('https://svc.example/mcp', 'svc', '{a}', '{}', 'svc')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO meters (key, service, meter, display_name, unit) VALUES \
         ('svc/calls', 'svc', 'calls', 'Calls', 'call'), \
         ('svc/bytes', 'svc', 'bytes', 'Bytes', 'byte')",
    )
    .execute(pool)
    .await
    .unwrap();
}

fn month(s: &str) -> Month {
    s.parse().unwrap()
}

/// A flat price of `ucents` per unit.
fn flat(ucents: i64) -> Tiers {
    Tiers::new(vec![Tier {
        up_to: None,
        unit_amount_ucents: ucents,
    }])
    .unwrap()
}

/// Insert a version directly, bypassing `set_version`'s future-only rule.
async fn insert_flat(pool: &PgPool, meter: &str, m: Month, ucents: i64) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) VALUES ($1, $2) RETURNING id",
    )
    .bind(meter)
    .bind(m.first_day())
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, NULL, $2)",
    )
    .bind(id)
    .bind(ucents)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn set(db: &Db, meter: &str, m: Month, tiers: &Tiers) -> Result<(), Error> {
    let mut tx = db.begin_unpinned().await.unwrap();
    set_version(&mut tx, meter, m, tiers).await?;
    tx.commit().await.unwrap();
    Ok(())
}

async fn in_effect(db: &Db, meter: &str, m: &str) -> Option<i64> {
    let mut tx = db.begin_unpinned().await.unwrap();
    let v = tiers_in_effect(tx.conn(), meter, month(m)).await.unwrap();
    v.map(|v| v.tiers.as_slice()[0].unit_amount_ucents)
}

async fn now_month(db: &Db) -> Month {
    let mut tx = db.begin_unpinned().await.unwrap();
    current_month(tx.conn()).await.unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_latest_version_not_after_the_month_is_in_effect(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    insert_flat(&pool, "svc/calls", month("2026-01"), 100).await;
    insert_flat(&pool, "svc/calls", month("2026-04"), 200).await;
    insert_flat(&pool, "svc/calls", month("2026-07"), 300).await;

    assert_eq!(
        in_effect(&db, "svc/calls", "2025-12").await,
        None,
        "before any price"
    );
    assert_eq!(in_effect(&db, "svc/calls", "2026-01").await, Some(100));
    assert_eq!(in_effect(&db, "svc/calls", "2026-03").await, Some(100));
    assert_eq!(
        in_effect(&db, "svc/calls", "2026-04").await,
        Some(200),
        "from its first day"
    );
    assert_eq!(in_effect(&db, "svc/calls", "2026-06").await, Some(200));
    assert_eq!(in_effect(&db, "svc/calls", "2026-07").await, Some(300));
    assert_eq!(
        in_effect(&db, "svc/calls", "2031-01").await,
        Some(300),
        "until the next"
    );
    assert_eq!(
        in_effect(&db, "svc/bytes", "2026-07").await,
        None,
        "another meter's price"
    );

    // An unpriced meter rates to 0 and says so.
    let mut tx = db.begin_unpinned().await.unwrap();
    let none = tiers_in_effect(tx.conn(), "svc/bytes", month("2026-07"))
        .await
        .unwrap();
    assert_eq!(
        rate(1_000, none.as_ref().map(|v| &v.tiers)).unwrap(),
        LineAmount::Unpriced
    );

    // The book lists each priced meter once, with the version in effect.
    let book = book_in_effect(tx.conn(), month("2026-05")).await.unwrap();
    assert_eq!(book.len(), 1, "svc/bytes is unpriced and left out");
    assert_eq!(book[0].meter.key, "svc/calls");
    assert_eq!(book[0].meter.service, "svc");
    assert_eq!(book[0].meter.meter, "calls");
    assert_eq!(book[0].meter.display_name, "Calls");
    assert_eq!(book[0].meter.unit, "call");
    assert_eq!(book[0].version.effective_month, month("2026-04"));
    assert_eq!(book[0].version.tiers, flat(200));
    assert!(book_in_effect(tx.conn(), month("2025-12"))
        .await
        .unwrap()
        .is_empty());

    let all = list_versions(tx.conn()).await.unwrap();
    let months: Vec<String> = all.iter().map(|v| v.effective_month.to_string()).collect();
    assert_eq!(months, ["2026-01", "2026-04", "2026-07"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tiers_round_trip_in_order(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    let next = now_month(&db).await.offset(1).unwrap();
    let tiers = Tiers::new(vec![
        Tier {
            up_to: Some(1_000),
            unit_amount_ucents: 0,
        },
        Tier {
            up_to: Some(1_000_000),
            unit_amount_ucents: 150_000,
        },
        Tier {
            up_to: None,
            unit_amount_ucents: 75_000,
        },
    ])
    .unwrap();
    set(&db, "svc/calls", next, &tiers).await.unwrap();

    let mut tx = db.begin_unpinned().await.unwrap();
    let v = tiers_in_effect(tx.conn(), "svc/calls", next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.tiers, tiers);
    assert_eq!(v.meter, "svc/calls");
}

/// Only a future month may be priced: the current month is being billed at
/// the price it started with, even when a version from an earlier month is in
/// effect for it, and an unpriced meter gets its first price from next month.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn only_a_future_month_can_be_priced(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    let current = now_month(&db).await;
    let last = current.offset(-1).unwrap();
    let next = current.offset(1).unwrap();
    insert_flat(&pool, "svc/calls", last, 1).await;

    for m in [last, current] {
        let err = set(&db, "svc/calls", m, &flat(2)).await.unwrap_err();
        assert!(
            matches!(err, Error::NotFuture { month, current: c } if month == m && c == current),
            "{m}: {err}"
        );
    }
    assert_eq!(
        in_effect(&db, "svc/calls", &current.to_string()).await,
        Some(1),
        "this month keeps the price in effect when it started"
    );
    let err = set(&db, "svc/bytes", current, &flat(2)).await.unwrap_err();
    assert!(
        matches!(err, Error::NotFuture { .. }),
        "unpriced, still not now: {err}"
    );

    // A future month is set, and replaced under a new id.
    let mut tx = db.begin_unpinned().await.unwrap();
    let first = set_version(&mut tx, "svc/calls", next, &flat(5))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(first.replaced, None);
    let mut tx = db.begin_unpinned().await.unwrap();
    let second = set_version(&mut tx, "svc/calls", next, &flat(6))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(second.replaced, Some(first.version.id));
    assert_ne!(second.version.id, first.version.id);
    assert_eq!(
        in_effect(&db, "svc/calls", &next.to_string()).await,
        Some(6)
    );
    assert_eq!(
        in_effect(&db, "svc/calls", &current.to_string()).await,
        Some(1),
        "a scheduled price does not reach back"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unknown_meter_cannot_be_priced(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    let next = now_month(&db).await.offset(1).unwrap();
    let err = set(&db, "svc/nope", next, &flat(1)).await.unwrap_err();
    assert!(
        matches!(err, Error::UnknownMeter(ref m) if m == "svc/nope"),
        "{err}"
    );
}

/// Two runs pricing the same new (meter, month) at once: the second to commit
/// gets a clear error, not Postgres's unique-violation text.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_concurrent_set_is_reported_as_such(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    let next = now_month(&db).await.offset(1).unwrap();

    let mut first = db.begin_unpinned().await.unwrap();
    set_version(&mut first, "svc/calls", next, &flat(1))
        .await
        .unwrap();

    let other = db.clone();
    let second = tokio::spawn(async move {
        let mut tx = other.begin_unpinned().await.unwrap();
        // Blocks on the unique index until `first` commits.
        set_version(&mut tx, "svc/calls", next, &flat(2))
            .await
            .map(|_| ())
    });
    // Wait until the second run is actually blocked on `first`'s row lock, so
    // the test exercises the race rather than whichever run happens to start
    // first on a slow machine.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the second run never blocked on the first"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    first.commit().await.unwrap();

    let err = second.await.unwrap().unwrap_err();
    assert!(
        matches!(err, Error::Concurrent { ref meter, month } if meter == "svc/calls" && month == next),
        "{err}"
    );
    assert!(err.to_string().contains("pricebook list"), "{err}");
    assert_eq!(
        in_effect(&db, "svc/calls", &next.to_string()).await,
        Some(1)
    );
}

/// The rater trusts [`Tiers`], so a stored version edited by hand into a shape
/// it refuses must fail loudly when priced, while a listing still shows it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_malformed_stored_version_is_an_error_not_a_price(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    let bad = insert_flat(&pool, "svc/calls", month("2026-01"), 1).await;
    insert_flat(&pool, "svc/bytes", month("2026-01"), 1).await;
    // Bound the only tier: no unbounded last tier any more.
    sqlx::query("UPDATE price_tiers SET up_to = 10 WHERE version_id = $1")
        .bind(bad)
        .execute(&pool)
        .await
        .unwrap();

    let mut tx = db.begin_unpinned().await.unwrap();
    let err = tiers_in_effect(tx.conn(), "svc/calls", month("2026-02"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Corrupt { version, .. } if version == bad),
        "{err}"
    );
    let err = book_in_effect(tx.conn(), month("2026-02"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Corrupt { .. }), "{err}");

    let listed = list_versions(tx.conn()).await.unwrap();
    assert_eq!(listed.len(), 2, "one bad version does not hide the rest");
    let calls = listed.iter().find(|v| v.meter == "svc/calls").unwrap();
    assert!(calls.tiers.as_ref().unwrap_err().contains("unbounded"));
    let bytes = listed.iter().find(|v| v.meter == "svc/bytes").unwrap();
    assert_eq!(bytes.tiers, Ok(flat(1)));
}

/// Billing reads prices inside an org's transaction, as `otto_app`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_tenant_transaction_reads_the_price_book(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    insert_flat(&pool, "svc/calls", month("2026-01"), 42).await;
    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let v = tiers_in_effect(tx.conn(), "svc/calls", month("2026-11"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.tiers, flat(42));
    assert_eq!(
        current_month(tx.conn()).await.unwrap(),
        now_month(&db).await
    );
}
