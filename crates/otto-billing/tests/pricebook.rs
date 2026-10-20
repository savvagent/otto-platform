//! `pricebook`: versions by effective month, written unpinned, read anywhere.
//!
//! Prices here are fixtures, not rates anyone is charged.

use chrono::{DateTime, Utc};
use otto_billing::pricebook::{
    book_in_effect, list_versions, rate, set_version, tiers_in_effect, Error, LineAmount, Month,
    Tier, Tiers,
};
use otto_tenant::{Db, OrgId};
use sqlx::PgPool;

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

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

/// A flat price of `ucents` per unit.
fn flat(ucents: i64) -> Tiers {
    Tiers::new(vec![Tier {
        up_to: None,
        unit_amount_ucents: ucents,
    }])
    .unwrap()
}

async fn set(db: &Db, meter: &str, m: &str, tiers: &Tiers, now: &str) -> Result<(), Error> {
    let mut tx = db.begin_unpinned().await.unwrap();
    set_version(&mut tx, meter, month(m), tiers, at(now)).await?;
    tx.commit().await.unwrap();
    Ok(())
}

async fn in_effect(db: &Db, meter: &str, m: &str) -> Option<i64> {
    let mut tx = db.begin_unpinned().await.unwrap();
    let v = tiers_in_effect(tx.conn(), meter, month(m)).await.unwrap();
    v.map(|v| v.tiers.as_slice()[0].unit_amount_ucents)
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_latest_version_not_after_the_month_is_in_effect(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    let now = "2026-01-15T12:00:00Z";
    set(&db, "svc/calls", "2026-01", &flat(100), now)
        .await
        .unwrap();
    set(&db, "svc/calls", "2026-04", &flat(200), now)
        .await
        .unwrap();
    set(&db, "svc/calls", "2026-07", &flat(300), now)
        .await
        .unwrap();

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
    assert_eq!(book[0].meter.display_name, "Calls");
    assert_eq!(book[0].version.effective_month, month("2026-04"));
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
    set(&db, "svc/calls", "2026-11", &tiers, "2026-10-20T00:00:00Z")
        .await
        .unwrap();

    let mut tx = db.begin_unpinned().await.unwrap();
    let v = tiers_in_effect(tx.conn(), "svc/calls", month("2026-11"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.tiers, tiers);
    assert_eq!(v.meter, "svc/calls");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn past_and_in_effect_prices_never_change(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    let now = "2026-10-20T00:00:00Z";

    // A past month, whether or not it had a price, is refused.
    let err = set(&db, "svc/calls", "2026-09", &flat(1), now)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::PastMonth { .. }), "{err}");

    // The current month may be priced once ...
    set(&db, "svc/calls", "2026-10", &flat(1), now)
        .await
        .unwrap();
    // ... but not repriced: this month is being billed at that price.
    let err = set(&db, "svc/calls", "2026-10", &flat(2), now)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InEffect { .. }), "{err}");
    assert_eq!(in_effect(&db, "svc/calls", "2026-10").await, Some(1));

    // A future month is replaced, under a new id.
    let mut tx = db.begin_unpinned().await.unwrap();
    let first = set_version(&mut tx, "svc/calls", month("2026-12"), &flat(5), at(now))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(first.replaced, None);
    let mut tx = db.begin_unpinned().await.unwrap();
    let second = set_version(&mut tx, "svc/calls", month("2026-12"), &flat(6), at(now))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(second.replaced, Some(first.version.id));
    assert_ne!(second.version.id, first.version.id);
    assert_eq!(in_effect(&db, "svc/calls", "2026-12").await, Some(6));

    // Once that month arrives, it is in effect and fixed.
    let err = set(
        &db,
        "svc/calls",
        "2026-12",
        &flat(7),
        "2026-12-01T00:00:00Z",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::InEffect { .. }), "{err}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unknown_meter_cannot_be_priced(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    let err = set(&db, "svc/nope", "2026-11", &flat(1), "2026-10-20T00:00:00Z")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::UnknownMeter(ref m) if m == "svc/nope"),
        "{err}"
    );
}

/// The rater trusts [`Tiers`], so a stored version edited by hand into a shape
/// it refuses must fail loudly on read rather than misprice.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_malformed_stored_version_is_an_error_not_a_price(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool.clone());
    set(
        &db,
        "svc/calls",
        "2026-11",
        &flat(1),
        "2026-10-20T00:00:00Z",
    )
    .await
    .unwrap();
    // Bound the only tier: no unbounded last tier any more.
    sqlx::query("UPDATE price_tiers SET up_to = 10")
        .execute(&pool)
        .await
        .unwrap();

    let mut tx = db.begin_unpinned().await.unwrap();
    let err = tiers_in_effect(tx.conn(), "svc/calls", month("2026-11"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Corrupt { .. }), "{err}");
}

/// Billing reads prices inside an org's transaction, as `otto_app`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_tenant_transaction_reads_the_price_book(pool: PgPool) {
    seed_meters(&pool).await;
    let db = Db::from_pool(pool);
    set(
        &db,
        "svc/calls",
        "2026-11",
        &flat(42),
        "2026-10-20T00:00:00Z",
    )
    .await
    .unwrap();
    let mut tx = db.begin(OrgId::new()).await.unwrap();
    let v = tiers_in_effect(tx.conn(), "svc/calls", month("2026-11"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.tiers, flat(42));
}
