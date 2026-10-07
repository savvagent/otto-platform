//! Domain claims across orgs: a pending claim never blocks another org, and
//! the first verified claim wins (savvagent/otto-platform#6).

mod common;

use common::{db, tenant};
use otto_core::domains;
use otto_core::error::Error;
use otto_core::idp;
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;
use sqlx::PgPool;

async fn claim(
    db: &Db,
    org: otto_tenant::ids::OrgId,
    domain: &str,
    token: &str,
) -> Result<(), Error> {
    let mut tx = db.begin(org).await.unwrap();
    let res = domains::claim(&mut tx, domain, token).await.map(|_| ());
    if res.is_ok() {
        tx.commit().await.unwrap();
    }
    res
}

async fn verify(db: &Db, org: otto_tenant::ids::OrgId, domain: &str) -> Result<(), Error> {
    let mut tx = db.begin(org).await.unwrap();
    let res = domains::mark_verified(&mut tx, domain).await.map(|_| ());
    if res.is_ok() {
        tx.commit().await.unwrap();
    }
    res
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_pending_claim_does_not_block_another_org(pool: PgPool) {
    let db = db(pool);
    let squatter = tenant(&db, "squatter").await;
    let owner = tenant(&db, "bigcorp").await;

    claim(&db, squatter.org, "bigcorp.com", "squat")
        .await
        .unwrap();
    // The real owner can still claim and verify.
    claim(&db, owner.org, "BigCorp.com", "real").await.unwrap();
    verify(&db, owner.org, "bigcorp.com").await.unwrap();

    // Each org sees only its own claim, with its own token.
    let mut tx = db.begin(owner.org).await.unwrap();
    let mine = domains::list(&mut tx).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].verification_token, "real");
    assert!(mine[0].verified_at.is_some());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_verified_claim_blocks_other_orgs_until_released(pool: PgPool) {
    let db = db(pool);
    let a = tenant(&db, "acme").await;
    let b = tenant(&db, "globex").await;

    claim(&db, a.org, "shared.test", "token-a").await.unwrap();
    claim(&db, b.org, "shared.test", "token-b").await.unwrap();
    verify(&db, a.org, "shared.test").await.unwrap();

    // B can neither verify its pending claim nor make a new one.
    let err = verify(&db, b.org, "shared.test").await.unwrap_err();
    assert!(matches!(err, Error::DomainAlreadyClaimed), "{err:?}");
    let err = claim(&db, b.org, "shared.test", "token-b2")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::DomainAlreadyClaimed), "{err:?}");

    // A can still re-claim its own domain (a "lost the token" recovery).
    claim(&db, a.org, "shared.test", "token-a2").await.unwrap();
    verify(&db, a.org, "shared.test").await.unwrap();

    // Once A releases it, B's pending claim is verifiable.
    let mut tx = db.begin(a.org).await.unwrap();
    domains::delete(&mut tx, "shared.test").await.unwrap();
    tx.commit().await.unwrap();
    verify(&db, b.org, "shared.test").await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_verified_index_settles_a_simultaneous_verification(pool: PgPool) {
    let db = db(pool);
    let a = tenant(&db, "acme").await;
    let b = tenant(&db, "globex").await;
    claim(&db, a.org, "race.test", "token-a").await.unwrap();
    claim(&db, b.org, "race.test", "token-b").await.unwrap();

    // Both pass the up-front check before either commits; the unique index
    // decides at commit/statement time.
    let mut tx_a = db.begin(a.org).await.unwrap();
    domains::mark_verified(&mut tx_a, "race.test")
        .await
        .unwrap();
    tx_a.commit().await.unwrap();

    let mut tx_b = db.begin(b.org).await.unwrap();
    // Bypass mark_verified's up-front check to exercise the index directly.
    let err = sqlx::query(
        "UPDATE claimed_domains SET verified_at = now() WHERE org_id = $1 AND domain = $2",
    )
    .bind(b.org)
    .bind("race.test")
    .execute(tx_b.conn())
    .await
    .unwrap_err();
    let constraint = err.as_database_error().and_then(|e| e.constraint());
    assert_eq!(constraint, Some("claimed_domains_verified_domain_key"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn routing_follows_the_verified_claim_only(pool: PgPool) {
    let db = db(pool);
    let squatter = tenant(&db, "squatter").await;
    let owner = tenant(&db, "bigcorp").await;
    let cipher = Cipher::from_base64_key(&base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [9u8; 32],
    ))
    .unwrap();

    for (org, issuer) in [
        (squatter.org, "https://idp.squat.test"),
        (owner.org, "https://idp.bigcorp.test"),
    ] {
        let mut tx = db.begin(org).await.unwrap();
        idp::upsert_connection(
            &mut tx,
            issuer,
            "client",
            cipher.seal(b"secret").unwrap(),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    claim(&db, squatter.org, "bigcorp.com", "squat")
        .await
        .unwrap();
    assert!(idp::resolve_for_domain(&db, "bigcorp.com")
        .await
        .unwrap()
        .is_none());

    claim(&db, owner.org, "bigcorp.com", "real").await.unwrap();
    verify(&db, owner.org, "bigcorp.com").await.unwrap();
    let (org, conn) = idp::resolve_for_domain(&db, "BIGCORP.com")
        .await
        .unwrap()
        .expect("routes to the verified owner");
    assert_eq!(org, owner.org);
    assert_eq!(conn.issuer, "https://idp.bigcorp.test");
}
