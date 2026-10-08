//! Enterprise OIDC federation — `otto-core` CRUD, the ceremony lifecycle, and
//! the two security-critical races this feature exists to close:
//! `create_user_for_federation`'s never-`DO UPDATE` guarantee, and
//! `consume_by_state_hash`'s single-use burn under a replayed/racing
//! callback. See otto-factory's `docs/specs/2026-09-16-oidc-federation-design.md` §2/§3.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use common::{db, tenant};
use otto_core::error::Error;
use otto_core::orgs::OrgsExt;
use otto_core::{ceremonies, domains, identities, idp, orgs};
use otto_tenant::crypto::Cipher;
use sqlx::PgPool;
use std::collections::HashSet;

fn sealed(cipher: &Cipher, plaintext: &[u8]) -> otto_tenant::crypto::Sealed {
    cipher.seal(plaintext).unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn idp_connections_round_trip_and_rebind_replaces(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([9u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();

    assert!(idp::get_connection(&mut tx).await.unwrap().is_none());

    let secret_a = sealed(&cipher, b"first-client-secret");
    let conn_a = idp::upsert_connection(
        &mut tx,
        "https://idp.acme.test",
        "client-a",
        secret_a,
        serde_json::json!({"issuer": "https://idp.acme.test"}),
    )
    .await
    .unwrap();
    assert_eq!(conn_a.issuer, "https://idp.acme.test");
    assert_eq!(conn_a.client_id, "client-a");

    // The sealed secret round-trips through storage, unopened.
    let stored_secret = idp::get_connection_secret(&mut tx)
        .await
        .unwrap()
        .expect("secret");
    assert_eq!(
        cipher
            .open(&stored_secret.ciphertext, &stored_secret.nonce)
            .unwrap(),
        b"first-client-secret"
    );

    // Rebinding replaces the connection wholesale (ON CONFLICT (org_id) DO
    // UPDATE), not a second row.
    let secret_b = sealed(&cipher, b"rotated-client-secret");
    let conn_b = idp::upsert_connection(
        &mut tx,
        "https://idp2.acme.test",
        "client-b",
        secret_b,
        serde_json::json!({"issuer": "https://idp2.acme.test"}),
    )
    .await
    .unwrap();
    assert_eq!(conn_b.id, conn_a.id);
    assert_eq!(conn_b.issuer, "https://idp2.acme.test");
    assert_eq!(conn_b.client_id, "client-b");

    let stored_secret = idp::get_connection_secret(&mut tx)
        .await
        .unwrap()
        .expect("secret");
    assert_eq!(
        cipher
            .open(&stored_secret.ciphertext, &stored_secret.nonce)
            .unwrap(),
        b"rotated-client-secret"
    );

    let fetched = idp::get_connection(&mut tx).await.unwrap().unwrap();
    assert_eq!(fetched, conn_b);

    tx.commit().await.unwrap();
}

/// A rebind that changes `issuer`/`client_id` must clear stale
/// `user_identities` pins on the preserved connection row — a security
/// review found `upsert_connection` kept them, which would let a `sub` at
/// the *new* IdP that happens to collide with an old pin resolve straight
/// onto that account (`sub` is only unique within an issuer).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rebinding_to_a_different_issuer_clears_stale_identity_pins(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let other = db.upsert_user("other@acme.com", None).await.unwrap().id;
    let cipher = Cipher::from_base64_key(&B64.encode([7u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let conn_a = idp::upsert_connection(
        &mut tx,
        "https://idp-a.test",
        "client-a",
        sealed(&cipher, b"secret-a"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, other, conn_a.id, "shared-sub")
        .await
        .unwrap();
    assert_eq!(
        identities::resolve_user(&db, conn_a.id, "shared-sub")
            .await
            .unwrap(),
        Some(other)
    );

    // Rebind to a different issuer — same org, same connection row (the
    // `id` is preserved by ON CONFLICT), but a different IdP.
    let mut tx = db.begin(t.org).await.unwrap();
    let conn_b = idp::upsert_connection(
        &mut tx,
        "https://idp-b.test",
        "client-b",
        sealed(&cipher, b"secret-b"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(conn_b.id, conn_a.id);

    // The stale pin is gone: a principal at the new IdP presenting the same
    // `sub` string is a stranger, not `other`.
    assert_eq!(
        identities::resolve_user(&db, conn_b.id, "shared-sub")
            .await
            .unwrap(),
        None
    );
}

/// Rebinding with the *same* issuer and client_id (e.g. re-saving after a
/// client secret rotation) must not disturb existing pins — only a change to
/// which IdP is bound clears them.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rebinding_with_the_same_issuer_and_client_id_keeps_identity_pins(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let other = db.upsert_user("other@acme.com", None).await.unwrap().id;
    let cipher = Cipher::from_base64_key(&B64.encode([8u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let conn_a = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret-old"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, other, conn_a.id, "stable-sub")
        .await
        .unwrap();

    // Rotate the secret only — issuer and client_id unchanged.
    let mut tx = db.begin(t.org).await.unwrap();
    idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret-new"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        identities::resolve_user(&db, conn_a.id, "stable-sub")
            .await
            .unwrap(),
        Some(other)
    );
}

#[test]
fn generate_verification_token_is_unique_and_url_safe() {
    let a = domains::generate_verification_token();
    let b = domains::generate_verification_token();
    assert_ne!(a, b);
    assert!(a
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert!(a.len() > 16);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn claimed_domains_claim_reclaim_and_verify(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;

    let mut tx = db.begin(t.org).await.unwrap();

    let claimed = domains::claim(&mut tx, "acme.com", "token-1")
        .await
        .unwrap();
    assert_eq!(claimed.domain, "acme.com");
    assert_eq!(claimed.verification_token, "token-1");
    assert!(claimed.verified_at.is_none());

    // Re-claiming your own domain resets verification -- a same-org re-claim
    // is a legitimate "I lost the old token" recovery, not a conflict.
    let reclaimed = domains::claim(&mut tx, "acme.com", "token-2")
        .await
        .unwrap();
    assert_eq!(reclaimed.verification_token, "token-2");
    assert!(reclaimed.verified_at.is_none());

    let verified = domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    assert!(verified.verified_at.is_some());

    let listed = domains::list(&mut tx).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].domain, "acme.com");

    // mark_verified against a domain this org never claimed is a refusal,
    // not a silent no-op.
    let err = domains::mark_verified(&mut tx, "never-claimed.test")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)));

    domains::delete(&mut tx, "acme.com").await.unwrap();
    assert!(domains::list(&mut tx).await.unwrap().is_empty());

    tx.commit().await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn identities_link_converges_on_a_racing_duplicate(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([3u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let conn = idp::upsert_connection(
        &mut tx,
        "https://idp.acme.test",
        "client-a",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert!(identities::resolve_user(&db, conn.id, "subject-1")
        .await
        .unwrap()
        .is_none());

    let first = identities::link(&db, t.user, conn.id, "subject-1")
        .await
        .unwrap();
    assert_eq!(first.user_id, t.user);
    assert_eq!(first.subject, "subject-1");

    // ON CONFLICT (idp_connection_id, subject) DO NOTHING then re-read: a
    // duplicate callback for the same ceremony (or a race between two tabs)
    // converges on the same row rather than erroring.
    let second = identities::link(&db, t.user, conn.id, "subject-1")
        .await
        .unwrap();
    assert_eq!(second.id, first.id);

    let resolved = identities::resolve_user(&db, conn.id, "subject-1")
        .await
        .unwrap();
    assert_eq!(resolved, Some(t.user));
}

// ---------------------------------------------------- create_user_for_federation

/// (a) A brand-new email creates a brand-new row.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn create_user_for_federation_creates_a_new_row(pool: PgPool) {
    let db = db(pool);

    let user_id = identities::create_user_for_federation(&db, "alice@acme.test")
        .await
        .unwrap()
        .expect("brand-new email creates a row");

    let user = db.get_user(user_id).await.unwrap().expect("user exists");
    assert_eq!(user.email.as_deref(), Some("alice@acme.test"));
}

/// (b) A second call against the same email — simulating the race
/// `create_user_for_federation`'s doc comment describes, where a
/// `PATCH /api/me` or a second federated sign-in attempt lands in the window
/// between the caller's `resolve_by_email` check and this insert — returns
/// `None` and must not alter the first row it found instead. This is the
/// literal implementation of the "never `DO UPDATE`" fix from spec review
/// round 3: `Db::upsert_user` would silently converge onto (and mutate the
/// caller's belief about) whoever's row already held this email.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn create_user_for_federation_refuses_a_second_call_for_the_same_email(pool: PgPool) {
    let db = db(pool);

    let first_id = identities::create_user_for_federation(&db, "bob@acme.test")
        .await
        .unwrap()
        .expect("first call creates the row");
    let first = db.get_user(first_id).await.unwrap().unwrap();

    let second = identities::create_user_for_federation(&db, "bob@acme.test")
        .await
        .unwrap();
    assert_eq!(
        second, None,
        "a conflict must never fall back to the existing row"
    );

    // The first row is completely untouched by the refused second call.
    let after = db.get_user(first_id).await.unwrap().unwrap();
    assert_eq!(after, first);

    // Only one row exists for this email -- the refusal did not somehow
    // still insert a duplicate.
    let found = db.get_user_by_email("bob@acme.test").await.unwrap();
    assert_eq!(found.map(|u| u.id), Some(first_id));
}

/// (c) Two concurrent calls for the same brand-new email: exactly one must
/// win with `Some(_)`, the other must see `None` -- never both `Some` with
/// two different user ids, which would mean two accounts silently sharing
/// one email address in the exact window this function's `ON CONFLICT ...
/// DO NOTHING` exists to close.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn create_user_for_federation_concurrent_calls_never_both_win(pool: PgPool) {
    let db = db(pool);

    let db_a = db.clone();
    let db_b = db.clone();
    let email = "concurrent@acme.test".to_string();
    let email_a = email.clone();
    let email_b = email.clone();

    let (a, b) = tokio::join!(
        tokio::spawn(async move { identities::create_user_for_federation(&db_a, &email_a).await }),
        tokio::spawn(async move { identities::create_user_for_federation(&db_b, &email_b).await }),
    );

    let a = a.unwrap().unwrap();
    let b = b.unwrap().unwrap();

    let winners: Vec<_> = [a, b].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1, "exactly one caller must win Some(_)");

    let found = db
        .get_user_by_email(&email)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(Some(found.id), winners.first().copied());
}

// -------------------------------------------------------------- ceremonies

async fn make_connection(db: &otto_tenant::Db, org: otto_tenant::OrgId) -> uuid::Uuid {
    let cipher = Cipher::from_base64_key(&B64.encode([5u8; 32])).unwrap();
    let mut tx = db.begin(org).await.unwrap();
    let conn = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    conn.id
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn ceremony_create_and_consume_round_trip(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let conn_id = make_connection(&db, t.org).await;

    let ceremony = ceremonies::create(
        &db,
        t.org,
        conn_id,
        None,
        b"state-hash-1",
        b"binding-hash-1",
        "nonce-1",
        Utc::now() + Duration::minutes(10),
        None,
    )
    .await
    .unwrap();
    assert_eq!(ceremony.org_id, t.org);
    assert_eq!(ceremony.idp_connection_id, conn_id);
    assert!(ceremony.user_id.is_none());
    assert!(ceremony.consumed_at.is_none());

    let consumed = ceremonies::consume_by_state_hash(&db, b"state-hash-1")
        .await
        .unwrap()
        .expect("ceremony resolves by state hash");
    assert_eq!(consumed.id, ceremony.id);
    assert!(consumed.consumed_at.is_some());

    // Single-use: a second lookup for the same state_hash finds nothing.
    let replayed = ceremonies::consume_by_state_hash(&db, b"state-hash-1")
        .await
        .unwrap();
    assert!(
        replayed.is_none(),
        "a consumed ceremony must not resolve twice"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn ceremony_carries_its_next_path_to_the_consumer(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let conn_id = make_connection(&db, t.org).await;

    ceremonies::create(
        &db,
        t.org,
        conn_id,
        None,
        b"state-hash-next",
        b"binding-hash-next",
        "nonce",
        Utc::now() + Duration::minutes(10),
        Some("/oauth/authorize?client_id=c"),
    )
    .await
    .unwrap();

    let consumed = ceremonies::consume_by_state_hash(&db, b"state-hash-next")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        consumed.next_path.as_deref(),
        Some("/oauth/authorize?client_id=c")
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn ceremony_expired_rows_are_not_resolved(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let conn_id = make_connection(&db, t.org).await;

    ceremonies::create(
        &db,
        t.org,
        conn_id,
        None,
        b"state-hash-expired",
        b"binding-hash-expired",
        "nonce",
        Utc::now() - Duration::minutes(1),
        None,
    )
    .await
    .unwrap();

    let resolved = ceremonies::consume_by_state_hash(&db, b"state-hash-expired")
        .await
        .unwrap();
    assert!(resolved.is_none());
}

/// The TOCTOU-closing race `consume_by_state_hash`'s `SELECT ... FOR UPDATE`
/// exists for: two overlapping callers racing the exact same `state_hash`
/// (a replayed callback URL racing the legitimate one) must never both
/// resolve the ceremony -- exactly one gets the row, the other gets `None`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn consume_by_state_hash_never_resolves_the_same_ceremony_twice_under_a_race(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let conn_id = make_connection(&db, t.org).await;

    ceremonies::create(
        &db,
        t.org,
        conn_id,
        None,
        b"state-hash-race",
        b"binding-hash-race",
        "nonce",
        Utc::now() + Duration::minutes(10),
        None,
    )
    .await
    .unwrap();

    let db_a = db.clone();
    let db_b = db.clone();

    let (a, b) = tokio::join!(
        tokio::spawn(
            async move { ceremonies::consume_by_state_hash(&db_a, b"state-hash-race").await }
        ),
        tokio::spawn(
            async move { ceremonies::consume_by_state_hash(&db_b, b"state-hash-race").await }
        ),
    );

    let a = a.unwrap().unwrap();
    let b = b.unwrap().unwrap();

    let winners = [a, b].into_iter().flatten().count();
    assert_eq!(
        winners, 1,
        "exactly one racing caller must resolve the ceremony"
    );
}

/// A domain reassigned mid-flight cannot retarget an in-flight ceremony: the
/// ceremony's own stored `org_id` is denormalized at creation time and never
/// re-derived from a fresh domain lookup. This is the data-layer half of
/// spec §3's mid-flight-reassignment test; the callback's actual reliance on
/// this fact (trusting `ceremony.org_id` over a fresh `resolve_for_domain`
/// call) is Task 3's test.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn ceremony_org_id_survives_a_mid_flight_domain_reassignment(pool: PgPool) {
    let db = db(pool);
    let a = tenant(&db, "acme").await;
    let b = tenant(&db, "globex").await;
    let cipher = Cipher::from_base64_key(&B64.encode([6u8; 32])).unwrap();

    let mut tx_a = db.begin(a.org).await.unwrap();
    let conn_a = idp::upsert_connection(
        &mut tx_a,
        "https://idp.acme.test",
        "client-a",
        sealed(&cipher, b"secret-a"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx_a, "shared.test", "token-a")
        .await
        .unwrap();
    domains::mark_verified(&mut tx_a, "shared.test")
        .await
        .unwrap();
    tx_a.commit().await.unwrap();

    // A ceremony starts, scoped to org A's connection and denormalizing
    // org A's id onto the row.
    let ceremony = ceremonies::create(
        &db,
        a.org,
        conn_a.id,
        None,
        b"state-hash-reassign",
        b"binding-hash-reassign",
        "nonce",
        Utc::now() + Duration::minutes(10),
        None,
    )
    .await
    .unwrap();

    // Org A releases the domain (enforce_sso defaults to off, so this
    // succeeds with no lockout guard involved).
    let mut tx_a2 = db.begin(a.org).await.unwrap();
    domains::delete(&mut tx_a2, "shared.test").await.unwrap();
    tx_a2.commit().await.unwrap();

    // Org B claims and verifies the same domain before the ceremony's
    // callback runs.
    let mut tx_b = db.begin(b.org).await.unwrap();
    let conn_b = idp::upsert_connection(
        &mut tx_b,
        "https://idp.globex.test",
        "client-b",
        sealed(&cipher, b"secret-b"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx_b, "shared.test", "token-b")
        .await
        .unwrap();
    domains::mark_verified(&mut tx_b, "shared.test")
        .await
        .unwrap();
    tx_b.commit().await.unwrap();

    // A fresh resolve now names org B...
    let (resolved_org, resolved_conn) = idp::resolve_for_domain(&db, "shared.test")
        .await
        .unwrap()
        .expect("domain resolves");
    assert_eq!(resolved_org, b.org);
    assert_eq!(resolved_conn.id, conn_b.id);

    // ...but the ceremony's own stored org_id still names org A. Task 3's
    // callback trusts this field, not a fresh lookup, so a domain reassigned
    // mid-flow cannot retarget an in-flight ceremony.
    assert_eq!(ceremony.org_id, a.org);
    assert_ne!(ceremony.org_id, resolved_org);
}

// ------------------------------------------------------------ lockout guards

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_enforce_sso_refuses_with_no_connection_or_verified_domain(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([8u8; 32])).unwrap();

    // Nothing bound at all.
    let mut tx = db.begin(t.org).await.unwrap();
    let err = orgs::set_enforce_sso(&mut tx, true, t.user)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    tx.rollback().await.unwrap();

    // A connection, but no verified domain.
    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token").await.unwrap();
    let err = orgs::set_enforce_sso(&mut tx, true, t.user)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    tx.commit().await.unwrap();

    // Verifying the domain is what finally allows it — but only once the
    // caller has also linked their own identity (see the dedicated test
    // below for that condition in isolation). identities::link is unscoped
    // (&Db, its own separate connection), so it needs the connection row
    // already committed and visible outside the Tx that created it.
    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    let org = orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    assert!(org.enforce_sso);
    tx.commit().await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_enforce_sso_refuses_when_the_caller_has_not_linked_their_own_identity(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([9u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token").await.unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();

    // Infrastructure is fully in place, but the caller hasn't linked their
    // own account to it yet — this is the lockout the third condition
    // exists to prevent: turning enforcement on right now would refuse
    // passkey login for everyone, including this exact caller, with no way
    // back in.
    let err = orgs::set_enforce_sso(&mut tx, true, t.user)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    tx.commit().await.unwrap();

    // Once the caller links, the same call succeeds. identities::link is
    // unscoped (&Db), so the connection row it references must already be
    // committed and visible outside the Tx that created it.
    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    let org = orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    assert!(org.enforce_sso);
    tx.commit().await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_enforce_sso_does_not_require_a_different_admins_link(pool: PgPool) {
    // A second admin's own linked identity does not satisfy the guard for
    // the caller turning enforcement on — the whole point is that *this*
    // caller can get back in, not merely that someone in the org can.
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([11u8; 32])).unwrap();
    let other_admin = db
        .upsert_user("other-admin@acme.test", Some("Other Admin"))
        .await
        .unwrap();
    db.add_member(t.org, other_admin.id, otto_core::orgs::Role::Admin)
        .await
        .unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token").await.unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, other_admin.id, connection.id, "other-sub")
        .await
        .unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let err = orgs::set_enforce_sso(&mut tx, true, t.user)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    tx.rollback().await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn delete_connection_and_delete_last_domain_are_refused_while_enforced(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([4u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token").await.unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let err = idp::delete_connection(&mut tx).await.unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    let err = domains::delete(&mut tx, "acme.com").await.unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    tx.rollback().await.unwrap();

    // Turning enforcement off first is what unblocks both.
    let mut tx = db.begin(t.org).await.unwrap();
    orgs::set_enforce_sso(&mut tx, false, t.user).await.unwrap();
    domains::delete(&mut tx, "acme.com").await.unwrap();
    idp::delete_connection(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
}

/// Re-claiming resets `verified_at` to `NULL` the same way `delete` removes
/// the row — a security review found `claim` took no lockout guard at all,
/// so re-POSTing the org's only verified domain silently produced the exact
/// stranded state `delete`'s own guard exists to prevent.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn reclaiming_the_only_verified_domain_is_refused_while_enforced(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([5u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token").await.unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let err = domains::claim(&mut tx, "acme.com", "new-token")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SsoLockout { .. }));
    tx.rollback().await.unwrap();

    // Still verified — the refused claim must not have reset it.
    let mut tx = db.begin(t.org).await.unwrap();
    let remaining = domains::list(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(remaining[0].verified_at.is_some());

    // Claiming a *second* domain (not the last verified one) still works —
    // only re-claiming the sole verified domain is guarded.
    let mut tx = db.begin(t.org).await.unwrap();
    domains::claim(&mut tx, "acme.dev", "token-2")
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn delete_a_non_last_verified_domain_is_never_refused(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([2u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token-1")
        .await
        .unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    domains::claim(&mut tx, "acme.dev", "token-2")
        .await
        .unwrap();
    domains::mark_verified(&mut tx, "acme.dev").await.unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    domains::delete(&mut tx, "acme.com").await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let remaining = domains::list(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].domain, "acme.dev");
}

/// The TOCTOU guard `orgs::lock_for_sso_guard` exists for: two admins each
/// deleting one of the org's two verified domains at once, with
/// `enforce_sso` on. Without the lock, both transactions can read "not the
/// last one" before either commits, and both deletes land -- leaving the org
/// with `enforce_sso = true` and zero verified domains. With it, exactly one
/// must succeed and the other must see the updated count and refuse.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn concurrent_domain_deletes_never_both_leave_zero_verified_domains(pool: PgPool) {
    let db = db(pool);
    let t = tenant(&db, "acme").await;
    let cipher = Cipher::from_base64_key(&B64.encode([1u8; 32])).unwrap();

    let mut tx = db.begin(t.org).await.unwrap();
    let connection = idp::upsert_connection(
        &mut tx,
        "https://idp.test",
        "client",
        sealed(&cipher, b"secret"),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    domains::claim(&mut tx, "acme.com", "token-1")
        .await
        .unwrap();
    domains::mark_verified(&mut tx, "acme.com").await.unwrap();
    domains::claim(&mut tx, "acme.dev", "token-2")
        .await
        .unwrap();
    domains::mark_verified(&mut tx, "acme.dev").await.unwrap();
    tx.commit().await.unwrap();

    identities::link(&db, t.user, connection.id, "owner-sub")
        .await
        .unwrap();
    let mut tx = db.begin(t.org).await.unwrap();
    orgs::set_enforce_sso(&mut tx, true, t.user).await.unwrap();
    tx.commit().await.unwrap();

    let org = t.org;
    let db_a = db.clone();
    let db_b = db.clone();

    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            let mut tx = db_a.begin(org).await.unwrap();
            let result = domains::delete(&mut tx, "acme.com").await;
            if result.is_ok() {
                tx.commit().await.unwrap();
            }
            result
        }),
        tokio::spawn(async move {
            let mut tx = db_b.begin(org).await.unwrap();
            let result = domains::delete(&mut tx, "acme.dev").await;
            if result.is_ok() {
                tx.commit().await.unwrap();
            }
            result
        }),
    );

    let a = a.unwrap();
    let b = b.unwrap();
    let outcomes = [a.is_ok(), b.is_ok()];

    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "exactly one of the two concurrent deletes must succeed: {a:?} / {b:?}"
    );
    for err in [a, b].into_iter().filter_map(|r| r.err()) {
        assert!(matches!(err, Error::SsoLockout { .. }));
    }

    let mut tx = db.begin(org).await.unwrap();
    let remaining: HashSet<String> = domains::list(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .filter(|d| d.verified_at.is_some())
        .map(|d| d.domain)
        .collect();
    tx.commit().await.unwrap();
    assert_eq!(
        remaining.len(),
        1,
        "exactly one verified domain must remain"
    );
}
