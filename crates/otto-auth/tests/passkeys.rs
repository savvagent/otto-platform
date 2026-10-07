//! Passkey registration ownership checks, driven through a software
//! authenticator that performs the real WebAuthn ceremony (genuine signatures
//! over the challenge this server issued), so the signature-verification step
//! that precedes the ownership check is exercised rather than stubbed.
//!
//! The token is built with `falsify_uv: true` because the server requires user
//! verification and a software token has no biometric to perform. The software
//! token also cannot hold resident keys, so [`for_soft_token`] drops that
//! requirement from the challenge it is handed; the server-side state is
//! unaffected.

use otto_auth::error::AuthError;
use otto_auth::passkeys::{self, RegistrationVia};
use otto_core::orgs::OrgsExt;
use otto_tenant::audit::action;
use otto_tenant::ids::UserId;
use otto_tenant::Db;
use sqlx::PgPool;
use webauthn_authenticator_rs::softtoken::SoftToken;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential, Url};

const RP_ID: &str = "platform.otto.test";
const ORIGIN: &str = "https://platform.otto.test";

fn rp() -> passkeys::Webauthn {
    passkeys::relying_party(RP_ID, ORIGIN).unwrap()
}

fn authenticator() -> WebauthnAuthenticator<SoftToken> {
    WebauthnAuthenticator::new(SoftToken::new(true).unwrap().0)
}

fn for_soft_token(mut challenge: CreationChallengeResponse) -> CreationChallengeResponse {
    if let Some(sel) = challenge.public_key.authenticator_selection.as_mut() {
        sel.require_resident_key = false;
        sel.resident_key = None;
    }
    challenge
}

/// Start a ceremony for `owner` and sign it, returning the ceremony id and the
/// signed credential.
async fn signed_ceremony(db: &Db, owner: UserId) -> (uuid::Uuid, RegisterPublicKeyCredential) {
    let ceremony = passkeys::start_registration(db, &rp(), Some(owner))
        .await
        .unwrap();
    let credential = authenticator()
        .do_registration(
            Url::parse(ORIGIN).unwrap(),
            for_soft_token(ceremony.challenge),
        )
        .expect("the authenticator refused the registration challenge");
    (ceremony.id, credential)
}

async fn count(db: &Db, sql: &str, bind: Option<&str>) -> i64 {
    let q = sqlx::query_scalar(sql);
    let q = match bind {
        Some(b) => q.bind(b.to_string()),
        None => q,
    };
    q.fetch_one(db.pool()).await.unwrap()
}

/// A ceremony whose account matches `expected` registers normally.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_matching_expected_account_registers(pool: PgPool) {
    let db = Db::from_pool(pool);
    let owner = db.create_unclaimed_user().await.unwrap().id;
    let (ceremony, credential) = signed_ceremony(&db, owner).await;

    let user = passkeys::finish_registration(
        &db,
        &rp(),
        ceremony,
        &credential,
        Some("laptop"),
        RegistrationVia::Add,
        Some(owner),
        None,
    )
    .await
    .unwrap();

    assert_eq!(user, owner);
    assert_eq!(count(&db, "SELECT count(*) FROM passkeys", None).await, 1);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM audit_events WHERE action = $1",
            Some(action::PASSKEY_REGISTRATION_REFUSED)
        )
        .await,
        0
    );
}

/// `expected: None` skips the check entirely (the signup flow has no
/// independent identity to compare against).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn no_expected_account_skips_the_check(pool: PgPool) {
    let db = Db::from_pool(pool);
    let owner = db.create_unclaimed_user().await.unwrap().id;
    let (ceremony, credential) = signed_ceremony(&db, owner).await;

    let user = passkeys::finish_registration(
        &db,
        &rp(),
        ceremony,
        &credential,
        None,
        RegistrationVia::Signup,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(user, owner);
}

/// A mismatch must leave no credential and no success row, must leave the
/// ceremony intact for its real owner, and must leave a refusal row written
/// on a connection independent of the rolled-back transaction.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_ceremony_account_mismatch_writes_a_refusal_but_no_credential(pool: PgPool) {
    let db = Db::from_pool(pool);

    // The ceremony belongs to `owner`, but the caller claims to be `other`.
    let owner = db.create_unclaimed_user().await.unwrap().id;
    let other = db.create_unclaimed_user().await.unwrap().id;
    let (ceremony, credential) = signed_ceremony(&db, owner).await;

    let result = passkeys::finish_registration(
        &db,
        &rp(),
        ceremony,
        &credential,
        Some("laptop"),
        RegistrationVia::Add,
        Some(other),
        Some("203.0.113.7"),
    )
    .await;

    let err = result.expect_err("a mismatched ceremony must be refused");
    match &err {
        AuthError::CeremonyAccountMismatch {
            ceremony_account,
            caller_account,
        } => {
            assert_eq!(*ceremony_account, owner, "the ceremony's real account");
            assert_eq!(*caller_account, other, "who the caller expected to be");
        }
        unexpected => panic!("expected a CeremonyAccountMismatch, got {unexpected:?}"),
    }
    assert_eq!(err.status(), 403);
    assert_eq!(err.public(), "that ceremony belongs to a different account");

    assert_eq!(
        count(&db, "SELECT count(*) FROM passkeys", None).await,
        0,
        "a ceremony/caller mismatch must not leave a credential behind"
    );
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM audit_events WHERE action = $1",
            Some(action::PASSKEY_REGISTERED)
        )
        .await,
        0,
        "a rejected request must not leave a row asserting it succeeded"
    );

    // The rollback restores the ceremony's own consumption.
    let survives: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE id = $1)")
            .bind(ceremony)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(survives, "a mismatch must not burn the owner's ceremony");

    let (actor, detail): (UserId, serde_json::Value) =
        sqlx::query_as("SELECT actor_user_id, detail FROM audit_events WHERE action = $1")
            .bind(action::PASSKEY_REGISTRATION_REFUSED)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(actor, owner, "attributed to the ceremony's verified owner");
    assert_eq!(detail["attemptedBy"], serde_json::json!(other.to_string()));

    // The real owner can still finish the surviving ceremony.
    let user = passkeys::finish_registration(
        &db,
        &rp(),
        ceremony,
        &credential,
        Some("laptop"),
        RegistrationVia::Add,
        Some(owner),
        None,
    )
    .await
    .unwrap();
    assert_eq!(user, owner);
}
