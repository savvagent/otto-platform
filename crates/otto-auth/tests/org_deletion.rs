//! A deleted org gains no new credentials and no new members: outstanding
//! authorization codes and invites die with it, and the paths that would mint
//! more refuse.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_auth::oauth::{self, AuthorizeRequest, RegistrationRequest};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens;
use otto_core::error::Error as CoreError;
use otto_core::invites::InvitesExt;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const RS: &str = "https://otto-factory.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:4545/callback";
const VERIFIER: &str = "a-pkce-code-verifier-that-is-at-least-forty-three-chars-long";

async fn setup(db: &Db) -> (OrgId, UserId, String) {
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: RS,
            name: "factory",
            scopes: &["jobs:read"],
            default_scopes: &["jobs:read"],
        },
    )
    .await
    .unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = db.upsert_user("dev@acme.example", None).await.unwrap();
    db.add_member(org.id, user.id, Role::Owner).await.unwrap();
    let client = oauth::register_client(
        db,
        RegistrationRequest {
            client_name: Some("agent".into()),
            redirect_uris: vec![REDIRECT.into()],
            software_id: None,
            grant_types: None,
        },
    )
    .await
    .unwrap()
    .client_id;
    (org.id, user.id, client)
}

fn request(client_id: &str) -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: client_id.into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        code_challenge_method: "S256".into(),
        scopes: vec![],
        resource: RS.into(),
        state: None,
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_outstanding_authorization_code_cannot_be_redeemed_after_deletion(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (org, user, client) = setup(&db).await;
    let code = oauth::issue_authorization_code(&db, &request(&client), user, org)
        .await
        .unwrap();

    db.delete_org(org).await.unwrap();

    let err = oauth::redeem_code(&db, &code, &client, REDIRECT, VERIFIER, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, otto_auth::AuthError::InvalidGrant(_)),
        "{err:?}"
    );
    let tokens_issued: i64 = sqlx::query_scalar("SELECT count(*) FROM access_tokens")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(tokens_issued, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_guard_alone_stops_redemption(pool: PgPool) {
    // As above, but undoing delete_org's own consumption of the code, so it is
    // the `deleted_at` predicate in redeem_code that refuses.
    let db = Db::from_pool(pool);
    let (org, user, client) = setup(&db).await;
    let code = oauth::issue_authorization_code(&db, &request(&client), user, org)
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET deleted_at = now()")
        .execute(db.pool())
        .await
        .unwrap();

    assert!(
        oauth::redeem_code(&db, &code, &client, REDIRECT, VERIFIER, None)
            .await
            .is_err()
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_deleted_org_cannot_mint_a_pat(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (org, user, _) = setup(&db).await;
    tokens::mint_pat(&db, user, org, "ok", &[], RS, None)
        .await
        .unwrap();

    db.delete_org(org).await.unwrap();
    assert!(tokens::mint_pat(&db, user, org, "late", &[], RS, None)
        .await
        .is_err());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn pending_invites_are_deleted_and_acceptance_is_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (org, owner, _) = setup(&db).await;
    let newcomer = db.upsert_user("new@acme.example", None).await.unwrap();

    let (kept, accepted) = (vec![1u8; 32], vec![2u8; 32]);
    let mut tx = db.begin(org).await.unwrap();
    tx.create_invite("new@acme.example", Role::Member, Some(owner), &kept)
        .await
        .unwrap();
    tx.create_invite("other@acme.example", Role::Member, Some(owner), &accepted)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    db.delete_org(org).await.unwrap();

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM org_invites")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(left, 0, "pending invites survive org deletion");

    // And with the rows back (deleted_at alone), acceptance still refuses.
    sqlx::query("UPDATE orgs SET deleted_at = NULL")
        .execute(db.pool())
        .await
        .unwrap();
    let mut tx = db.begin(org).await.unwrap();
    tx.create_invite("new@acme.example", Role::Member, Some(owner), &kept)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE orgs SET deleted_at = now()")
        .execute(db.pool())
        .await
        .unwrap();

    let mut tx = db.begin(org).await.unwrap();
    let err = tx
        .accept_invite(&kept, newcomer.id, "new@acme.example")
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::InviteInvalid), "{err:?}");
}
