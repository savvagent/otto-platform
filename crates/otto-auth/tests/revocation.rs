//! Revocation racing redemption: a member removal (or anything else that
//! revokes) committing while the member's refresh token or authorization code
//! is being redeemed must win, and the revocation covers codes not yet
//! redeemed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_auth::oauth::{self, RegistrationRequest};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens::{self, IssueParams};
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const RESOURCE: &str = "https://otto-tower.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:4545/callback";
const VERIFIER: &str = "a-pkce-code-verifier-that-is-at-least-forty-three-chars-long";

async fn setup(db: &Db) -> (UserId, OrgId, String) {
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: RESOURCE,
            name: "otto-tower",
            scopes: &["jobs:read"],
            default_scopes: &["jobs:read"],
        },
    )
    .await
    .unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = db.upsert_user("dev@acme.example", None).await.unwrap();
    db.add_member(org.id, user.id, Role::Member).await.unwrap();
    let client = oauth::register_client(
        db,
        RegistrationRequest {
            client_name: Some("test agent".into()),
            redirect_uris: vec![REDIRECT.into()],
            software_id: None,
            grant_types: None,
        },
    )
    .await
    .unwrap()
    .client_id;
    (user.id, org.id, client)
}

async fn refresh_token(db: &Db, user: UserId, org: OrgId, client: &str) -> String {
    tokens::issue(
        db,
        IssueParams {
            user_id: user,
            org_id: org,
            client_id: Some(client),
            scopes: &["jobs:read".to_owned()],
            resource: RESOURCE,
            with_refresh: true,
        },
    )
    .await
    .unwrap()
    .refresh_token
    .unwrap()
}

async fn live_access_tokens(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM access_tokens WHERE revoked_at IS NULL")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Waits until some session of this test's database is blocked on a lock.
async fn someone_waits_on_a_lock(pool: &PgPool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting > 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "nothing came to wait on a lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A refresh started while a member removal has revoked the member's tokens
/// but not yet committed waits for it, then is refused: it mints nothing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refresh_racing_a_member_removal_is_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let refresh = refresh_token(&db, user, org, &client).await;

    let mut removing = db.begin_unpinned().await.unwrap();
    tokens::revoke_all_in_org_tx(removing.conn(), user, org)
        .await
        .unwrap();

    let (db2, client2) = (db.clone(), client.clone());
    let redeem =
        tokio::spawn(async move { tokens::redeem_refresh(&db2, &refresh, &client2, None).await });
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!redeem.is_finished());
    removing.commit().await.unwrap();

    let err = redeem.await.unwrap().unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert_eq!(live_access_tokens(&db).await, 0, "a successor was minted");
}

/// The happy path still rotates once, and a replay still revokes the family.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refresh_rotates_once_and_a_replay_revokes_the_family(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let refresh = refresh_token(&db, user, org, &client).await;

    let (rotated, ..) = tokens::redeem_refresh(&db, &refresh, &client, None)
        .await
        .unwrap();
    assert!(tokens::introspect(&db, &rotated.access_token, RESOURCE)
        .await
        .is_ok());
    let err = tokens::redeem_refresh(&db, &refresh, &client, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert!(tokens::introspect(&db, &rotated.access_token, RESOURCE)
        .await
        .is_err());
    assert!(
        tokens::redeem_refresh(&db, &rotated.refresh_token.unwrap(), &client, None)
            .await
            .is_err()
    );
}

/// Removing a member also consumes their codes not yet redeemed, which
/// would otherwise mint a fresh pair after the removal.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn removing_a_member_consumes_their_unredeemed_codes(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = otto_auth::crypto::generate(otto_auth::crypto::prefix::AUTH_CODE);
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'S256', '{jobs:read}', $7, \
                 now() + interval '5 minutes')",
    )
    .bind(&code.hash)
    .bind(&client)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(REDIRECT)
    .bind(URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())))
    .bind(RESOURCE)
    .execute(db.pool())
    .await
    .unwrap();

    tokens::revoke_all_in_org(&db, user, org).await.unwrap();
    let err = oauth::redeem_code(
        &db,
        &code.into_plaintext(),
        &client,
        REDIRECT,
        VERIFIER,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert_eq!(live_access_tokens(&db).await, 0);
}

/// A pair minted by a redemption in flight, written as `redeem_refresh` and
/// `redeem_code` write theirs: the plaintext access and refresh tokens.
async fn mint_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: UserId,
    org: OrgId,
    client: &str,
) -> (String, String) {
    use otto_auth::crypto::{self, prefix};
    let access = crypto::generate(prefix::ACCESS);
    let refresh = crypto::generate(prefix::REFRESH);
    let access_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO access_tokens \
           (token_hash, kind, user_id, org_id, client_id, scopes, resource, expires_at) \
         VALUES ($1, 'oauth', $2, $3, $4, '{jobs:read}', $5, now() + interval '1 hour') \
         RETURNING id",
    )
    .bind(&access.hash)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(client)
    .bind(RESOURCE)
    .fetch_one(&mut **tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO refresh_tokens \
           (token_hash, access_token_id, user_id, org_id, client_id, scopes, resource, \
            expires_at) \
         VALUES ($1, $2, $3, $4, $5, '{jobs:read}', $6, now() + interval '30 days')",
    )
    .bind(&refresh.hash)
    .bind(access_id)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(client)
    .bind(RESOURCE)
    .execute(&mut **tx)
    .await
    .unwrap();
    (access.into_plaintext(), refresh.into_plaintext())
}

/// How a member loses access.
#[derive(Clone, Copy, Debug)]
enum Revocation {
    MemberRemoval,
    OrgDeletion,
}

async fn revoke(db: Db, how: Revocation, user: UserId, org: OrgId) {
    match how {
        Revocation::MemberRemoval => {
            tokens::revoke_all_in_org(&db, user, org).await.unwrap();
        }
        Revocation::OrgDeletion => db.delete_org(org).await.unwrap(),
    }
}

/// After the in-flight redemption committed and the revocation finished,
/// the pair it minted is dead.
async fn assert_pair_revoked(db: &Db, client: &str, access: &str, refresh: &str) {
    assert!(
        tokens::introspect(db, access, RESOURCE).await.is_err(),
        "the in-flight access token survived the revocation"
    );
    let err = tokens::redeem_refresh(db, refresh, client, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert_eq!(live_access_tokens(db).await, 0);
}

/// A refresh that has locked its token and minted its successor, not yet
/// committed, when a revocation starts: the revocation waits for it, then
/// revokes the successor too.
async fn refresh_in_flight_then_revocation(pool: PgPool, how: Revocation) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let presented = refresh_token(&db, user, org, &client).await;
    // The presented pair's access token is revoked by the revocation anyway;
    // count only what the redemption mints.
    sqlx::query("UPDATE access_tokens SET revoked_at = now()")
        .execute(db.pool())
        .await
        .unwrap();

    // `redeem_refresh`'s steps, held open before its commit.
    let mut refreshing = db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE")
        .bind(otto_auth::crypto::hash(&presented))
        .execute(&mut *refreshing)
        .await
        .unwrap();
    let (access, refresh) = mint_in(&mut refreshing, user, org, &client).await;
    sqlx::query(
        "UPDATE refresh_tokens SET consumed_at = now() \
         WHERE token_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(otto_auth::crypto::hash(&presented))
    .execute(&mut *refreshing)
    .await
    .unwrap();

    let revoking = tokio::spawn(revoke(db.clone(), how, user, org));
    someone_waits_on_a_lock(db.pool()).await;
    assert!(
        !revoking.is_finished(),
        "{how:?} did not wait for the refresh"
    );
    refreshing.commit().await.unwrap();
    revoking.await.unwrap();

    assert_pair_revoked(&db, &client, &access, &refresh).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_refresh_in_flight_and_revokes_its_pair(pool: PgPool) {
    refresh_in_flight_then_revocation(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_org_deletion_waits_for_a_refresh_in_flight_and_revokes_its_pair(pool: PgPool) {
    refresh_in_flight_then_revocation(pool, Revocation::OrgDeletion).await;
}

/// The same for a code redemption that has claimed its code and minted.
async fn code_in_flight_then_revocation(pool: PgPool, how: Revocation) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = otto_auth::crypto::generate(otto_auth::crypto::prefix::AUTH_CODE);
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, $4, $5, 'challenge', 'S256', '{jobs:read}', $6, \
                 now() + interval '5 minutes')",
    )
    .bind(&code.hash)
    .bind(&client)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(REDIRECT)
    .bind(RESOURCE)
    .execute(db.pool())
    .await
    .unwrap();

    // `redeem_code`'s steps, held open before its commit: the claim, then
    // the pair.
    let mut redeeming = db.pool().begin().await.unwrap();
    let claimed = sqlx::query(
        "UPDATE authorization_codes SET consumed_at = now() \
         WHERE code_hash = $1 AND consumed_at IS NULL",
    )
    .bind(&code.hash)
    .execute(&mut *redeeming)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(claimed, 1);
    let (access, refresh) = mint_in(&mut redeeming, user, org, &client).await;

    let revoking = tokio::spawn(revoke(db.clone(), how, user, org));
    someone_waits_on_a_lock(db.pool()).await;
    assert!(
        !revoking.is_finished(),
        "{how:?} did not wait for the redemption"
    );
    redeeming.commit().await.unwrap();
    revoking.await.unwrap();

    assert_pair_revoked(&db, &client, &access, &refresh).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_code_redemption_in_flight_and_revokes_its_pair(pool: PgPool) {
    code_in_flight_then_revocation(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_org_deletion_waits_for_a_code_redemption_in_flight_and_revokes_its_pair(pool: PgPool) {
    code_in_flight_then_revocation(pool, Revocation::OrgDeletion).await;
}

/// `redeem_code` itself holds the claim and the pair in one transaction: a
/// redemption refused after the claim (wrong verifier) still burns the code
/// and mints nothing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refused_code_redemption_burns_the_code_and_mints_nothing(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = otto_auth::crypto::generate(otto_auth::crypto::prefix::AUTH_CODE);
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'S256', '{jobs:read}', $7, \
                 now() + interval '5 minutes')",
    )
    .bind(&code.hash)
    .bind(&client)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(REDIRECT)
    .bind(URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())))
    .bind(RESOURCE)
    .execute(db.pool())
    .await
    .unwrap();
    let plaintext = code.into_plaintext();
    let wrong = "x".repeat(VERIFIER.len());
    assert!(
        oauth::redeem_code(&db, &plaintext, &client, REDIRECT, &wrong, None)
            .await
            .is_err()
    );
    assert_eq!(live_access_tokens(&db).await, 0);
    let err = oauth::redeem_code(&db, &plaintext, &client, REDIRECT, VERIFIER, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert_eq!(live_access_tokens(&db).await, 0);
}
