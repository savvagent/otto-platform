//! Revocation racing redemption: a member removal (or anything else that
//! revokes) committing while the member's refresh token or authorization code
//! is being redeemed must win, and the revocation covers codes not yet
//! redeemed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use savvagent_auth::oauth::{self, RegistrationRequest};
use savvagent_auth::resources::{self, ResourceServerSpec};
use savvagent_auth::tokens::{self, IssueParams};
use savvagent_auth::AuthError;
use savvagent_core::orgs::{OrgsExt, Role};
use savvagent_tenant::ids::{OrgId, UserId};
use savvagent_tenant::Db;
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
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
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
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
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
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn removing_a_member_consumes_their_unredeemed_codes(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
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
    use savvagent_auth::crypto::{self, prefix};
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
        .bind(savvagent_auth::crypto::hash(&presented))
        .execute(&mut *refreshing)
        .await
        .unwrap();
    let (access, refresh) = mint_in(&mut refreshing, user, org, &client).await;
    sqlx::query(
        "UPDATE refresh_tokens SET consumed_at = now() \
         WHERE token_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(savvagent_auth::crypto::hash(&presented))
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

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_refresh_in_flight_and_revokes_its_pair(pool: PgPool) {
    refresh_in_flight_then_revocation(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_org_deletion_waits_for_a_refresh_in_flight_and_revokes_its_pair(pool: PgPool) {
    refresh_in_flight_then_revocation(pool, Revocation::OrgDeletion).await;
}

/// The same for a code redemption that has claimed its code and minted.
async fn code_in_flight_then_revocation(pool: PgPool, how: Revocation) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
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

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_code_redemption_in_flight_and_revokes_its_pair(pool: PgPool) {
    code_in_flight_then_revocation(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_org_deletion_waits_for_a_code_redemption_in_flight_and_revokes_its_pair(pool: PgPool) {
    code_in_flight_then_revocation(pool, Revocation::OrgDeletion).await;
}

/// `redeem_code` itself holds the claim and the pair in one transaction: a
/// redemption refused after the claim (wrong verifier) still burns the code
/// and mints nothing.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_refused_code_redemption_burns_the_code_and_mints_nothing(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
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

/// An unredeemed code for the member with the test's PKCE verifier; returns
/// the plaintext.
async fn pkce_code(db: &Db, user: UserId, org: OrgId, client: &str) -> String {
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'S256', '{jobs:read}', $7, \
                 now() + interval '5 minutes')",
    )
    .bind(&code.hash)
    .bind(client)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(REDIRECT)
    .bind(URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())))
    .bind(RESOURCE)
    .execute(db.pool())
    .await
    .unwrap();
    code.into_plaintext()
}

/// A pool smaller than the number of concurrent redemptions below, on the
/// test's database, with a short acquire timeout so exhaustion shows as a
/// failure rather than a hang.
async fn small_pool(pool: &PgPool) -> Db {
    let small = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    Db::from_pool(small)
}

const CONCURRENT: usize = 12;

/// Every outcome of `CONCURRENT` redemptions of one grant: exactly one
/// succeeds, the rest are `invalid_grant`, and all finish well within the
/// pool's acquire timeout.
fn one_wins<T>(outcomes: Vec<savvagent_auth::Result<T>>) {
    let (won, lost): (Vec<_>, Vec<_>) = outcomes.into_iter().partition(|o| o.is_ok());
    assert_eq!(won.len(), 1, "exactly one redemption succeeds");
    for o in lost {
        let err = o.err().unwrap();
        assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    }
}

/// More concurrent redemptions of one code than the pool has connections:
/// each holds only its own connection while it waits for the code's row, so
/// the pool is never exhausted and they all finish.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn concurrent_redemptions_of_one_code_do_not_exhaust_the_pool(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let (user, org, client) = setup(&db).await;
    let code = pkce_code(&db, user, org, &client).await;
    let small = small_pool(&pool).await;

    let tasks: Vec<_> = (0..CONCURRENT)
        .map(|_| {
            let (db, code, client) = (small.clone(), code.clone(), client.clone());
            tokio::spawn(async move {
                oauth::redeem_code(&db, &code, &client, REDIRECT, VERIFIER, None)
                    .await
                    .map(|_| ())
            })
        })
        .collect();
    let outcomes = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    })
    .await
    .expect("the redemptions stalled: pool exhausted");
    one_wins(outcomes);
}

/// The same for one refresh token.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn concurrent_refreshes_of_one_token_do_not_exhaust_the_pool(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let (user, org, client) = setup(&db).await;
    let refresh = refresh_token(&db, user, org, &client).await;
    let small = small_pool(&pool).await;

    let tasks: Vec<_> = (0..CONCURRENT)
        .map(|_| {
            let (db, refresh, client) = (small.clone(), refresh.clone(), client.clone());
            tokio::spawn(async move {
                tokens::redeem_refresh(&db, &refresh, &client, None)
                    .await
                    .map(|_| ())
            })
        })
        .collect();
    let outcomes = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    })
    .await
    .expect("the refreshes stalled: pool exhausted");
    one_wins(outcomes);
}

/// The real `redeem_code`, started while a member removal holds the code's
/// row (it has revoked and consumed, not yet committed): it waits, then is
/// refused, and mints nothing.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_code_redemption_racing_a_member_removal_is_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = pkce_code(&db, user, org, &client).await;

    let mut removing = db.begin_unpinned().await.unwrap();
    tokens::revoke_all_in_org_tx(removing.conn(), user, org)
        .await
        .unwrap();

    let (db2, client2) = (db.clone(), client.clone());
    let redeem = tokio::spawn(async move {
        oauth::redeem_code(&db2, &code, &client2, REDIRECT, VERIFIER, None).await
    });
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!redeem.is_finished());
    removing.commit().await.unwrap();

    let err = redeem.await.unwrap().unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert_eq!(live_access_tokens(&db).await, 0, "a pair was minted");
}

/// A replayed refresh token while another transaction holds a row of its
/// family for longer than a redemption's 5 s lock timeout: the theft
/// response still revokes the family (the request waits for the row), and
/// only then refuses with `invalid_grant`, never a retriable failure with the
/// family still live.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_replay_revokes_the_family_even_while_a_row_of_it_is_busy(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let stolen = refresh_token(&db, user, org, &client).await;
    let (rotated, ..) = tokens::redeem_refresh(&db, &stolen, &client, None)
        .await
        .unwrap();
    let successor = rotated.refresh_token.unwrap();

    // Something holds the successor's row (a refresh of it in flight, say).
    let mut busy = db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE")
        .bind(savvagent_auth::crypto::hash(&successor))
        .execute(&mut *busy)
        .await
        .unwrap();

    let (db2, client2) = (db.clone(), client.clone());
    let replay =
        tokio::spawn(async move { tokens::redeem_refresh(&db2, &stolen, &client2, None).await });
    // Past the redemption's own lock timeout.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert!(
        !replay.is_finished(),
        "the replay gave up instead of waiting"
    );
    busy.commit().await.unwrap();

    let err = replay.await.unwrap().unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert!(tokens::introspect(&db, &rotated.access_token, RESOURCE)
        .await
        .is_err());
    let live_refresh: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(live_refresh, 0, "the family is still live");
}

// --------------------------------------------- credentials minted concurrently

/// Hold what `mint_pat` and `issue_authorization_code` hold between their
/// membership check and their insert: the org's row and the member's row,
/// `FOR SHARE`, then a credential inserted, not yet committed.
async fn minting_pat_in_flight(
    db: &Db,
    user: UserId,
    org: OrgId,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, String) {
    use savvagent_auth::crypto::{self, prefix};
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM orgs WHERE id = $1 AND deleted_at IS NULL FOR SHARE")
        .bind(org.as_uuid())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2 FOR SHARE")
        .bind(org.as_uuid())
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .unwrap();
    let pat = crypto::generate(prefix::PAT);
    sqlx::query(
        "INSERT INTO access_tokens \
           (token_hash, kind, name, user_id, org_id, scopes, resource, expires_at) \
         VALUES ($1, 'pat', 'ci', $2, $3, '{jobs:read}', $4, now() + interval '30 days')",
    )
    .bind(&pat.hash)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(RESOURCE)
    .execute(&mut *tx)
    .await
    .unwrap();
    (tx, pat.into_plaintext())
}

/// A member removal as the console runs it: revoke, then delete the row.
async fn remove_member(db: Db, user: UserId, org: OrgId) {
    let mut tx = db.begin_unpinned().await.unwrap();
    tokens::revoke_all_in_org_tx(tx.conn(), user, org)
        .await
        .unwrap();
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org.as_uuid())
        .bind(user.as_uuid())
        .execute(tx.conn())
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn live_pats(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM access_tokens WHERE kind = 'pat' AND revoked_at IS NULL",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn unconsumed_codes(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM authorization_codes WHERE consumed_at IS NULL")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// A PAT mint that has passed its checks and inserted, not yet committed, when
/// a removal or deletion starts: the revocation waits, then revokes the PAT.
async fn pat_in_flight_then_revocation(pool: PgPool, how: Revocation) {
    let db = Db::from_pool(pool);
    let (user, org, _client) = setup(&db).await;
    let (minting, pat) = minting_pat_in_flight(&db, user, org).await;

    let revoking = match how {
        Revocation::MemberRemoval => tokio::spawn(remove_member(db.clone(), user, org)),
        Revocation::OrgDeletion => tokio::spawn(revoke(db.clone(), how, user, org)),
    };
    someone_waits_on_a_lock(db.pool()).await;
    assert!(
        !revoking.is_finished(),
        "{how:?} did not wait for the PAT mint"
    );
    minting.commit().await.unwrap();
    revoking.await.unwrap();

    assert!(
        tokens::introspect(&db, &pat, RESOURCE).await.is_err(),
        "the PAT survived {how:?}"
    );
    assert_eq!(live_pats(&db).await, 0);
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_pat_mint_in_flight_and_revokes_it(pool: PgPool) {
    pat_in_flight_then_revocation(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn an_org_deletion_waits_for_a_pat_mint_in_flight_and_revokes_it(pool: PgPool) {
    pat_in_flight_then_revocation(pool, Revocation::OrgDeletion).await;
}

/// The other order: the removal or deletion holds its locks (revoked, not yet
/// committed) when the mint starts. The mint waits, then is refused.
async fn revocation_in_flight_then_mint(pool: PgPool, how: Revocation) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;

    let mut revoking = db.begin_unpinned().await.unwrap();
    match how {
        Revocation::MemberRemoval => {
            tokens::revoke_all_in_org_tx(revoking.conn(), user, org)
                .await
                .unwrap();
            sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
                .bind(org.as_uuid())
                .bind(user.as_uuid())
                .execute(revoking.conn())
                .await
                .unwrap();
        }
        Revocation::OrgDeletion => {
            sqlx::query("UPDATE orgs SET deleted_at = now() WHERE id = $1")
                .bind(org.as_uuid())
                .execute(revoking.conn())
                .await
                .unwrap();
        }
    }

    let db2 = db.clone();
    let pat =
        tokio::spawn(
            async move { tokens::mint_pat(&db2, user, org, "ci", &[], RESOURCE, None).await },
        );
    let (db3, client3) = (db.clone(), client.clone());
    let code = tokio::spawn(async move {
        oauth::issue_authorization_code(&db3, &code_req(&client3), user, org).await
    });
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!pat.is_finished(), "the mint did not wait for {how:?}");
    revoking.commit().await.unwrap();

    let err = pat.await.unwrap().unwrap_err();
    assert!(matches!(err, AuthError::InvalidRequest(_)), "{err:?}");
    assert_eq!(live_pats(&db).await, 0);
    let err = code.await.unwrap().unwrap_err();
    assert!(matches!(err, AuthError::InvalidRequest(_)), "{err:?}");
    assert_eq!(unconsumed_codes(&db).await, 0);
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_pat_mint_and_a_code_issuance_racing_a_member_removal_are_refused(pool: PgPool) {
    revocation_in_flight_then_mint(pool, Revocation::MemberRemoval).await;
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_pat_mint_and_a_code_issuance_racing_an_org_deletion_are_refused(pool: PgPool) {
    revocation_in_flight_then_mint(pool, Revocation::OrgDeletion).await;
}

fn code_req(client: &str) -> oauth::AuthorizeRequest {
    oauth::AuthorizeRequest {
        client_id: client.into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        code_challenge_method: "S256".into(),
        scopes: vec!["jobs:read".into()],
        resource: RESOURCE.into(),
        state: None,
    }
}

/// A code issuance that has passed its checks and inserted, not yet
/// committed, when a removal starts: the removal waits, then consumes the
/// code, so it can never redeem (and certainly not after a re-add).
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_member_removal_waits_for_a_code_issuance_in_flight_and_consumes_the_code(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;

    let mut issuing = db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM orgs WHERE id = $1 AND deleted_at IS NULL FOR SHARE")
        .bind(org.as_uuid())
        .execute(&mut *issuing)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2 FOR SHARE")
        .bind(org.as_uuid())
        .bind(user.as_uuid())
        .execute(&mut *issuing)
        .await
        .unwrap();
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
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
    .execute(&mut *issuing)
    .await
    .unwrap();

    let removing = tokio::spawn(remove_member(db.clone(), user, org));
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!removing.is_finished(), "the removal did not wait");
    issuing.commit().await.unwrap();
    removing.await.unwrap();

    assert_eq!(unconsumed_codes(&db).await, 0);
    // Re-added later, the stale code still redeems nothing.
    db.add_member(org, user, Role::Member).await.unwrap();
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

/// RFC 7009 revocation of a refresh token that is mid-refresh: the consumed
/// token is revoked and so is the successor pair the refresh minted.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn revoking_a_refresh_token_mid_refresh_leaves_no_valid_successor(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let presented = refresh_token(&db, user, org, &client).await;
    sqlx::query("UPDATE access_tokens SET revoked_at = now()")
        .execute(db.pool())
        .await
        .unwrap();

    // `redeem_refresh`'s steps, held open before its commit.
    let mut refreshing = db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE")
        .bind(savvagent_auth::crypto::hash(&presented))
        .execute(&mut *refreshing)
        .await
        .unwrap();
    let (access, refresh) = mint_in(&mut refreshing, user, org, &client).await;
    sqlx::query(
        "UPDATE refresh_tokens SET consumed_at = now(), \
                rotated_to = (SELECT id FROM refresh_tokens WHERE token_hash = $2) \
         WHERE token_hash = $1",
    )
    .bind(savvagent_auth::crypto::hash(&presented))
    .bind(savvagent_auth::crypto::hash(&refresh))
    .execute(&mut *refreshing)
    .await
    .unwrap();

    let (db2, presented2) = (db.clone(), presented.clone());
    let revoking = tokio::spawn(async move { tokens::revoke_presented(&db2, &presented2).await });
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!revoking.is_finished(), "the revocation did not wait");
    refreshing.commit().await.unwrap();
    revoking.await.unwrap().unwrap();

    assert_pair_revoked(&db, &client, &access, &refresh).await;
}

/// Revoking a stale (already rotated) refresh token revokes what the grant
/// went on to mint, however many rotations ago, and no other grant's tokens.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn revoking_a_rotated_refresh_token_revokes_its_successors_only(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let first = refresh_token(&db, user, org, &client).await;
    let other = refresh_token(&db, user, org, &client).await;
    let (second, ..) = tokens::redeem_refresh(&db, &first, &client, None)
        .await
        .unwrap();
    let (third, ..) = tokens::redeem_refresh(&db, &second.refresh_token.unwrap(), &client, None)
        .await
        .unwrap();

    tokens::revoke_presented(&db, &first).await.unwrap();

    assert!(tokens::introspect(&db, &third.access_token, RESOURCE)
        .await
        .is_err());
    let err = tokens::redeem_refresh(&db, &third.refresh_token.unwrap(), &client, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    // The other grant of the same client is untouched.
    tokens::redeem_refresh(&db, &other, &client, None)
        .await
        .unwrap();
}

/// Replay detection waits for a code redemption of the same family in flight
/// and revokes the pair it minted.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_replay_detection_waits_for_a_code_redemption_in_flight_and_revokes_its_pair(
    pool: PgPool,
) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = savvagent_auth::crypto::generate(savvagent_auth::crypto::prefix::AUTH_CODE);
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
    let mut redeeming = db.pool().begin().await.unwrap();
    sqlx::query(
        "UPDATE authorization_codes SET consumed_at = now() \
         WHERE code_hash = $1 AND consumed_at IS NULL",
    )
    .bind(&code.hash)
    .execute(&mut *redeeming)
    .await
    .unwrap();
    let (access, refresh) = mint_in(&mut redeeming, user, org, &client).await;

    let (db2, client2) = (db.clone(), client.clone());
    let replay =
        tokio::spawn(async move { tokens::revoke_family(&db2, user, org, &client2).await });
    someone_waits_on_a_lock(db.pool()).await;
    assert!(!replay.is_finished(), "the family revocation did not wait");
    redeeming.commit().await.unwrap();
    replay.await.unwrap().unwrap();
    assert_pair_revoked(&db, &client, &access, &refresh).await;
}
