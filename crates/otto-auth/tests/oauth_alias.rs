//! OAuth flows through a resource alias (savvagent/otto-platform#89, design
//! D1): a client still configured with a renamed resource server's old URI
//! keeps working until the alias's sunset. Authorize, code redemption,
//! refresh and PAT issuance resolve a live alias to the canonical server and
//! store and compare canonical URIs. An expired or dropped alias the client
//! names is `invalid_target`, like a URI never registered. A grant stored
//! under an alias (a mint that raced the rename) still belongs to its server.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use otto_auth::oauth::{self, AuthorizeRequest, RegistrationRequest};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens::{self, IssueParams};
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const OLD: &str = "https://otto-factory.example/mcp";
const NEW: &str = "https://otto-tower.example/mcp";
const FLAGS: &str = "https://otto-flags.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:4545/callback";
const VERIFIER: &str = "a-pkce-code-verifier-that-is-at-least-forty-three-chars-long";

async fn register(db: &Db, uri: &str, scopes: &[&str]) {
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: uri,
            name: uri,
            scopes,
            default_scopes: &scopes[..1],
        },
    )
    .await
    .unwrap();
}

/// OLD renamed to NEW with OLD a live alias, plus an unrelated FLAGS server.
async fn renamed(db: &Db) {
    register(db, OLD, &["jobs:read", "jobs:write"]).await;
    register(db, FLAGS, &["flags:read"]).await;
    resources::rename(db, OLD, NEW, Some(Utc::now() + Duration::days(90)), None)
        .await
        .unwrap();
}

async fn member(db: &Db) -> (UserId, OrgId) {
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = db.upsert_user("dev@acme.example", None).await.unwrap();
    db.add_member(org.id, user.id, Role::Owner).await.unwrap();
    (user.id, org.id)
}

async fn client(db: &Db) -> String {
    oauth::register_client(
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
    .client_id
}

fn authorize_req(client_id: &str, resource: &str) -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: client_id.into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        code_challenge_method: "S256".into(),
        scopes: vec!["jobs:read".into()],
        resource: resource.into(),
        state: None,
    }
}

/// Ages an alias past its sunset, as only time (or a superuser) can.
async fn expire(db: &Db, alias: &str) {
    sqlx::query(
        "UPDATE resource_server_aliases SET sunset_at = now() - interval '1 second' \
         WHERE alias_uri = $1",
    )
    .bind(alias)
    .execute(db.pool())
    .await
    .unwrap();
}

/// How an alias stops working.
#[derive(Debug, Clone, Copy)]
enum Ended {
    Expired,
    Dropped,
}

async fn end(db: &Db, how: Ended) {
    match how {
        Ended::Expired => expire(db, OLD).await,
        Ended::Dropped => {
            resources::drop_alias(db, OLD).await.unwrap();
        }
    }
}

async fn stored_resources(db: &Db, table: &str) -> Vec<String> {
    sqlx::query_scalar(&format!("SELECT resource FROM {table} ORDER BY resource"))
        .fetch_all(db.pool())
        .await
        .unwrap()
}

fn invalid_target(err: &AuthError) -> bool {
    matches!(err, AuthError::InvalidTarget(_))
}

/// What a mint that read the old canonical URI before the rename committed
/// writes after it: a grant stored under the alias.
async fn raced_code(db: &Db, user: UserId, org: OrgId, client_id: &str) -> String {
    let code = otto_auth::crypto::generate(otto_auth::crypto::prefix::AUTH_CODE);
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'S256', '{jobs:read}', $7, \
                 now() + interval '5 minutes')",
    )
    .bind(&code.hash)
    .bind(client_id)
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(REDIRECT)
    .bind(URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())))
    .bind(OLD)
    .execute(db.pool())
    .await
    .unwrap();
    code.into_plaintext()
}

async fn raced_refresh(db: &Db, user: UserId, org: OrgId, client_id: &str) -> String {
    tokens::issue(
        db,
        IssueParams {
            user_id: user,
            org_id: org,
            client_id: Some(client_id),
            scopes: &["jobs:read".to_owned()],
            resource: OLD,
            with_refresh: true,
        },
    )
    .await
    .unwrap()
    .refresh_token
    .unwrap()
}

// ---- authorize and code issuance ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authorizing_with_a_live_alias_resolves_to_the_canonical_server(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let client_id = client(&db).await;
    let auth = oauth::validate_authorize(&db, &authorize_req(&client_id, OLD))
        .await
        .unwrap();
    assert_eq!(auth.resource.resource_uri, NEW);
    assert_eq!(auth.scopes, ["jobs:read"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_code_issued_for_an_alias_stores_and_mints_the_canonical_uri(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let code = oauth::issue_authorization_code(&db, &authorize_req(&client_id, OLD), user, org)
        .await
        .unwrap();
    assert_eq!(stored_resources(&db, "authorization_codes").await, [NEW]);

    // The client repeats the alias it authorized with at the token endpoint.
    let (issued, ..) = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(OLD))
        .await
        .unwrap();
    assert_eq!(stored_resources(&db, "access_tokens").await, [NEW]);
    assert_eq!(stored_resources(&db, "refresh_tokens").await, [NEW]);
    tokens::introspect(&db, &issued.access_token, NEW)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_code_redeems_naming_the_canonical_uri_the_alias_or_nothing(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    for requested in [Some(NEW), Some(OLD), None] {
        let code = oauth::issue_authorization_code(&db, &authorize_req(&client_id, NEW), user, org)
            .await
            .unwrap();
        oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, requested)
            .await
            .unwrap_or_else(|e| panic!("{requested:?}: {e:?}"));
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_code_redeemed_naming_another_server_is_still_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let code = oauth::issue_authorization_code(&db, &authorize_req(&client_id, OLD), user, org)
        .await
        .unwrap();
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(FLAGS))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
    assert!(stored_resources(&db, "access_tokens").await.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_expired_alias_is_invalid_target_wherever_the_client_names_it(pool: PgPool) {
    ended_alias_is_invalid_target(pool, Ended::Expired).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_dropped_alias_is_invalid_target_wherever_the_client_names_it(pool: PgPool) {
    ended_alias_is_invalid_target(pool, Ended::Dropped).await;
}

async fn ended_alias_is_invalid_target(pool: PgPool, how: Ended) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    // Grants made while the alias was live, stored under the canonical URI.
    let code = oauth::issue_authorization_code(&db, &authorize_req(&client_id, OLD), user, org)
        .await
        .unwrap();
    let pending = oauth::issue_authorization_code(&db, &authorize_req(&client_id, OLD), user, org)
        .await
        .unwrap();
    let (issued, ..) = oauth::redeem_code(&db, &pending, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
    let refresh = issued.refresh_token.unwrap();
    end(&db, how).await;

    let err = oauth::validate_authorize(&db, &authorize_req(&client_id, OLD))
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{how:?} authorize: {err:?}");
    let err = oauth::issue_authorization_code(&db, &authorize_req(&client_id, OLD), user, org)
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{how:?} code: {err:?}");
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(OLD))
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{how:?} redemption: {err:?}");
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(OLD))
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{how:?} refresh: {err:?}");
    let err = tokens::mint_pat(&db, user, org, "ci", &[], OLD, None)
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{how:?} PAT: {err:?}");

    // The refused refresh was not consumed: naming the canonical URI (or
    // nothing) still works, because the grant was never bound to the alias.
    tokens::redeem_refresh(&db, &refresh, &client_id, Some(NEW))
        .await
        .unwrap();
}

// ---- refresh ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn refresh_accepts_the_alias_of_the_stored_canonical_uri(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let code = oauth::issue_authorization_code(&db, &authorize_req(&client_id, NEW), user, org)
        .await
        .unwrap();
    let (issued, ..) = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
    let (rotated, ..) =
        tokens::redeem_refresh(&db, &issued.refresh_token.unwrap(), &client_id, Some(OLD))
            .await
            .unwrap();
    tokens::introspect(&db, &rotated.access_token, NEW)
        .await
        .unwrap();
    assert_eq!(stored_resources(&db, "refresh_tokens").await, [NEW, NEW]);

    let err = tokens::redeem_refresh(
        &db,
        &rotated.refresh_token.unwrap(),
        &client_id,
        Some(FLAGS),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
}

// ---- grants stored under an alias (a mint that raced the rename) ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_code_stored_under_an_alias_redeems_for_its_server_in_any_alias_state(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;

    // Live alias: the client may name the canonical URI, the alias, or nothing.
    for requested in [Some(NEW), Some(OLD), None] {
        let code = raced_code(&db, user, org, &client_id).await;
        let (issued, ..) =
            oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, requested)
                .await
                .unwrap_or_else(|e| panic!("{requested:?}: {e:?}"));
        tokens::introspect(&db, &issued.access_token, NEW)
            .await
            .unwrap();
    }
    // Tokens minted from it are bound to the canonical URI.
    assert!(stored_resources(&db, "access_tokens")
        .await
        .iter()
        .all(|r| r == NEW));

    // Another server is still another server.
    let code = raced_code(&db, user, org, &client_id).await;
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(FLAGS))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");

    // Once the alias has ended, the stored grant is still its server's, but
    // a client naming the dead alias is refused.
    expire(&db, OLD).await;
    for requested in [Some(NEW), None] {
        let code = raced_code(&db, user, org, &client_id).await;
        oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, requested)
            .await
            .unwrap_or_else(|e| panic!("expired, {requested:?}: {e:?}"));
    }
    let code = raced_code(&db, user, org, &client_id).await;
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(OLD))
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{err:?}");

    resources::drop_alias(&db, OLD).await.unwrap();
    let code = raced_code(&db, user, org, &client_id).await;
    oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refresh_token_stored_under_an_alias_refreshes_in_any_alias_state(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;

    for requested in [Some(NEW), Some(OLD), None] {
        let refresh = raced_refresh(&db, user, org, &client_id).await;
        let (rotated, ..) = tokens::redeem_refresh(&db, &refresh, &client_id, requested)
            .await
            .unwrap_or_else(|e| panic!("{requested:?}: {e:?}"));
        tokens::introspect(&db, &rotated.access_token, NEW)
            .await
            .unwrap();
        let successor: String =
            sqlx::query_scalar("SELECT resource FROM refresh_tokens WHERE token_hash = $1")
                .bind(otto_auth::crypto::hash(&rotated.refresh_token.unwrap()))
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            successor, NEW,
            "the successor is bound to the canonical URI"
        );
    }

    let refresh = raced_refresh(&db, user, org, &client_id).await;
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(FLAGS))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");

    resources::drop_alias(&db, OLD).await.unwrap();
    let refresh = raced_refresh(&db, user, org, &client_id).await;
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(OLD))
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{err:?}");
    for requested in [Some(NEW), None] {
        let refresh = raced_refresh(&db, user, org, &client_id).await;
        tokens::redeem_refresh(&db, &refresh, &client_id, requested)
            .await
            .unwrap_or_else(|e| panic!("dropped, {requested:?}: {e:?}"));
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_grant_stored_under_an_alias_of_a_disabled_server_is_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let code = raced_code(&db, user, org, &client_id).await;
    let refresh = raced_refresh(&db, user, org, &client_id).await;
    resources::set_disabled(&db, NEW, true).await.unwrap();
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{err:?}");
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, None)
        .await
        .unwrap_err();
    assert!(invalid_target(&err), "{err:?}");

    // The refused refresh token was not consumed: once the server is enabled
    // again it refreshes.
    resources::set_disabled(&db, NEW, false).await.unwrap();
    let (rotated, ..) = tokens::redeem_refresh(&db, &refresh, &client_id, Some(OLD))
        .await
        .unwrap();
    tokens::introspect(&db, &rotated.access_token, NEW)
        .await
        .unwrap();
}

// ---- requested resources that name nothing, or another server ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_requested_resource_never_registered_is_invalid_target(pool: PgPool) {
    const UNKNOWN: &str = "https://nobody.example/mcp";
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;

    for code in [
        oauth::issue_authorization_code(&db, &authorize_req(&client_id, NEW), user, org)
            .await
            .unwrap(),
        raced_code(&db, user, org, &client_id).await,
    ] {
        let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(UNKNOWN))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AuthError::InvalidTarget(m) if m.contains("nobody.example")),
            "{err:?}"
        );
    }
    let refresh = raced_refresh(&db, user, org, &client_id).await;
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(UNKNOWN))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AuthError::InvalidTarget(m) if m.contains("nobody.example")),
        "{err:?}"
    );
    // Not consumed by the refusal.
    tokens::redeem_refresh(&db, &refresh, &client_id, None)
        .await
        .unwrap();
}

/// A grant for another server, redeemed naming the renamed server's live
/// alias, is refused: the alias is the renamed server's, not the grant's.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_grant_for_another_server_redeemed_with_an_alias_is_invalid_grant(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let flags_req = AuthorizeRequest {
        scopes: vec!["flags:read".into()],
        ..authorize_req(&client_id, FLAGS)
    };
    let code = oauth::issue_authorization_code(&db, &flags_req, user, org)
        .await
        .unwrap();
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(OLD))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");

    let code = oauth::issue_authorization_code(&db, &flags_req, user, org)
        .await
        .unwrap();
    let (issued, ..) = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(FLAGS))
        .await
        .unwrap();
    let refresh = issued.refresh_token.unwrap();
    for named in [OLD, NEW] {
        let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(named))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::InvalidGrant(_)),
            "{named}: {err:?}"
        );
    }
    tokens::redeem_refresh(&db, &refresh, &client_id, Some(FLAGS))
        .await
        .unwrap();
}

// ---- PATs ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_pat_minted_for_an_alias_is_bound_to_the_canonical_uri(pool: PgPool) {
    let db = Db::from_pool(pool);
    renamed(&db).await;
    let (user, org) = member(&db).await;
    let (pat, _) = tokens::mint_pat(&db, user, org, "ci", &["jobs:write".into()], OLD, None)
        .await
        .unwrap();
    assert_eq!(stored_resources(&db, "access_tokens").await, [NEW]);
    let principal = tokens::introspect(&db, &pat, NEW).await.unwrap();
    assert!(principal.has_scope("jobs:write"));
}
