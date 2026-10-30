//! The switch to Savvagent (savvagent/otto-platform#128) retires every
//! sign-in credential minted under an `otto_` prefix. Each presentation point
//! refuses one exactly as it refuses a value that was never minted, even when
//! the row behind it is still live; and the client ids that keep working
//! (`otto_client_`) still do.
//!
//! Every credential is stored by hash only, so a token minted before the
//! switch is modelled by minting a `sav_` one and pointing its row at the
//! `otto_` twin of its plaintext. Pointing the row back afterwards and using
//! the `sav_` value again shows the refusal touched nothing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_auth::crypto::{self, prefix};
use otto_auth::oauth::{self, RegistrationRequest};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens::{self, IssueParams};
use otto_auth::{sessions, AuthError};
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

/// The `otto_` twin of a `sav_` credential: same body, retired prefix.
fn twin(minted: &str, new: &str, old: &str) -> String {
    assert!(minted.starts_with(new), "{minted} is not {new}");
    minted.replacen(new, old, 1)
}

/// Point `table`'s row stored for `from` at `to` instead.
async fn rehash(db: &Db, table: &str, column: &str, from: &str, to: &str) {
    let n = sqlx::query(&format!(
        "UPDATE {table} SET {column} = $2 WHERE {column} = $1"
    ))
    .bind(crypto::hash(from))
    .bind(crypto::hash(to))
    .execute(db.pool())
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(n, 1, "no {table} row for the minted value");
}

/// The refusal for a value that was never minted, to compare against.
fn same_refusal(retired: &AuthError, unknown: &AuthError) {
    assert_eq!(format!("{retired:?}"), format!("{unknown:?}"));
}

/// An unknown value of the given shape.
fn never_minted(prefix: &str) -> String {
    crypto::generate(prefix).into_plaintext()
}

async fn issue(db: &Db, user: UserId, org: OrgId, client: &str) -> tokens::IssuedTokens {
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
}

/// An authorization code for `client`, stored as `oauth::authorize` stores
/// one, returned as plaintext.
async fn code_for(db: &Db, user: UserId, org: OrgId, client: &str) -> String {
    let code = crypto::generate(prefix::AUTH_CODE);
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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_access_token_minted_before_savvagent_is_refused_at_introspection(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let access = issue(&db, user, org, &client).await.access_token;
    tokens::introspect(&db, &access, RESOURCE).await.unwrap();

    let old = twin(&access, "sav_at_", "otto_at_");
    rehash(&db, "access_tokens", "token_hash", &access, &old).await;
    let retired = tokens::introspect(&db, &old, RESOURCE).await.unwrap_err();
    let unknown = tokens::introspect(&db, &never_minted(prefix::ACCESS), RESOURCE)
        .await
        .unwrap_err();
    same_refusal(&retired, &unknown);

    rehash(&db, "access_tokens", "token_hash", &old, &access).await;
    tokens::introspect(&db, &access, RESOURCE).await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_pat_minted_before_savvagent_is_refused_at_introspection(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, _) = setup(&db).await;
    let (pat, _) = tokens::mint_pat(&db, user, org, "ci", &[], RESOURCE, None)
        .await
        .unwrap();
    tokens::introspect(&db, &pat, RESOURCE).await.unwrap();

    let old = twin(&pat, "sav_pat_", "otto_pat_");
    rehash(&db, "access_tokens", "token_hash", &pat, &old).await;
    let retired = tokens::introspect(&db, &old, RESOURCE).await.unwrap_err();
    let unknown = tokens::introspect(&db, &never_minted(prefix::PAT), RESOURCE)
        .await
        .unwrap_err();
    same_refusal(&retired, &unknown);

    rehash(&db, "access_tokens", "token_hash", &old, &pat).await;
    tokens::introspect(&db, &pat, RESOURCE).await.unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refresh_token_minted_before_savvagent_is_refused_by_the_refresh_grant(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let refresh = issue(&db, user, org, &client).await.refresh_token.unwrap();

    let old = twin(&refresh, "sav_rt_", "otto_rt_");
    rehash(&db, "refresh_tokens", "token_hash", &refresh, &old).await;
    let retired = tokens::redeem_refresh(&db, &old, &client, None)
        .await
        .unwrap_err();
    let unknown = tokens::redeem_refresh(&db, &never_minted(prefix::REFRESH), &client, None)
        .await
        .unwrap_err();
    same_refusal(&retired, &unknown);

    // Neither consumed nor treated as a replay: the family is intact.
    rehash(&db, "refresh_tokens", "token_hash", &old, &refresh).await;
    tokens::redeem_refresh(&db, &refresh, &client, None)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_code_minted_before_savvagent_is_refused_at_redemption(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, client) = setup(&db).await;
    let code = code_for(&db, user, org, &client).await;

    let old = twin(&code, "sav_ac_", "otto_ac_");
    rehash(&db, "authorization_codes", "code_hash", &code, &old).await;
    let retired = oauth::redeem_code(&db, &old, &client, REDIRECT, VERIFIER, None)
        .await
        .unwrap_err();
    let unknown = oauth::redeem_code(
        &db,
        &never_minted(prefix::AUTH_CODE),
        &client,
        REDIRECT,
        VERIFIER,
        None,
    )
    .await
    .unwrap_err();
    same_refusal(&retired, &unknown);

    // Not burned by the refusal.
    rehash(&db, "authorization_codes", "code_hash", &old, &code).await;
    oauth::redeem_code(&db, &code, &client, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_session_minted_before_savvagent_is_refused(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, _, _) = setup(&db).await;
    let session = sessions::create(&db, user).await.unwrap().token;
    sessions::resolve(&db, &session).await.unwrap();

    let old = twin(&session, "sav_ss_", "otto_ss_");
    rehash(&db, "browser_sessions", "token_hash", &session, &old).await;
    let retired = sessions::resolve(&db, &old).await.unwrap_err();
    let unknown = sessions::resolve(&db, &never_minted(prefix::SESSION))
        .await
        .unwrap_err();
    same_refusal(&retired, &unknown);

    rehash(&db, "browser_sessions", "token_hash", &old, &session).await;
    sessions::resolve(&db, &session).await.unwrap();
}

/// New clients get `sav_client_` ids; a client registered before the switch
/// keeps its `otto_client_` id, and the whole grant still works for it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_client_registered_before_savvagent_keeps_working(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (user, org, minted) = setup(&db).await;
    assert!(minted.starts_with("sav_client_"), "{minted}");

    let old = twin(&minted, "sav_client_", "otto_client_");
    sqlx::query("UPDATE oauth_clients SET client_id = $2 WHERE client_id = $1")
        .bind(&minted)
        .bind(&old)
        .execute(db.pool())
        .await
        .unwrap();
    oauth::get_client(&db, &old).await.unwrap();

    let code = code_for(&db, user, org, &old).await;
    let (issued, _, _) = oauth::redeem_code(&db, &code, &old, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
    let principal = tokens::introspect(&db, &issued.access_token, RESOURCE)
        .await
        .unwrap();
    assert_eq!(principal.client_id.as_deref(), Some(old.as_str()));
    tokens::redeem_refresh(&db, &issued.refresh_token.unwrap(), &old, None)
        .await
        .unwrap();
}
