//! The resource-server registry and every token path that now consults it:
//! authorize, code redemption, refresh, PATs, and introspection credentials.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_auth::oauth::{self, AuthorizeRequest, RegistrationRequest};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens;
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const FACTORY: &str = "https://otto-factory.example/mcp";
const FLAGS: &str = "https://otto-flags.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:4545/callback";
const VERIFIER: &str = "a-pkce-code-verifier-that-is-at-least-forty-three-chars-long";

async fn register_both(db: &Db) {
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: FACTORY,
            name: "otto-factory",
            scopes: &["jobs:read", "jobs:write"],
            default_scopes: &["jobs:read"],
        },
    )
    .await
    .unwrap();
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: FLAGS,
            name: "otto-flags",
            scopes: &["flags:read", "flags:write"],
            default_scopes: &["flags:read"],
        },
    )
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

fn authorize_req(client_id: &str, resource: &str, scopes: &[&str]) -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: client_id.into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        code_challenge_method: "S256".into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        resource: resource.into(),
        state: None,
    }
}

/// Runs the whole authorization-code flow and returns the issued tokens.
async fn code_flow(
    db: &Db,
    resource: &str,
    scopes: &[&str],
) -> (tokens::IssuedTokens, String, UserId, OrgId) {
    let (user, org) = member(db).await;
    let client_id = client(db).await;
    let req = authorize_req(&client_id, resource, scopes);
    oauth::validate_authorize(db, &req).await.unwrap();
    let code = oauth::issue_authorization_code(db, &req, user, org)
        .await
        .unwrap();
    let (issued, _, _) = oauth::redeem_code(db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
    (issued, client_id, user, org)
}

// ---- registration ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn register_is_idempotent_and_never_re_enables(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    resources::set_disabled(&db, FLAGS, true).await.unwrap();

    let updated = resources::register(
        &db,
        ResourceServerSpec {
            resource_uri: FLAGS,
            name: "otto-flags v2",
            scopes: &["flags:read", "flags:write", "flags:admin"],
            default_scopes: &["flags:read"],
        },
    )
    .await
    .unwrap();

    assert_eq!(updated.name, "otto-flags v2");
    assert_eq!(updated.scopes, ["flags:read", "flags:write", "flags:admin"]);
    assert!(updated.disabled, "re-registering must not re-enable");
    assert_eq!(resources::list(&db).await.unwrap().len(), 2);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn register_refuses_defaults_outside_the_scope_list(pool: PgPool) {
    let db = Db::from_pool(pool);
    let err = resources::register(
        &db,
        ResourceServerSpec {
            resource_uri: FLAGS,
            name: "otto-flags",
            scopes: &["flags:read"],
            default_scopes: &["flags:write"],
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::InvalidRequest(_)), "{err:?}");
}

// ---- scope descriptions ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn scope_descriptions_are_stored_and_replaced_wholesale(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    assert!(resources::get(&db, FACTORY)
        .await
        .unwrap()
        .unwrap()
        .scope_descriptions
        .is_empty());

    let rs = resources::set_scope_descriptions(
        &db,
        FACTORY,
        &[("jobs:read", "  View jobs "), ("jobs:write", "Change jobs")],
    )
    .await
    .unwrap();
    assert_eq!(rs.scope_description("jobs:read"), Some("View jobs"));

    let stored = resources::get(&db, FACTORY).await.unwrap().unwrap();
    assert_eq!(stored.scope_description("jobs:write"), Some("Change jobs"));
    // Another resource server is untouched.
    let other = resources::get(&db, FLAGS).await.unwrap().unwrap();
    assert!(other.scope_descriptions.is_empty());

    // Replace, not merge; an empty set clears.
    let rs = resources::set_scope_descriptions(&db, FACTORY, &[("jobs:read", "Look")])
        .await
        .unwrap();
    assert_eq!(rs.scope_description("jobs:write"), None);
    let rs = resources::set_scope_descriptions(&db, FACTORY, &[])
        .await
        .unwrap();
    assert!(rs.scope_descriptions.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn scope_descriptions_are_validated(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;

    let long = "x".repeat(resources::MAX_SCOPE_DESCRIPTION_CHARS + 1);
    for bad in [
        vec![("flags:read", "a scope of another resource server")],
        vec![("jobs:read", "")],
        vec![("jobs:read", long.as_str())],
        vec![("jobs:read", "multi\nline")],
    ] {
        let err = resources::set_scope_descriptions(&db, FACTORY, &bad)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::InvalidRequest(_)),
            "{bad:?}: {err:?}"
        );
    }
    let err = resources::set_scope_descriptions(&db, "https://nope.example/mcp", &[])
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");
}

/// A service re-registers at every startup; that must not erase what an
/// operator wrote, but a description must not outlive its scope.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn re_registering_keeps_descriptions_of_surviving_scopes_only(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    resources::set_scope_descriptions(
        &db,
        FACTORY,
        &[("jobs:read", "View jobs"), ("jobs:write", "Change jobs")],
    )
    .await
    .unwrap();

    let rs = resources::register(
        &db,
        ResourceServerSpec {
            resource_uri: FACTORY,
            name: "otto-factory",
            scopes: &["jobs:read", "jobs:admin"],
            default_scopes: &["jobs:read"],
        },
    )
    .await
    .unwrap();
    assert_eq!(rs.scope_description("jobs:read"), Some("View jobs"));
    assert_eq!(rs.scope_description("jobs:write"), None);
    assert_eq!(rs.scope_descriptions.len(), 1);
}

/// The database refuses an orphan description even if the Rust check is
/// bypassed.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_database_refuses_a_description_for_an_unknown_scope(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let r = sqlx::query(
        "UPDATE resource_servers SET scope_descriptions = '{\"ghost\": \"x\"}' WHERE resource_uri = $1",
    )
    .bind(FACTORY)
    .execute(db.pool())
    .await;
    assert!(r.is_err());
    let r = sqlx::query(
        "UPDATE resource_servers SET scope_descriptions = '[]' WHERE resource_uri = $1",
    )
    .bind(FACTORY)
    .execute(db.pool())
    .await;
    assert!(r.is_err());
}

// ---- authorize ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authorize_refuses_an_unregistered_resource(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let client_id = client(&db).await;
    let req = authorize_req(&client_id, "https://elsewhere.example/mcp", &[]);
    let err = oauth::validate_authorize(&db, &req).await.unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");
    assert_eq!(err.oauth_code(), Some("invalid_target"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authorize_refuses_another_resource_servers_scope(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let client_id = client(&db).await;
    let req = authorize_req(&client_id, FLAGS, &["jobs:write"]);
    let err = oauth::validate_authorize(&db, &req).await.unwrap_err();
    assert!(matches!(err, AuthError::InvalidScope(_)), "{err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authorize_refuses_a_disabled_resource(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    resources::set_disabled(&db, FLAGS, true).await.unwrap();
    let client_id = client(&db).await;
    let err = oauth::validate_authorize(&db, &authorize_req(&client_id, FLAGS, &[]))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authorize_reports_the_resource_and_granted_scopes(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let client_id = client(&db).await;
    let auth = oauth::validate_authorize(&db, &authorize_req(&client_id, FLAGS, &[]))
        .await
        .unwrap();
    assert_eq!(auth.resource.name, "otto-flags");
    assert_eq!(auth.scopes, ["flags:read"]);
}

// ---- code redemption and audience ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_empty_scope_request_yields_that_resources_defaults(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let (issued, ..) = code_flow(&db, FLAGS, &[]).await;
    assert_eq!(issued.scopes, ["flags:read"]);

    let principal = tokens::introspect(&db, &issued.access_token, FLAGS)
        .await
        .unwrap();
    assert_eq!(principal.scopes, ["flags:read"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_token_for_one_resource_is_refused_by_another(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let (issued, ..) = code_flow(&db, FLAGS, &["flags:write"]).await;
    let err = tokens::introspect(&db, &issued.access_token, FACTORY)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::WrongAudience), "{err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn redemption_refuses_a_different_requested_resource(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let req = authorize_req(&client_id, FLAGS, &[]);
    let code = oauth::issue_authorization_code(&db, &req, user, org)
        .await
        .unwrap();
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, Some(FACTORY))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn disabling_a_resource_stops_redemption_and_refresh(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;

    // A code issued before the resource was disabled cannot be redeemed after.
    let (user, org) = member(&db).await;
    let client_id = client(&db).await;
    let req = authorize_req(&client_id, FLAGS, &[]);
    let code = oauth::issue_authorization_code(&db, &req, user, org)
        .await
        .unwrap();
    resources::set_disabled(&db, FLAGS, true).await.unwrap();
    let err = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");

    // A refresh token issued while enabled cannot be redeemed after.
    resources::set_disabled(&db, FLAGS, false).await.unwrap();
    let req = authorize_req(&client_id, FLAGS, &[]);
    let code = oauth::issue_authorization_code(&db, &req, user, org)
        .await
        .unwrap();
    let (issued, _, _) = oauth::redeem_code(&db, &code, &client_id, REDIRECT, VERIFIER, None)
        .await
        .unwrap();
    resources::set_disabled(&db, FLAGS, true).await.unwrap();
    let refresh = issued.refresh_token.clone().unwrap();
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn refresh_refuses_a_different_requested_resource(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let (issued, client_id, ..) = code_flow(&db, FLAGS, &[]).await;
    let refresh = issued.refresh_token.clone().unwrap();
    let err = tokens::redeem_refresh(&db, &refresh, &client_id, Some(FACTORY))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidGrant(_)), "{err:?}");

    // Naming the right resource, or none, still works.
    let (rotated, ..) = tokens::redeem_refresh(&db, &refresh, &client_id, Some(FLAGS))
        .await
        .unwrap();
    assert_eq!(rotated.scopes, ["flags:read"]);
}

// ---- PATs ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn pats_obey_the_registry(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;
    let (user, org) = member(&db).await;

    let err = tokens::mint_pat(&db, user, org, "ci", &["jobs:write".into()], FLAGS, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidScope(_)), "{err:?}");

    let err = tokens::mint_pat(&db, user, org, "ci", &[], "https://nope.example/mcp", None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");

    let (pat, _) = tokens::mint_pat(&db, user, org, "ci", &[], FLAGS, None)
        .await
        .unwrap();
    let principal = tokens::introspect(&db, &pat, FLAGS).await.unwrap();
    assert_eq!(principal.scopes, ["flags:read"]);
}

// ---- introspection credentials ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn introspection_credentials_authenticate_only_their_resource(pool: PgPool) {
    let db = Db::from_pool(pool);
    register_both(&db).await;

    // No credential issued yet.
    let err = resources::authenticate_introspection(&db, FLAGS, "otto_rs_anything")
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidClient(_)), "{err:?}");

    let first = resources::rotate_introspection_secret(&db, FLAGS)
        .await
        .unwrap();
    assert!(first.starts_with(resources::INTROSPECTION_SECRET_PREFIX));
    let rs = resources::authenticate_introspection(&db, FLAGS, &first)
        .await
        .unwrap();
    assert_eq!(rs.resource_uri, FLAGS);

    // Another resource's URI with this credential fails.
    assert!(resources::authenticate_introspection(&db, FACTORY, &first)
        .await
        .is_err());

    // Rotation retires the old credential.
    let second = resources::rotate_introspection_secret(&db, FLAGS)
        .await
        .unwrap();
    assert!(resources::authenticate_introspection(&db, FLAGS, &first)
        .await
        .is_err());
    assert!(resources::authenticate_introspection(&db, FLAGS, &second)
        .await
        .is_ok());

    // Disabled servers cannot introspect.
    resources::set_disabled(&db, FLAGS, true).await.unwrap();
    assert!(resources::authenticate_introspection(&db, FLAGS, &second)
        .await
        .is_err());

    // Unknown resources fail the same way.
    let err = resources::authenticate_introspection(&db, "https://nope.example/mcp", &second)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidClient(_)), "{err:?}");
}
