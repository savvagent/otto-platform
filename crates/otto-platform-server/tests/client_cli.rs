//! `otto-platform-server client register`, end to end against a real database.

use otto_auth::{oauth, resources};
use otto_platform_server::client_cmd::{execute, parse};
use otto_platform_server::resource_cmd;
use otto_tenant::Db;
use sqlx::PgPool;

async fn run(db: &Db, line: &str) -> anyhow::Result<String> {
    let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let mut out = Vec::new();
    execute(db, parse(&args).unwrap(), &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_registers_a_first_party_client(pool: PgPool) {
    let db = Db::from_pool(pool);

    let out = run(
        &db,
        "register --name Console --redirect-uri https://console.example/cb --first-party",
    )
    .await
    .unwrap();
    let client_id = out.trim();
    assert!(client_id.starts_with("otto_client_"), "{out:?}");

    let client = oauth::get_client(&db, client_id).await.unwrap();
    assert!(client.first_party);
    assert_eq!(client.client_name.as_deref(), Some("Console"));
    assert_eq!(client.redirect_uris, vec!["https://console.example/cb"]);

    let dcr: bool =
        sqlx::query_scalar("SELECT registered_via_dcr FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(!dcr, "an operator-registered client did not come from DCR");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn first_party_is_opt_in(pool: PgPool) {
    let db = Db::from_pool(pool);

    let out = run(
        &db,
        "register --name Tool --redirect-uri http://127.0.0.1:1455/cb",
    )
    .await
    .unwrap();
    let client = oauth::get_client(&db, out.trim()).await.unwrap();
    assert!(!client.first_party);
}

/// The CLI shares DCR's redirect screening: an operator typo is not a way
/// around it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_cli_screens_redirect_uris_like_dynamic_registration(pool: PgPool) {
    let db = Db::from_pool(pool);

    for bad in [
        "http://console.example/cb",
        "https://console.example/cb#frag",
        "https://*.example/cb",
    ] {
        let err = run(
            &db,
            &format!("register --name X --redirect-uri {bad} --first-party"),
        )
        .await;
        assert!(err.is_err(), "{bad} was accepted");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// RFC 8252 section 8.6: a loopback callback always goes through consent, so
/// it cannot belong to a client that skips it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_first_party_client_cannot_have_a_loopback_redirect(pool: PgPool) {
    let db = Db::from_pool(pool);

    for uri in [
        "http://localhost/auth/callback",
        "http://127.0.0.1:3000/cb",
        "http://[::1]/cb",
    ] {
        let err = run(
            &db,
            &format!("register --name X --redirect-uri https://ok.example/cb --redirect-uri {uri} --first-party"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }
    // Still fine for an ordinary client.
    run(
        &db,
        "register --name Tool --redirect-uri http://127.0.0.1:1455/cb",
    )
    .await
    .unwrap();
}

// ---- `resource ... --scope-description` ----

async fn resource(db: &Db, args: &[&str]) -> anyhow::Result<String> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let mut out = Vec::new();
    resource_cmd::execute(db, None, resource_cmd::parse(&args).unwrap(), &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

const SVC: &str = "https://svc.example/mcp";

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_sets_and_replaces_scope_descriptions(pool: PgPool) {
    let db = Db::from_pool(pool);

    resource(
        &db,
        &[
            "register",
            SVC,
            "--name",
            "Svc",
            "--scopes",
            "a,b",
            "--scope-description",
            "a=Read the things",
            "--scope-description",
            "b=Write the things, carefully",
        ],
    )
    .await
    .unwrap();
    let rs = resources::get(&db, SVC).await.unwrap().unwrap();
    assert_eq!(rs.scope_description("a"), Some("Read the things"));
    assert_eq!(
        rs.scope_description("b"),
        Some("Write the things, carefully")
    );

    // Registering again without the flag keeps them.
    resource(
        &db,
        &["register", SVC, "--name", "Svc 2", "--scopes", "a,b"],
    )
    .await
    .unwrap();
    let rs = resources::get(&db, SVC).await.unwrap().unwrap();
    assert_eq!(rs.scope_descriptions.len(), 2);

    // `describe` replaces; `--clear` empties.
    resource(
        &db,
        &["describe", SVC, "--scope-description", "a=Only this"],
    )
    .await
    .unwrap();
    let rs = resources::get(&db, SVC).await.unwrap().unwrap();
    assert_eq!(rs.scope_descriptions.len(), 1);
    resource(&db, &["describe", SVC, "--clear"]).await.unwrap();
    assert!(resources::get(&db, SVC)
        .await
        .unwrap()
        .unwrap()
        .scope_descriptions
        .is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_refuses_a_description_for_an_unknown_scope(pool: PgPool) {
    let db = Db::from_pool(pool);
    resource(&db, &["register", SVC, "--name", "Svc", "--scopes", "a"])
        .await
        .unwrap();
    let err = resource(&db, &["describe", SVC, "--scope-description", "zzz=nope"])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("zzz"), "{err}");
}
