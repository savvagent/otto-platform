//! `otto-platform-server client register`, end to end against a real database.

use otto_auth::oauth;
use otto_platform_server::client_cmd::{execute, parse};
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
