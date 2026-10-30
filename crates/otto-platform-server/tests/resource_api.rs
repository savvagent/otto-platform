//! The resource-server surface end to end against a real database: RFC 7662
//! introspection, the internal usage and lookup API, lifecycle webhook
//! delivery, and `otto-resource`'s client talking to all of it over a socket.

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use otto_auth::resources::{self, ResourceServerSpec};
use otto_auth::tokens::{self, IssueParams};
use otto_core::orgs::{OrgsExt, Role};
use otto_core::teams::TeamsExt;
use otto_resource::{ClientConfig, PlatformClient, UsageEvent};
use otto_tenant::crypto::Cipher;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const FACTORY: &str = "https://otto-factory.example/mcp";
const FLAGS: &str = "https://otto-flags.example/mcp";

struct World {
    db: Db,
    factory_secret: String,
    flags_secret: String,
    org: OrgId,
    user: UserId,
}

async fn world(pool: PgPool) -> World {
    let db = Db::from_pool(pool);
    let mut secrets = Vec::new();
    for (uri, name, scope) in [
        (FACTORY, "otto-factory", "jobs:read"),
        (FLAGS, "otto-flags", "flags:read"),
    ] {
        resources::register(
            &db,
            ResourceServerSpec {
                resource_uri: uri,
                name,
                scopes: &[scope, "admin"],
                default_scopes: &[scope],
            },
        )
        .await
        .unwrap();
        secrets.push(
            resources::rotate_introspection_secret(&db, uri)
                .await
                .unwrap(),
        );
    }
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = db
        .upsert_user("dev@acme.example", Some("Dev"))
        .await
        .unwrap();
    db.add_member(org.id, user.id, Role::Admin).await.unwrap();
    // The org has authorized both resource servers, which usage ingest needs
    // (`not_authorized` otherwise, savvagent/otto-platform#79). The tokens
    // themselves are not used.
    for uri in [FACTORY, FLAGS] {
        authorize(&db, org.id, user.id, uri).await;
    }
    World {
        db,
        flags_secret: secrets.pop().unwrap(),
        factory_secret: secrets.pop().unwrap(),
        org: org.id,
        user: user.id,
    }
}

/// Have `org` authorize the resource server `resource`, as issuing it a token
/// does (`org_resource_grants`, recorded by a trigger), without leaving a
/// token behind for the tests that count them.
async fn authorize(db: &Db, org: OrgId, _user: UserId, resource: &str) {
    sqlx::query(
        "INSERT INTO org_resource_grants (org_id, resource_uri) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(org)
    .bind(resource)
    .execute(db.pool())
    .await
    .unwrap();
}

/// Both resource servers, for an org a test makes besides the world's.
async fn authorize_both(db: &Db, org: OrgId) {
    for uri in [FACTORY, FLAGS] {
        authorize(db, org, UserId::new(), uri).await;
    }
}

/// Have `org` authorize `resource` the real way: issue a token for it.
async fn authorize_with_token(db: &Db, org: OrgId, user: UserId, resource: &str) {
    tokens::issue(
        db,
        IssueParams {
            user_id: user,
            org_id: org,
            client_id: Some("agent"),
            scopes: &["admin".to_string()],
            resource,
            with_refresh: false,
        },
    )
    .await
    .unwrap();
}

impl World {
    async fn oauth_token(&self, resource: &str, scopes: &[&str]) -> String {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        tokens::issue(
            &self.db,
            IssueParams {
                user_id: self.user,
                org_id: self.org,
                client_id: Some("agent"),
                scopes: &scopes,
                resource,
                with_refresh: false,
            },
        )
        .await
        .unwrap()
        .access_token
    }

    fn factory_basic(&self) -> String {
        basic(FACTORY, &self.factory_secret)
    }
}

/// HTTP Basic as RFC 6749 §2.3.1 says: the client id is form-encoded first.
fn basic(uri: &str, secret: &str) -> String {
    let user = percent_encoding::utf8_percent_encode(uri, percent_encoding::NON_ALPHANUMERIC);
    format!("Basic {}", B64.encode(format!("{user}:{secret}")))
}

async fn send(db: &Db, req: Request<Body>) -> (StatusCode, Value) {
    let res = otto_platform_server::router(db.clone(), otto_platform_server::Billing::Enabled)
        .oneshot(req)
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn introspect(db: &Db, auth: Option<&str>, token: &str) -> (StatusCode, Value) {
    let mut req = Request::post("/oauth/introspect")
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let form = url_form(&[("token", token), ("token_type_hint", "access_token")]);
    send(db, req.body(Body::from(form)).unwrap()).await
}

fn url_form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}",
                percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

async fn get(db: &Db, auth: &str, path: &str) -> (StatusCode, Value) {
    send(
        db,
        Request::get(path)
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn post_usage(db: &Db, auth: &str, events: Vec<Value>) -> (StatusCode, Value) {
    send(
        db,
        Request::post("/internal/usage")
            .header("authorization", auth)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "events": events }).to_string()))
            .unwrap(),
    )
    .await
}

fn usage_event(org: OrgId, user: Option<UserId>, id: Uuid, billable: bool) -> Value {
    json!({
        "event_id": id,
        "org_id": org,
        "user_id": user,
        "tool": "flag.set",
        "billable": billable,
        "occurred_at": Utc::now(),
    })
}

// ------------------------------------------------------------ introspection

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_active_oauth_token_returns_its_claims(pool: PgPool) {
    let w = world(pool).await;
    let token = w.oauth_token(FACTORY, &["jobs:read", "admin"]).await;

    let (status, body) = introspect(&w.db, Some(&w.factory_basic()), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true);
    assert_eq!(body["sub"], w.user.to_string());
    assert_eq!(body["org_id"], w.org.to_string());
    assert_eq!(body["role"], "admin");
    assert_eq!(body["scope"], "jobs:read admin");
    assert_eq!(body["aud"], FACTORY);
    assert_eq!(body["client_id"], "agent");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["token_kind"], "oauth");
    assert!(body["exp"].as_i64().unwrap() > Utc::now().timestamp());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_token_for_another_resource_server_is_inactive(pool: PgPool) {
    let w = world(pool).await;
    let flags_token = w.oauth_token(FLAGS, &["flags:read"]).await;

    // The factory authenticates fine, but the token was minted for flags.
    let (status, body) = introspect(&w.db, Some(&w.factory_basic()), &flags_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "active": false }));

    // Flags itself still sees it.
    let (_, body) = introspect(&w.db, Some(&basic(FLAGS, &w.flags_secret)), &flags_token).await;
    assert_eq!(body["active"], true);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn revoked_unknown_and_expired_tokens_are_inactive(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();

    let revoked = w.oauth_token(FACTORY, &["jobs:read"]).await;
    tokens::revoke_presented(&w.db, &revoked).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &revoked).await.1,
        json!({ "active": false })
    );

    let expired = w.oauth_token(FACTORY, &["jobs:read"]).await;
    sqlx::query("UPDATE access_tokens SET expires_at = now() - interval '1 minute'")
        .execute(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &expired).await.1,
        json!({ "active": false })
    );

    let (status, body) = introspect(
        &w.db,
        Some(&auth),
        &otto_auth::crypto::generate(otto_auth::crypto::prefix::ACCESS).into_plaintext(),
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, json!({ "active": false })));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn personal_access_tokens_introspect_too(pool: PgPool) {
    let w = world(pool).await;
    let (pat, id) = tokens::mint_pat(
        &w.db,
        w.user,
        w.org,
        "ci",
        &["jobs:read".to_string()],
        FACTORY,
        Some(30),
    )
    .await
    .unwrap();

    let (_, body) = introspect(&w.db, Some(&w.factory_basic()), &pat).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["token_kind"], "pat");
    assert_eq!(body["jti"], id.to_string());
    assert_eq!(body["scope"], "jobs:read");

    let (_, other) = introspect(&w.db, Some(&basic(FLAGS, &w.flags_secret)), &pat).await;
    assert_eq!(other, json!({ "active": false }));
}

/// Point the stored token whose plaintext is `minted` at `presented` instead:
/// the row a token minted before the switch to Savvagent (#128) would be.
async fn rehash_access_token(db: &Db, minted: &str, presented: &str) {
    let n = sqlx::query("UPDATE access_tokens SET token_hash = $2 WHERE token_hash = $1")
        .bind(otto_auth::crypto::hash(minted))
        .bind(otto_auth::crypto::hash(presented))
        .execute(db.pool())
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(n, 1);
}

/// Savvagent (#128) is a hard switch: an access token or PAT minted under
/// `otto_at_`/`otto_pat_` is inactive, exactly as an unknown token is, even
/// with its row still live.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn access_tokens_and_pats_minted_before_savvagent_are_inactive(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let oauth = w.oauth_token(FACTORY, &["jobs:read"]).await;
    let (pat, _) = tokens::mint_pat(&w.db, w.user, w.org, "ci", &[], FACTORY, None)
        .await
        .unwrap();

    for (minted, new, old) in [
        (&oauth, "sav_at_", "otto_at_"),
        (&pat, "sav_pat_", "otto_pat_"),
    ] {
        assert_eq!(
            introspect(&w.db, Some(&auth), minted).await.1["active"],
            true
        );
        let retired = minted.replacen(new, old, 1);
        assert_ne!(&retired, minted);
        rehash_access_token(&w.db, minted, &retired).await;
        assert_eq!(
            introspect(&w.db, Some(&auth), &retired).await,
            (StatusCode::OK, json!({ "active": false })),
            "{old}"
        );
        // The row is untouched: put the new prefix back and it answers again.
        rehash_access_token(&w.db, &retired, minted).await;
        assert_eq!(
            introspect(&w.db, Some(&auth), minted).await.1["active"],
            true
        );
    }
}

/// Post a refresh grant for `refresh` to the token endpoint, which only the
/// assembled `app` serves (otto-web's router, not `router`).
async fn refresh_grant(db: &Db, refresh: &str) -> (StatusCode, Value) {
    let config = otto_platform_server::Config {
        database_url: "unused".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: "https://savvagent.test".into(),
        encryption_key: B64.encode([5u8; 32]),
        client_ip_header: None,
        enforce_quotas: false,
        static_dir: None,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
        email: None,
        stripe: None,
        usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
    };
    let res = otto_platform_server::app(db.clone(), &config)
        .unwrap()
        .oneshot(
            Request::post("https://savvagent.test/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(url_form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh),
                    ("client_id", "agent"),
                    ("resource", FACTORY),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A refresh token minted under `otto_rt_` gets the token endpoint's answer
/// for an unknown refresh token, even with its row still live, and the row is
/// neither consumed nor revoked by the attempt.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refresh_token_minted_before_savvagent_is_refused_at_the_token_endpoint(pool: PgPool) {
    let w = world(pool).await;
    let refresh = tokens::issue(
        &w.db,
        IssueParams {
            user_id: w.user,
            org_id: w.org,
            client_id: Some("agent"),
            scopes: &["jobs:read".to_string()],
            resource: FACTORY,
            with_refresh: true,
        },
    )
    .await
    .unwrap()
    .refresh_token
    .expect("issued with a refresh token");

    let retired = refresh.replacen("sav_rt_", "otto_rt_", 1);
    assert_ne!(retired, refresh);
    let n = sqlx::query("UPDATE refresh_tokens SET token_hash = $2 WHERE token_hash = $1")
        .bind(otto_auth::crypto::hash(&refresh))
        .bind(otto_auth::crypto::hash(&retired))
        .execute(w.db.pool())
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(n, 1);

    let unknown = otto_auth::crypto::generate(otto_auth::crypto::prefix::REFRESH).into_plaintext();
    let refused = refresh_grant(&w.db, &retired).await;
    assert_eq!(refused, refresh_grant(&w.db, &unknown).await);
    assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{}", refused.1);

    let (consumed, revoked): (Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT consumed_at, revoked_at FROM refresh_tokens WHERE token_hash = $1")
            .bind(otto_auth::crypto::hash(&retired))
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        (consumed, revoked),
        (None, None),
        "the refusal touched the row"
    );

    // Put the new prefix back and the same row refreshes.
    sqlx::query("UPDATE refresh_tokens SET token_hash = $2 WHERE token_hash = $1")
        .bind(otto_auth::crypto::hash(&retired))
        .bind(otto_auth::crypto::hash(&refresh))
        .execute(w.db.pool())
        .await
        .unwrap();
    let (status, body) = refresh_grant(&w.db, &refresh).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string(), "{body}");
}

/// Resource server credentials issued before the switch (`otto_rs_`
/// introspection secrets, `otto_whsec_` webhook keys) keep working until
/// phase 3 rotates each service's.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn resource_server_secrets_issued_before_savvagent_keep_working(pool: PgPool) {
    use std::sync::atomic::AtomicU16;

    let w = world(pool).await;
    assert!(w.factory_secret.starts_with("sav_rs_"));
    let old = w.factory_secret.replacen("sav_rs_", "otto_rs_", 1);
    sqlx::query(
        "UPDATE resource_servers SET introspection_secret_hash = $2 WHERE resource_uri = $1",
    )
    .bind(FACTORY)
    .bind(otto_auth::crypto::hash(&old))
    .execute(w.db.pool())
    .await
    .unwrap();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;
    for auth in [basic(FACTORY, &old), format!("Bearer {old}")] {
        let (status, body) = introspect(&w.db, Some(&auth), &token).await;
        assert_eq!(
            (status, &body["active"]),
            (StatusCode::OK, &json!(true)),
            "{auth}"
        );
    }

    // A webhook key issued under `otto_whsec_` still signs deliveries.
    let (url, received) = receiver(Arc::new(AtomicU16::new(204))).await;
    let cipher = cipher();
    let minted = resources::set_webhook(&w.db, &cipher, FACTORY, Some(&url))
        .await
        .unwrap()
        .unwrap();
    let old_key = minted.replacen("sav_whsec_", "otto_whsec_", 1);
    let sealed = cipher.seal(old_key.as_bytes()).unwrap();
    sqlx::query(
        "UPDATE resource_servers SET webhook_secret_ciphertext = $2, webhook_secret_nonce = $3 \
         WHERE resource_uri = $1",
    )
    .bind(FACTORY)
    .bind(sealed.ciphertext.as_slice())
    .bind(sealed.nonce.as_slice())
    .execute(w.db.pool())
    .await
    .unwrap();
    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = w.db.begin(w.org).await.unwrap();
    tx.delete_team(team.id).await.unwrap();
    tx.commit().await.unwrap();
    let http = otto_platform_server::webhooks::http_client().unwrap();
    otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
        .await
        .unwrap();
    let got = received.lock().unwrap();
    let (headers, body) = got.first().expect("no delivery");
    let sig = headers[otto_resource::webhook::SIGNATURE_HEADER]
        .to_str()
        .unwrap();
    otto_resource::webhook::verify(&old_key, sig, body).unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_removed_member_or_deleted_org_deactivates_the_token(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;
    assert_eq!(
        introspect(&w.db, Some(&auth), &token).await.1["active"],
        true
    );

    // Role changes are visible immediately.
    w.db.add_member(w.org, w.user, Role::Member).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &token).await.1["role"],
        "member"
    );

    w.db.remove_member(w.org, w.user).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &token).await.1,
        json!({ "active": false })
    );

    w.db.add_member(w.org, w.user, Role::Member).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &token).await.1["active"],
        true
    );
    w.db.delete_org(w.org).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&auth), &token).await.1,
        json!({ "active": false })
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn resource_server_credentials_are_required_and_checked(pool: PgPool) {
    let w = world(pool).await;
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    for auth in [
        None,
        Some(basic(FACTORY, "sav_rs_wrong")),
        // Flags' secret presented as the factory.
        Some(basic(FACTORY, &w.flags_secret)),
        Some(basic("https://nobody.example/mcp", &w.factory_secret)),
        Some("Bearer sav_rs_wrong".to_owned()),
        Some("Basic !!!not-base64".to_owned()),
    ] {
        let (status, body) = introspect(&w.db, auth.as_deref(), &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(body["error"], "invalid_client");
    }

    // Bearer <secret> identifies the server by itself.
    let (status, body) =
        introspect(&w.db, Some(&format!("Bearer {}", w.factory_secret)), &token).await;
    assert_eq!(
        (status, body["active"].clone()),
        (StatusCode::OK, json!(true))
    );

    // A disabled resource server is refused.
    resources::set_disabled(&w.db, FACTORY, true).await.unwrap();
    assert_eq!(
        introspect(&w.db, Some(&w.factory_basic()), &token).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn introspection_requires_a_token(pool: PgPool) {
    let w = world(pool).await;
    let (status, body) = introspect(&w.db, Some(&w.factory_basic()), "  ").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

// -------------------------------------------------------------------- usage

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_ingest_is_idempotent_on_event_id(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let batch = vec![
        usage_event(w.org, Some(w.user), a, true),
        usage_event(w.org, None, b, false),
    ];

    let (status, receipt) = post_usage(&w.db, &auth, batch.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt,
        json!({ "accepted": 2, "duplicates": 0, "rejected": [] })
    );

    // The response was "lost"; the shipper sends the same batch plus one new event.
    let mut replay = batch.clone();
    replay.push(usage_event(w.org, Some(w.user), Uuid::new_v4(), true));
    let (_, receipt) = post_usage(&w.db, &auth, replay).await;
    assert_eq!(
        receipt,
        json!({ "accepted": 1, "duplicates": 2, "rejected": [] })
    );

    let (_, status) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/usage-status", w.org),
    )
    .await;
    assert_eq!(status["billable_count"], 2);
    assert_eq!(status["total_count"], 3);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 3);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn event_ids_are_scoped_per_resource_server(pool: PgPool) {
    let w = world(pool).await;
    let id = Uuid::new_v4();
    let ev = vec![usage_event(w.org, None, id, true)];

    let (_, r1) = post_usage(&w.db, &w.factory_basic(), ev.clone()).await;
    let (_, r2) = post_usage(&w.db, &basic(FLAGS, &w.flags_secret), ev).await;
    assert_eq!(r1["accepted"], 1);
    assert_eq!(
        r2["accepted"], 1,
        "another server's identical uuid is a different event"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn unacceptable_events_are_rejected_without_failing_the_batch(pool: PgPool) {
    let w = world(pool).await;
    let ghost = OrgId::new();
    let bad_tool = Uuid::new_v4();
    let mut no_tool = usage_event(w.org, None, bad_tool, true);
    no_tool["tool"] = json!("  ");

    let (status, receipt) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![
            usage_event(w.org, None, Uuid::new_v4(), true),
            usage_event(ghost, None, Uuid::new_v4(), true),
            no_tool,
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["accepted"], 1);
    assert_eq!(receipt["rejected"].as_array().unwrap().len(), 2);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unknown_user_id_does_not_fail_the_event(pool: PgPool) {
    let w = world(pool).await;
    let (_, receipt) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![usage_event(
            w.org,
            Some(UserId::new()),
            Uuid::new_v4(),
            true,
        )],
    )
    .await;
    assert_eq!(receipt["accepted"], 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_status_reports_the_plan_and_its_features_and_oversized_batches_are_refused(
    pool: PgPool,
) {
    let w = world(pool).await;
    let auth = w.factory_basic();

    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/usage-status", w.org),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["plan"], "free");
    assert_eq!(body["included_ops"], 500);
    // The free plan's legacy hard stop is never served (#59): a family-wide
    // bucket would let one service's usage stop another's work.
    assert_eq!(body["hard_stop"], false);
    assert_eq!(body["billable_count"], 0);
    // The free plan unlocks nothing.
    assert_eq!(body["features"], serde_json::json!({}));

    // Every paid plan unlocks auto-rollback (0016_plan_features.sql).
    for plan in ["team", "business", "enterprise"] {
        sqlx::query("UPDATE orgs SET plan = $1::org_plan WHERE id = $2")
            .bind(plan)
            .bind(w.org.as_uuid())
            .execute(w.db.pool())
            .await
            .unwrap();
        let (status, body) = get(
            &w.db,
            &auth,
            &format!("/internal/orgs/{}/usage-status", w.org),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{plan}");
        assert_eq!(body["plan"], plan);
        assert_eq!(
            body["features"],
            serde_json::json!({"auto_rollback": true}),
            "{plan}"
        );
    }

    let (status, _) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/usage-status", Uuid::new_v4()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let events: Vec<Value> = (0..501)
        .map(|_| usage_event(w.org, None, Uuid::new_v4(), true))
        .collect();
    assert_eq!(
        post_usage(&w.db, &auth, events).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn internal_routes_require_the_resource_server_credential(pool: PgPool) {
    let w = world(pool).await;
    for path in [
        format!("/internal/orgs/{}/usage-status", w.org),
        format!("/internal/orgs/{}/members/{}", w.org, w.user),
        format!("/internal/orgs/{}/members/{}/teams", w.org, w.user),
        format!("/internal/orgs/{}/teams/{}", w.org, Uuid::new_v4()),
    ] {
        let (status, _) = send(&w.db, Request::get(&path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        let (status, _) = get(&w.db, "Bearer sav_rs_nope", &path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (status, _) = send(
        &w.db,
        Request::post("/internal/usage")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"events":[]}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ------------------------------------------------------------------ lookups

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn member_lookups_stay_inside_the_named_org(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let other_org = w.db.create_org("other", "Other").await.unwrap();

    let (status, body) = get(
        &w.db,
        &auth,
        &format!(
            "/internal/orgs/{}/members/by-email?email=DEV%40acme.example",
            w.org
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["id"], w.user.to_string());
    assert_eq!(body["user"]["email"], "dev@acme.example");
    assert_eq!(body["role"], "admin");
    assert_eq!(body["org"]["slug"], "acme");
    assert_eq!(body["org"]["plan"], "free");

    // The user exists, but not in that org: the same 404 as no account at all.
    let (in_other, _) = get(
        &w.db,
        &auth,
        &format!(
            "/internal/orgs/{}/members/by-email?email=dev%40acme.example",
            other_org.id
        ),
    )
    .await;
    let (no_account, _) = get(
        &w.db,
        &auth,
        &format!(
            "/internal/orgs/{}/members/by-email?email=ghost%40acme.example",
            w.org
        ),
    )
    .await;
    assert_eq!(
        (in_other, no_account),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND)
    );

    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/members/{}", w.org, w.user),
    )
    .await;
    assert_eq!(
        (status, body["role"].clone()),
        (StatusCode::OK, json!("admin"))
    );
    let (status, _) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/members/{}", other_org.id, w.user),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn team_lookups_require_the_team_to_be_in_the_org(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let other = w.db.create_org("other", "Other").await.unwrap();
    authorize_both(&w.db, other.id).await;

    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.commit().await.unwrap();

    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/teams/{}", w.org, team.id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["slug"], "platform");
    assert_eq!(body["org_id"], w.org.to_string());

    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/teams/by-slug/platform", w.org),
    )
    .await;
    assert_eq!(
        (status, body["id"].clone()),
        (StatusCode::OK, json!(team.id.to_string()))
    );

    for path in [
        format!("/internal/orgs/{}/teams/{}", other.id, team.id),
        format!("/internal/orgs/{}/teams/by-slug/platform", other.id),
        format!("/internal/orgs/{}/teams/{}", w.org, Uuid::new_v4()),
    ] {
        assert_eq!(
            get(&w.db, &auth, &path).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn member_teams_lists_only_this_orgs_teams_for_a_member(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let other = w.db.create_org("other", "Other").await.unwrap();
    authorize_both(&w.db, other.id).await;
    w.db.add_member(other.id, w.user, Role::Member)
        .await
        .unwrap();
    let stranger = w.db.upsert_user("x@elsewhere.example", None).await.unwrap();

    let mut tx = w.db.begin(w.org).await.unwrap();
    let zed = tx.create_team("zed", "Zed").await.unwrap();
    let alpha = tx.create_team("alpha", "Alpha").await.unwrap();
    tx.create_team("unjoined", "Unjoined").await.unwrap();
    tx.add_team_member(zed.id, w.user).await.unwrap();
    tx.add_team_member(alpha.id, w.user).await.unwrap();
    tx.commit().await.unwrap();
    // A team in the other org the same user belongs to must not leak.
    let mut tx = w.db.begin(other.id).await.unwrap();
    let foreign = tx.create_team("foreign", "Foreign").await.unwrap();
    tx.add_team_member(foreign.id, w.user).await.unwrap();
    tx.commit().await.unwrap();

    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/members/{}/teams", w.org, w.user),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let slugs: Vec<_> = body["teams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["slug"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(slugs, ["alpha", "zed"], "ordered by name, this org only");
    assert_eq!(body["teams"][0]["id"], alpha.id.to_string());
    assert_eq!(body["teams"][0]["name"], "Alpha");
    assert_eq!(body["teams"][0]["org_id"], w.org.to_string());

    // The other org sees only its own team.
    let (_, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/members/{}/teams", other.id, w.user),
    )
    .await;
    assert_eq!(body["teams"].as_array().unwrap().len(), 1);
    assert_eq!(body["teams"][0]["slug"], "foreign");

    // A member on no team: 200 and empty.
    w.db.add_member(w.org, stranger.id, Role::Member)
        .await
        .unwrap();
    let (status, body) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/members/{}/teams", w.org, stranger.id),
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, json!({"teams": []})));

    // Non-members, unknown users and unknown orgs are all the same 404.
    let outsider = w.db.upsert_user("o@elsewhere.example", None).await.unwrap();
    for path in [
        format!("/internal/orgs/{}/members/{}/teams", w.org, outsider.id),
        format!("/internal/orgs/{}/members/{}/teams", w.org, Uuid::new_v4()),
        format!("/internal/orgs/{}/members/{}/teams", Uuid::new_v4(), w.user),
    ] {
        assert_eq!(
            get(&w.db, &auth, &path).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

// ------------------------------------------------------- webhook delivery

type Received = Arc<Mutex<Vec<(axum::http::HeaderMap, Vec<u8>)>>>;

/// A receiver that records every request and answers with `status`.
async fn receiver(status: Arc<std::sync::atomic::AtomicU16>) -> (String, Received) {
    let received: Received = Arc::default();
    let sink = received.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let sink = sink.clone();
                let status = status.clone();
                async move {
                    sink.lock().unwrap().push((headers, body.to_vec()));
                    StatusCode::from_u16(status.load(std::sync::atomic::Ordering::SeqCst)).unwrap()
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, received)
}

fn cipher() -> Cipher {
    Cipher::from_base64_key(&B64.encode([9u8; 32])).unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn webhooks_are_signed_delivered_retried_and_deduplicable(pool: PgPool) {
    use std::sync::atomic::{AtomicU16, Ordering};

    let w = world(pool).await;
    let status = Arc::new(AtomicU16::new(500));
    let (url, received) = receiver(status.clone()).await;
    let cipher = cipher();
    let secret = resources::set_webhook(&w.db, &cipher, FACTORY, Some(&url))
        .await
        .unwrap()
        .unwrap();
    assert!(secret.starts_with("sav_whsec_"));

    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = w.db.begin(w.org).await.unwrap();
    tx.delete_team(team.id).await.unwrap();
    tx.commit().await.unwrap();

    let http = otto_platform_server::webhooks::http_client().unwrap();

    // First attempt: the receiver is down. Recorded and rescheduled.
    assert_eq!(
        otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
            .await
            .unwrap(),
        1
    );
    let (attempts, last_status, delivered): (i32, Option<i32>, bool) = sqlx::query_as(
        "SELECT attempts, last_status, delivered_at IS NOT NULL FROM webhook_deliveries",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!((attempts, last_status, delivered), (1, Some(500), false));
    // Not due again until the backoff elapses.
    assert_eq!(
        otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
            .await
            .unwrap(),
        0
    );

    // The receiver recovers and the backoff elapses.
    status.store(200, Ordering::SeqCst);
    sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = now()")
        .execute(w.db.pool())
        .await
        .unwrap();
    otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
        .await
        .unwrap();
    let delivered: bool =
        sqlx::query_scalar("SELECT delivered_at IS NOT NULL FROM webhook_deliveries")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert!(delivered);
    // Delivered rows are not delivered again.
    sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = now()")
        .execute(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
            .await
            .unwrap(),
        0
    );

    // Two attempts, both verifiable with the one secret, same event id.
    let got = received.lock().unwrap();
    assert_eq!(got.len(), 2);
    let events: Vec<_> = got
        .iter()
        .map(|(headers, body)| {
            let sig = headers[otto_resource::webhook::SIGNATURE_HEADER]
                .to_str()
                .unwrap();
            let ev = otto_resource::webhook::verify(&secret, sig, body).unwrap();
            assert_eq!(
                headers["otto-event-id"].to_str().unwrap(),
                ev.id.to_string()
            );
            assert_eq!(headers["otto-event-type"], "team.deleted");
            ev
        })
        .collect();
    assert_eq!(events[0].id, events[1].id);
    assert_eq!(
        events[0].event,
        otto_resource::webhook::LifecycleEvent::TeamDeleted {
            org_id: w.org.as_uuid(),
            team_id: team.id.as_uuid(),
        }
    );
    // A different secret does not verify.
    let (headers, body) = &got[0];
    let sig = headers[otto_resource::webhook::SIGNATURE_HEADER]
        .to_str()
        .unwrap();
    assert!(otto_resource::webhook::verify("sav_whsec_other", sig, body).is_err());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn every_event_kind_round_trips_through_delivery(pool: PgPool) {
    use otto_resource::webhook::LifecycleEvent;
    use std::sync::atomic::AtomicU16;

    let w = world(pool).await;
    let (url, received) = receiver(Arc::new(AtomicU16::new(204))).await;
    let cipher = cipher();
    let secret = resources::set_webhook(&w.db, &cipher, FLAGS, Some(&url))
        .await
        .unwrap()
        .unwrap();

    let member = w.db.upsert_user("m@acme.example", None).await.unwrap();
    w.db.add_member(w.org, member.id, Role::Member)
        .await
        .unwrap();
    w.db.remove_member(w.org, member.id).await.unwrap();
    w.db.delete_org(w.org).await.unwrap();

    let http = otto_platform_server::webhooks::http_client().unwrap();
    otto_platform_server::webhooks::deliver_due(&w.db, &cipher, &http)
        .await
        .unwrap();

    let mut kinds: Vec<LifecycleEvent> = received
        .lock()
        .unwrap()
        .iter()
        .map(|(h, b)| {
            otto_resource::webhook::verify(
                &secret,
                h[otto_resource::webhook::SIGNATURE_HEADER]
                    .to_str()
                    .unwrap(),
                b,
            )
            .unwrap()
            .event
        })
        .collect();
    kinds.sort_by_key(|e| format!("{e:?}"));
    assert_eq!(
        kinds,
        [
            LifecycleEvent::MemberRemoved {
                org_id: w.org.as_uuid(),
                user_id: member.id.as_uuid()
            },
            LifecycleEvent::OrgDeleted {
                org_id: w.org.as_uuid()
            },
        ]
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn webhook_config_is_validated_and_clearable(pool: PgPool) {
    let w = world(pool).await;
    let cipher = cipher();
    for bad in [
        "http://hooks.example/x",
        "ftp://x.example",
        "https://u:p@x.example/h",
        "nonsense",
    ] {
        assert!(
            resources::set_webhook(&w.db, &cipher, FACTORY, Some(bad))
                .await
                .is_err(),
            "{bad}"
        );
    }
    assert!(resources::set_webhook(
        &w.db,
        &cipher,
        "https://nope.example/mcp",
        Some("https://x.example/h")
    )
    .await
    .is_err());

    assert!(
        resources::set_webhook(&w.db, &cipher, FACTORY, Some("https://x.example/h"))
            .await
            .unwrap()
            .is_some()
    );
    let rs = resources::get(&w.db, FACTORY).await.unwrap().unwrap();
    assert_eq!(rs.webhook_url.as_deref(), Some("https://x.example/h"));

    assert!(resources::set_webhook(&w.db, &cipher, FACTORY, None)
        .await
        .unwrap()
        .is_none());
    assert!(resources::get(&w.db, FACTORY)
        .await
        .unwrap()
        .unwrap()
        .webhook_url
        .is_none());

    // With no webhook there is nothing to fan out to.
    w.db.delete_org(w.org).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

// ------------------------------------------------------ the otto-resource client

async fn serve(db: &Db) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = otto_platform_server::router(db.clone(), otto_platform_server::Billing::Enabled);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_introspects_and_caches_positive_results(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let client = PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    let claims = client.introspect(&token).await.unwrap().expect("active");
    assert_eq!(claims.user_id, w.user.as_uuid());
    assert_eq!(claims.org_id, w.org.as_uuid());
    assert_eq!(claims.role, otto_resource::Role::Admin);
    assert!(claims.has_scope("jobs:read") && !claims.has_scope("admin"));
    assert_eq!(claims.resource, FACTORY);
    assert_eq!(claims.kind, otto_resource::TokenKind::Oauth);

    // Revoked at the platform, still trusted from cache: the documented bound.
    tokens::revoke_presented(&w.db, &token).await.unwrap();
    assert_eq!(
        client.introspect(&token).await.unwrap().as_ref(),
        Some(&claims)
    );

    // A client with no cache sees the revocation.
    let fresh = PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();
    assert!(fresh.introspect(&token).await.unwrap().is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_remembers_negatives_only_briefly(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let mut cfg = ClientConfig::new(&base, FACTORY, &w.factory_secret);
    cfg.negative_ttl = std::time::Duration::from_millis(150);
    let client = PlatformClient::new(cfg).unwrap();

    // Not yet a token...
    let token = &otto_auth::crypto::generate(otto_auth::crypto::prefix::ACCESS).into_plaintext();
    assert!(client.introspect(token).await.unwrap().is_none());
    // ...then it becomes one (its hash is registered out of band).
    sqlx::query(
        "INSERT INTO access_tokens (token_hash, user_id, org_id, scopes, resource, expires_at) \
         VALUES ($1, $2, $3, '{jobs:read}', $4, now() + interval '1 hour')",
    )
    .bind(otto_auth::crypto::hash(token))
    .bind(w.user)
    .bind(w.org)
    .bind(FACTORY)
    .execute(w.db.pool())
    .await
    .unwrap();

    assert!(
        client.introspect(token).await.unwrap().is_none(),
        "negative still cached"
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(client.introspect(token).await.unwrap().is_some());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_reports_bad_credentials_as_errors_not_inactive_tokens(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    let client = PlatformClient::new(ClientConfig::new(&base, FACTORY, "sav_rs_wrong")).unwrap();
    assert!(matches!(
        client.introspect(&token).await,
        Err(otto_resource::Error::Unauthorized)
    ));

    let down = PlatformClient::new(ClientConfig::new("http://127.0.0.1:1", FACTORY, "x")).unwrap();
    let err = down.introspect(&token).await.unwrap_err();
    assert!(err.is_retriable(), "{err}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_ships_usage_and_reads_status_lookups(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let client = PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();

    let events: Vec<UsageEvent> = (0..3)
        .map(|i| UsageEvent {
            event_id: Uuid::new_v4(),
            org_id: w.org.as_uuid(),
            user_id: Some(w.user.as_uuid()),
            tool: "queue.enqueue".into(),
            billable: i != 0,
            occurred_at: Utc::now(),
            service: None,
            meter: None,
            quantity: None,
        })
        .collect();
    let receipt = client.ship_usage(&events).await.unwrap();
    assert_eq!((receipt.accepted, receipt.duplicates), (3, 0));
    let again = client.ship_usage(&events).await.unwrap();
    assert_eq!((again.accepted, again.duplicates), (0, 3));

    let status = client.usage_status(w.org.as_uuid()).await.unwrap();
    assert_eq!((status.billable_count, status.total_count), (2, 3));
    assert_eq!(status.included_ops, 500);
    assert!(!status.is_blocked());

    // Cached for the TTL: more usage does not show up yet.
    client
        .ship_usage(&[UsageEvent {
            event_id: Uuid::new_v4(),
            ..events[1].clone()
        }])
        .await
        .unwrap();
    assert_eq!(
        client
            .usage_status(w.org.as_uuid())
            .await
            .unwrap()
            .billable_count,
        2
    );

    assert!(matches!(
        client.usage_status(Uuid::new_v4()).await,
        Err(otto_resource::Error::NotFound)
    ));

    let member = client
        .member(w.org.as_uuid(), w.user.as_uuid())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.role, otto_resource::Role::Admin);
    assert_eq!(member.org.slug, "acme");
    let by_email = client
        .member_by_email(w.org.as_uuid(), "dev@acme.example")
        .await
        .unwrap();
    assert_eq!(by_email, Some(member));
    assert!(client
        .member_by_email(w.org.as_uuid(), "x+y@acme.example")
        .await
        .unwrap()
        .is_none());
    assert!(client
        .team(w.org.as_uuid(), Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
    assert!(client
        .team_by_slug(w.org.as_uuid(), "nope")
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_lists_member_teams(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let client = PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();
    let org = w.org.as_uuid();

    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.add_team_member(team.id, w.user).await.unwrap();
    tx.commit().await.unwrap();

    let teams = client
        .member_teams(org, w.user.as_uuid())
        .await
        .unwrap()
        .expect("member");
    assert_eq!(teams.len(), 1);
    assert_eq!(
        (teams[0].id, teams[0].slug.as_str(), teams[0].name.as_str()),
        (team.id.as_uuid(), "platform", "Platform")
    );
    assert!(client
        .member_teams(org, Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        client.usage_page_url("acme"),
        format!("{base}/o/acme/usage")
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn member_lookups_are_cached_briefly_and_expire(pool: PgPool) {
    // No assertion here depends on how quickly the test runs. "Cached" is
    // proven with a TTL far longer than any test, "expires" with a short TTL
    // that is only ever waited *past* (polling, never racing a deadline).
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let long_ttl = std::time::Duration::from_secs(3600);
    let mut cfg = ClientConfig::new(&base, FACTORY, &w.factory_secret);
    cfg.member_ttl = long_ttl;
    cfg.member_negative_ttl = long_ttl;
    let client = PlatformClient::new(cfg).unwrap();
    let mut cfg = ClientConfig::new(&base, FACTORY, &w.factory_secret);
    cfg.member_ttl = std::time::Duration::from_millis(100);
    cfg.member_negative_ttl = std::time::Duration::from_millis(100);
    let short = PlatformClient::new(cfg).unwrap();
    let (org, user) = (w.org.as_uuid(), w.user.as_uuid());

    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.add_team_member(team.id, w.user).await.unwrap();
    tx.commit().await.unwrap();
    let newcomer = w.db.upsert_user("new@acme.example", None).await.unwrap();

    // Both clients see (and remember) the initial state.
    for c in [&client, &short] {
        assert_eq!(
            c.member(org, user).await.unwrap().unwrap().role,
            otto_resource::Role::Admin
        );
        assert_eq!(c.member_teams(org, user).await.unwrap().unwrap().len(), 1);
        // Not a member yet; remembered.
        assert!(c
            .member(org, newcomer.id.as_uuid())
            .await
            .unwrap()
            .is_none());
    }

    // Platform-side changes are invisible while the entries are fresh...
    w.db.add_member(w.org, newcomer.id, Role::Member)
        .await
        .unwrap();
    let mut tx = w.db.begin(w.org).await.unwrap();
    tx.remove_team_member(team.id, w.user).await.unwrap();
    tx.commit().await.unwrap();
    w.db.add_member(w.org, w.user, Role::Member).await.unwrap();
    assert_eq!(
        client.member(org, user).await.unwrap().unwrap().role,
        otto_resource::Role::Admin
    );
    assert_eq!(
        client.member_teams(org, user).await.unwrap().unwrap().len(),
        1
    );
    assert!(client
        .member(org, newcomer.id.as_uuid())
        .await
        .unwrap()
        .is_none());

    // ...and visible once they expire. Poll rather than sleep a fixed time, so
    // a slow machine only makes this wait longer, never fail.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let role = short.member(org, user).await.unwrap().unwrap().role;
        let teams = short.member_teams(org, user).await.unwrap().unwrap();
        let newcomer_in = short
            .member(org, newcomer.id.as_uuid())
            .await
            .unwrap()
            .is_some();
        if role == otto_resource::Role::Member && teams.is_empty() && newcomer_in {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cached entries never expired"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // A zero TTL disables caching altogether.
    let mut cfg = ClientConfig::new(&base, FACTORY, &w.factory_secret);
    cfg.member_ttl = std::time::Duration::ZERO;
    let uncached = PlatformClient::new(cfg).unwrap();
    assert!(uncached.member(org, user).await.unwrap().is_some());
    w.db.remove_member(w.org, w.user).await.unwrap();
    assert!(uncached.member(org, user).await.unwrap().is_none());
    assert!(uncached.member_teams(org, user).await.unwrap().is_none());
}

#[test]
fn usage_status_blocking_rules() {
    let mut s = otto_resource::UsageStatus {
        org_id: Uuid::new_v4(),
        plan: "free".into(),
        period_start: Utc::now().date_naive(),
        billable_count: 499,
        total_count: 600,
        included_ops: 500,
        hard_stop: true,
        features: Default::default(),
        service: None,
        meters: Vec::new(),
        budget: None,
        blocked_reason: None,
    };
    assert!(!s.is_blocked());
    assert!(!s.budget_exceeded(), "no budget never blocks");
    assert!(!s.billable_blocked());
    s.billable_count = 500;
    assert!(s.is_blocked());
    assert!(
        !s.billable_blocked(),
        "the legacy bucket is not a reason to refuse"
    );
    s.hard_stop = false;
    assert!(!s.is_blocked() && s.over_limit());
    s.blocked_reason = Some(otto_resource::PAYMENT_REQUIRED.into());
    assert!(s.billable_blocked() && !s.budget_exceeded());
    // Absent from the wire when unset, for older clients.
    s.blocked_reason = None;
    assert!(serde_json::to_value(&s)
        .unwrap()
        .get("blocked_reason")
        .is_none());
}

#[test]
fn only_a_json_true_enables_a_feature() {
    let s: otto_resource::UsageStatus = serde_json::from_value(serde_json::json!({
        "org_id": Uuid::new_v4(),
        "plan": "team",
        "period_start": "2026-10-01",
        "billable_count": 0,
        "total_count": 0,
        "included_ops": 10000,
        "hard_stop": false,
        "features": {"on": true, "off": false, "count": 20, "text": "true"},
    }))
    .unwrap();
    assert!(s.feature_enabled("on"));
    for off in ["off", "count", "text", "missing"] {
        assert!(!s.feature_enabled(off), "{off}");
    }
}

#[test]
fn a_platform_without_features_grants_none() {
    // The body an older platform sends: no `features` at all.
    let s: otto_resource::UsageStatus = serde_json::from_value(serde_json::json!({
        "org_id": Uuid::new_v4(),
        "plan": "business",
        "period_start": "2026-10-01",
        "billable_count": 0,
        "total_count": 0,
        "included_ops": 100000,
        "hard_stop": false,
    }))
    .unwrap();
    assert!(s.features.is_empty());
    assert!(!s.feature_enabled("auto_rollback"));
}

// ---------------------------------------------------------------------- CLI

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_provisions_a_working_resource_server(pool: PgPool) {
    use otto_platform_server::resource_cmd::{execute, parse};

    let db = Db::from_pool(pool);
    let cipher = cipher();
    let run = |line: &str| {
        let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let cmd = parse(&args).unwrap();
        let db = db.clone();
        let cipher = cipher.clone();
        async move {
            let mut out = Vec::new();
            execute(&db, Some(&cipher), cmd, &mut out).await.unwrap();
            String::from_utf8(out).unwrap()
        }
    };
    let secret_in = |out: &str, prefix: &str| {
        out.lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix} secret in {out:?}"))
            .to_owned()
    };

    run(&format!("register {FLAGS} --name otto-flags --scopes flags:read,flags:write --default-scopes flags:read")).await;
    let secret = secret_in(&run(&format!("rotate-secret {FLAGS}")).await, "sav_rs_");
    let hook = run(&format!("set-webhook {FLAGS} https://flags.example/hooks")).await;
    secret_in(&hook, "sav_whsec_");
    assert!(run("list")
        .await
        .contains("webhook=https://flags.example/hooks"));

    // The printed credential is the one the API accepts.
    let org = db.create_org("acme", "Acme").await.unwrap();
    let (status, _) = get(
        &db,
        &basic(FLAGS, &secret),
        &format!("/internal/orgs/{}/usage-status", org.id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Rotating invalidates the previous one.
    let newer = secret_in(&run(&format!("rotate-secret {FLAGS}")).await, "sav_rs_");
    assert_ne!(secret, newer);
    let (status, _) = get(
        &db,
        &basic(FLAGS, &secret),
        &format!("/internal/orgs/{}/usage-status", org.id),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    run(&format!("set-webhook {FLAGS} --clear")).await;
    assert!(run("list").await.contains("webhook=-"));

    let mut out = Vec::new();
    let no_key = execute(
        &db,
        None,
        parse(&[
            "set-webhook".into(),
            FLAGS.into(),
            "https://flags.example/h".into(),
        ])
        .unwrap(),
        &mut out,
    )
    .await;
    assert!(
        no_key.is_err(),
        "storing a signing secret needs SAVVAGENT_ENCRYPTION_KEY"
    );
}

// ------------------------------------------------- usage bounds and replays

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_outside_the_accepted_window_is_rejected_not_counted(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let at = |when: chrono::DateTime<Utc>| {
        let mut ev = usage_event(w.org, None, Uuid::new_v4(), true);
        ev["occurred_at"] = json!(when);
        ev
    };
    let now = Utc::now();
    let too_old = otto_billing::usage::earliest_occurred_at(now) - chrono::Duration::seconds(1);

    let (_, receipt) = post_usage(
        &w.db,
        &auth,
        vec![
            at(too_old),
            at(now + chrono::Duration::minutes(6)),
            // Both bounds are inclusive of the edge.
            at(otto_billing::usage::earliest_occurred_at(now)),
            at(now + chrono::Duration::minutes(4)),
        ],
    )
    .await;
    assert_eq!(receipt["accepted"], 2, "{receipt}");
    let reasons: Vec<&str> = receipt["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons.len(), 2);
    assert!(reasons.iter().any(|r| r.contains("older")));
    assert!(reasons.iter().any(|r| r.contains("future")));

    // A rejected event leaves no trace, so it can be corrected and resent
    // under the same id.
    let id = Uuid::new_v4();
    let mut ev = usage_event(w.org, None, id, true);
    ev["occurred_at"] = json!(too_old);
    assert_eq!(post_usage(&w.db, &auth, vec![ev]).await.1["accepted"], 0);
    let (_, receipt) = post_usage(&w.db, &auth, vec![usage_event(w.org, None, id, true)]).await;
    assert_eq!(receipt["accepted"], 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_late_event_is_accepted_and_counted_in_an_open_month(pool: PgPool) {
    use otto_billing::period::{self, Month};

    let w = world(pool).await;
    let when = otto_billing::usage::earliest_occurred_at(Utc::now()) + chrono::Duration::hours(1);
    let mut ev = usage_event(w.org, None, Uuid::new_v4(), true);
    ev["occurred_at"] = json!(when);
    assert_eq!(
        post_usage(&w.db, &w.factory_basic(), vec![ev]).await.1["accepted"],
        1,
        "a late event is accepted whatever its month"
    );

    let periods: Vec<(chrono::NaiveDate, i64)> =
        sqlx::query_as("SELECT period_start, billable_count FROM org_period_usage")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    // The month it happened in, while that month is open (the first two
    // hours of the next); after that, the month it arrived in.
    let now = Utc::now();
    let expected = if period::period_closed(Month::of(when), now) {
        now.date_naive().with_day_one()
    } else {
        when.date_naive().with_day_one()
    };
    assert_eq!(periods, [(expected, 1)]);
}

trait WithDayOne {
    fn with_day_one(self) -> Self;
}
impl WithDayOne for chrono::NaiveDate {
    fn with_day_one(self) -> Self {
        use chrono::Datelike;
        self.with_day(1).unwrap()
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_event_id_replayed_under_another_org_is_rejected(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let other = w.db.create_org("other", "Other").await.unwrap();
    authorize_both(&w.db, other.id).await;
    let id = Uuid::new_v4();

    let (_, first) = post_usage(&w.db, &auth, vec![usage_event(w.org, None, id, true)]).await;
    assert_eq!(first["accepted"], 1);

    let (_, replay) = post_usage(&w.db, &auth, vec![usage_event(other.id, None, id, true)]).await;
    assert_eq!(replay["accepted"], 0);
    assert_eq!(replay["duplicates"], 0);
    assert_eq!(replay["rejected"][0]["event_id"], id.to_string());
    assert!(replay["rejected"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("different org"));

    let (_, status) = get(
        &w.db,
        &auth,
        &format!("/internal/orgs/{}/usage-status", other.id),
    )
    .await;
    assert_eq!(status["total_count"], 0);

    // The same org replaying is still a plain duplicate.
    let (_, same) = post_usage(&w.db, &auth, vec![usage_event(w.org, None, id, true)]).await;
    assert_eq!(
        (same["accepted"].clone(), same["duplicates"].clone()),
        (json!(0), json!(1))
    );
}

// ------------------------------------------------------------ client hygiene

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn every_token_the_platform_mints_passes_the_clients_shape_filter(pool: PgPool) {
    let w = world(pool).await;
    let oauth = w.oauth_token(FACTORY, &["jobs:read"]).await;
    let (pat, _) = tokens::mint_pat(&w.db, w.user, w.org, "ci", &[], FACTORY, None)
        .await
        .unwrap();
    assert!(oauth.starts_with("sav_at_"), "{oauth}");
    assert!(pat.starts_with("sav_pat_"), "{pat}");
    assert!(otto_resource::looks_like_token(&oauth), "{oauth}");
    assert!(otto_resource::looks_like_token(&pat), "{pat}");

    // The same tokens under the prefixes Savvagent (#128) retired do not.
    let retired_oauth = oauth.replacen("sav_at_", "otto_at_", 1);
    let retired_pat = pat.replacen("sav_pat_", "otto_pat_", 1);
    for junk in [
        "",
        "Bearer x",
        "sav_at_short",
        "sav_rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sav_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sav_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!A",
        &retired_oauth,
        &retired_pat,
    ] {
        assert!(!otto_resource::looks_like_token(junk), "{junk:?}");
    }
}

#[tokio::test]
async fn implausible_tokens_are_inactive_without_a_network_call() {
    // Nothing listens here: any request would be a transport error.
    let client =
        PlatformClient::new(ClientConfig::new("http://127.0.0.1:1", FACTORY, "x")).unwrap();
    assert!(client.introspect("not-a-token").await.unwrap().is_none());
    assert!(client.introspect("sav_at_x").await.unwrap().is_none());
    // A well-formed token under a prefix Savvagent (#128) retired.
    let retired = format!("otto_at_{}", "A".repeat(43));
    assert!(client.introspect(&retired).await.unwrap().is_none());
}

#[test]
fn a_response_for_another_audience_is_not_trusted() {
    let mut r = otto_resource::IntrospectionResponse {
        active: true,
        sub: Some(Uuid::new_v4()),
        org_id: Some(Uuid::new_v4()),
        role: Some(otto_resource::Role::Member),
        scope: Some("a".into()),
        aud: Some(FLAGS.into()),
        exp: Some(Utc::now().timestamp() + 60),
        client_id: None,
        token_type: Some("Bearer".into()),
        token_kind: Some(otto_resource::TokenKind::Oauth),
        jti: Some(Uuid::new_v4()),
    };
    assert!(r.clone().into_claims(FACTORY).is_none());
    assert!(r.clone().into_claims(FLAGS).is_some());
    r.aud = None;
    assert!(r.into_claims(FLAGS).is_none());
}

// ------------------------------------------------- the assembled application

/// otto-web's CSRF guard wraps only its own router. Resource-server calls
/// reach the same assembled `app`, and must work whatever `Origin` they carry
/// and even with a (stray) session cookie, which the guard would refuse on a
/// cookie-bearing write from a foreign origin.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn resource_server_calls_are_not_subject_to_the_browser_csrf_guard(pool: PgPool) {
    let w = world(pool).await;
    let config = otto_platform_server::Config {
        database_url: "unused".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: "https://otto.test".into(),
        encryption_key: B64.encode([5u8; 32]),
        client_ip_header: None,
        enforce_quotas: false,
        static_dir: None,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
        email: None,
        stripe: None,
        usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
    };
    let app = || otto_platform_server::app(w.db.clone(), &config).unwrap();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    // Control: the guard is live on the browser surface for this same request shape.
    let res = app()
        .oneshot(
            Request::post("/api/auth/logout")
                .header("origin", "https://evil.example")
                .header("cookie", "__Host-savvagent_session=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app()
        .oneshot(
            Request::post("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", w.factory_basic())
                .header("origin", "https://evil.example")
                .header("sec-fetch-site", "cross-site")
                .header("cookie", "__Host-savvagent_session=x")
                .body(Body::from(url_form(&[("token", &token)])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["active"],
        true
    );

    let res = app()
        .oneshot(
            Request::post("/internal/usage")
                .header("content-type", "application/json")
                .header("authorization", w.factory_basic())
                .header("origin", "https://evil.example")
                .body(Body::from(r#"{"events":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// The Savvagent cutover (savvagent/otto-platform#131) moves the public URL,
/// and with it the issuer and the CSRF origin, to `https://savvagent.com`,
/// while resource servers not yet repointed keep calling
/// `https://otto.savvagent.com`. Nothing may check the `Host` of those calls
/// against the public URL: introspection, the token endpoint and the internal
/// API must answer on the old host exactly as on the new one.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_old_host_keeps_answering_server_to_server_calls_after_the_cutover(pool: PgPool) {
    let w = world(pool).await;
    let config = otto_platform_server::Config {
        database_url: "unused".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: "https://savvagent.com".into(),
        encryption_key: B64.encode([5u8; 32]),
        client_ip_header: None,
        enforce_quotas: false,
        static_dir: None,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
        email: None,
        stripe: None,
        usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
    };
    let app = || otto_platform_server::app(w.db.clone(), &config).unwrap();
    const OLD_HOST: &str = "otto.savvagent.com";

    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;
    let res = app()
        .oneshot(
            Request::post("https://otto.savvagent.com/oauth/introspect")
                .header("host", OLD_HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", w.factory_basic())
                .body(Body::from(url_form(&[("token", &token)])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["active"], true, "{body}");

    // A refresh, which is what an agent holding a token from before the
    // cutover does against the token endpoint it was given.
    let issued = tokens::issue(
        &w.db,
        IssueParams {
            user_id: w.user,
            org_id: w.org,
            client_id: Some("agent"),
            scopes: &["jobs:read".to_string()],
            resource: FACTORY,
            with_refresh: true,
        },
    )
    .await
    .unwrap();
    let refresh = issued.refresh_token.expect("issued with a refresh token");
    let res = app()
        .oneshot(
            Request::post("https://otto.savvagent.com/oauth/token")
                .header("host", OLD_HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(url_form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh),
                    ("client_id", "agent"),
                    ("resource", FACTORY),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string(), "{body}");

    let res = app()
        .oneshot(
            Request::post("https://otto.savvagent.com/internal/usage")
                .header("host", OLD_HOST)
                .header("content-type", "application/json")
                .header("authorization", w.factory_basic())
                .body(Body::from(r#"{"events":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // And the discovery document names the new issuer whichever host serves
    // it, which is why resource servers must be repointed (cutover step 7).
    let res = app()
        .oneshot(
            Request::get("https://otto.savvagent.com/.well-known/oauth-authorization-server")
                .header("host", OLD_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["issuer"], "https://savvagent.com", "{body}");
}

// ------------------------------------------------------------------ meters

async fn put_meters(db: &Db, auth: &str, meters: Value) -> (StatusCode, Value) {
    send(
        db,
        Request::put("/internal/meters")
            .header("authorization", auth)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "meters": meters }).to_string()))
            .unwrap(),
    )
    .await
}

async fn stored_meters(db: &Db, service: &str) -> Vec<otto_billing::meters::Meter> {
    let mut tx = db.begin_unpinned().await.unwrap();
    otto_billing::meters::list_meters(&mut tx, service)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn meters_can_only_be_declared_under_the_callers_own_service(pool: PgPool) {
    let w = world(pool).await;
    resources::set_service(&w.db, FLAGS, "otto-flags")
        .await
        .unwrap();
    resources::set_service(&w.db, FACTORY, "otto-factory")
        .await
        .unwrap();
    let flags = basic(FLAGS, &w.flags_secret);

    let (status, body) = put_meters(
        &w.db,
        &flags,
        json!([
            {"key": "otto-flags/evaluations", "display_name": "Flag evaluations", "unit": "evaluation"},
            {"key": "otto-factory/jobs", "display_name": "Jobs", "unit": "job"},
            {"key": "otto-flags-x/evaluations", "display_name": "X", "unit": "x"},
            {"key": "evaluations", "display_name": "X", "unit": "x"},
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["declared"], json!(["otto-flags/evaluations"]));
    let rejected: Vec<&str> = body["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(
        rejected,
        [
            "otto-factory/jobs",
            "otto-flags-x/evaluations",
            "evaluations"
        ]
    );
    for r in body["rejected"].as_array().unwrap() {
        assert!(
            r["reason"].as_str().unwrap().contains("otto-flags/<meter>"),
            "{r}"
        );
    }

    // Nothing was written into another service's namespace.
    assert!(stored_meters(&w.db, "otto-factory").await.is_empty());
    let mine = stored_meters(&w.db, "otto-flags").await;
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].meter, "evaluations");
    assert_eq!(mine[0].display_name, "Flag evaluations");
    assert_eq!(mine[0].unit, "evaluation");

    // The declaring route takes the same credential as every /internal route.
    let (status, _) = put_meters(&w.db, "Bearer sav_rs_nope", json!([])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn redeclaring_meters_is_idempotent_and_updates_what_changed(pool: PgPool) {
    let w = world(pool).await;
    resources::set_service(&w.db, FLAGS, "otto-flags")
        .await
        .unwrap();
    let flags = basic(FLAGS, &w.flags_secret);
    let decl = json!([
        {"key": "otto-flags/evaluations", "display_name": "Flag evaluations", "unit": "evaluation"},
        {"key": "otto-flags/rollbacks", "display_name": "Auto-rollbacks", "unit": "rollback"},
    ]);

    let (status, first) = put_meters(&w.db, &flags, decl.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let before = stored_meters(&w.db, "otto-flags").await;

    let (status, again) = put_meters(&w.db, &flags, decl).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, again);
    assert_eq!(again["rejected"], json!([]));
    assert_eq!(
        stored_meters(&w.db, "otto-flags").await,
        before,
        "an unchanged declaration changes nothing, timestamps included"
    );

    // A changed unit replaces the stored one; a meter left out stays.
    let (status, body) = put_meters(
        &w.db,
        &flags,
        json!([{"key": "otto-flags/evaluations", "display_name": " Evaluations ", "unit": "1k evaluations"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["declared"], json!(["otto-flags/evaluations"]));
    let after = stored_meters(&w.db, "otto-flags").await;
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].key, "otto-flags/evaluations");
    assert_eq!(after[0].display_name, "Evaluations");
    assert_eq!(after[0].unit, "1k evaluations");
    assert_eq!(after[0].created_at, before[0].created_at);
    assert!(after[0].updated_at >= before[0].updated_at);
    assert_eq!(after[1], before[1]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn malformed_meters_are_rejected_one_by_one(pool: PgPool) {
    let w = world(pool).await;
    resources::set_service(&w.db, FLAGS, "otto-flags")
        .await
        .unwrap();
    let flags = basic(FLAGS, &w.flags_secret);
    let long_key = format!("otto-flags/{}", "a".repeat(5000));

    let (status, body) = put_meters(
        &w.db,
        &flags,
        json!([
            {"key": "otto-flags/Evaluations", "display_name": "X", "unit": "x"},
            {"key": "otto-flags/1st", "display_name": "X", "unit": "x"},
            {"key": "otto-flags/ok", "display_name": "", "unit": "x"},
            {"key": "otto-flags/ok", "display_name": "x".repeat(81), "unit": "x"},
            {"key": "otto-flags/ok", "display_name": "X", "unit": "u".repeat(33)},
            {"key": "otto-flags/ok", "display_name": "two\nlines", "unit": "x"},
            {"key": long_key, "display_name": "X", "unit": "x"},
            {"key": "otto-flags/good", "display_name": "Good", "unit": "x"},
            {"key": "otto-flags/good", "display_name": "Twice", "unit": "x"},
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["declared"], json!(["otto-flags/good"]));
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 8, "{body}");
    // An absurd key is not echoed back whole.
    assert!(rejected[6]["key"].as_str().unwrap().len() <= 128);
    assert!(rejected[8 - 1]["reason"]
        .as_str()
        .unwrap()
        .contains("more than once"));
    let stored = stored_meters(&w.db, "otto-flags").await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].display_name, "Good");

    // More than the cap is refused whole.
    let many: Vec<Value> = (0..=otto_resource::MAX_METER_DECLARATIONS)
        .map(|i| json!({"key": format!("otto-flags/m{i}"), "display_name": "M", "unit": "x"}))
        .collect();
    let (status, body) = put_meters(&w.db, &flags, json!(many)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(stored_meters(&w.db, "otto-flags").await.len(), 1);

    // And so is a body far larger than any valid declaration.
    let huge = json!([{"key": "otto-flags/big", "display_name": "x".repeat(100_000), "unit": "x"}]);
    let (status, _) = put_meters(&w.db, &flags, huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_resource_server_without_a_service_cannot_declare_meters(pool: PgPool) {
    let w = world(pool).await;
    let (status, body) = put_meters(
        &w.db,
        &w.factory_basic(),
        json!([{"key": "otto-factory/jobs", "display_name": "Jobs", "unit": "job"}]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "service_not_set");
    assert!(stored_meters(&w.db, "otto-factory").await.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_client_declares_meters(pool: PgPool) {
    use otto_resource::{Error, MeterDeclaration};

    let w = world(pool).await;
    let base = serve(&w.db).await;
    let client = PlatformClient::new(ClientConfig::new(&base, FLAGS, &w.flags_secret)).unwrap();
    let decls: Vec<MeterDeclaration> = (0..otto_resource::MAX_METER_DECLARATIONS + 3)
        .map(|i| MeterDeclaration::new(format!("otto-flags/m{i}"), format!("M {i}"), "x"))
        .chain([MeterDeclaration::new(
            "otto-cxp/tickets",
            "Tickets",
            "ticket",
        )])
        .collect();

    // Before an operator assigns a service: 409, not retriable.
    let err = client.declare_meters(&decls).await.unwrap_err();
    assert!(
        matches!(&err, Error::Status { status: 409, body } if body.contains("service_not_set")),
        "{err:?}"
    );
    assert!(!err.is_retriable());

    resources::set_service(&w.db, FLAGS, "otto-flags")
        .await
        .unwrap();
    // More than one request's worth: the client splits and merges.
    let receipt = client.declare_meters(&decls).await.unwrap();
    assert_eq!(
        receipt.declared.len(),
        otto_resource::MAX_METER_DECLARATIONS + 3
    );
    assert_eq!(receipt.rejected.len(), 1);
    assert_eq!(receipt.rejected[0].key, "otto-cxp/tickets");
    assert!(!receipt.is_complete());
    assert_eq!(
        stored_meters(&w.db, "otto-flags").await.len(),
        otto_resource::MAX_METER_DECLARATIONS + 3
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_assigns_service_slugs(pool: PgPool) {
    use otto_platform_server::resource_cmd::{execute, parse};

    let db = Db::from_pool(pool);
    let run = |line: &str| {
        let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let cmd = parse(&args).unwrap();
        let db = db.clone();
        async move {
            let mut out = Vec::new();
            execute(&db, None, cmd, &mut out)
                .await
                .map(|()| String::from_utf8(out).unwrap())
        }
    };

    // register --service, and list shows it.
    let out = run(&format!(
        "register {FLAGS} --name otto-flags --scopes flags:read --service otto-flags"
    ))
    .await
    .unwrap();
    assert!(out.contains("service=otto-flags"), "{out}");
    run(&format!(
        "register {FACTORY} --name otto-factory --scopes jobs:read"
    ))
    .await
    .unwrap();
    let list = run("list").await.unwrap();
    let line = |uri: &str| {
        list.lines()
            .find(|l| l.starts_with(uri))
            .unwrap_or_else(|| panic!("{uri} not in {list:?}"))
            .to_owned()
    };
    assert!(line(FLAGS).ends_with("\tservice=otto-flags"), "{list}");
    assert!(line(FACTORY).ends_with("\tservice=-"), "{list}");

    // Re-registering without --service keeps it.
    run(&format!(
        "register {FLAGS} --name otto-flags --scopes flags:read,flags:write"
    ))
    .await
    .unwrap();
    assert_eq!(
        resources::get(&db, FLAGS)
            .await
            .unwrap()
            .unwrap()
            .service
            .as_deref(),
        Some("otto-flags")
    );

    // set-service assigns one; describe shows it.
    let out = run(&format!("set-service {FACTORY} otto-factory"))
        .await
        .unwrap();
    assert!(out.contains("service=otto-factory"), "{out}");
    let out = run(&format!("describe {FACTORY} --clear")).await.unwrap();
    assert!(out.contains("service=otto-factory"), "{out}");

    // Malformed slugs are refused while parsing, before anything is written.
    for bad in ["Otto", "otto_factory"] {
        let args: Vec<String> = format!("set-service {FACTORY} {bad}")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert!(parse(&args).is_err(), "{bad}");
    }
    // Slugs are unique, and the URI must be registered.
    for bad in [
        format!("set-service {FACTORY} otto-flags"),
        "set-service https://nope.example/mcp otto-nope".to_owned(),
    ] {
        let err = run(&bad).await.expect_err(&bad);
        assert!(!err.to_string().contains("duplicate key"), "{bad}: {err}");
    }
    let err = run(&format!("set-service {FACTORY} otto-flags"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already assigned"), "{err}");

    // Renaming is fine until the service has declared meters, then refused.
    run(&format!("set-service {FACTORY} otto-factory-2"))
        .await
        .unwrap();
    run(&format!("set-service {FACTORY} otto-factory"))
        .await
        .unwrap();
    let mut tx = db.begin_unpinned().await.unwrap();
    otto_billing::meters::upsert_meters(
        &mut tx,
        &[otto_billing::meters::check_declaration(
            "otto-factory",
            &otto_billing::meters::MeterSpec {
                key: "otto-factory/jobs",
                display_name: "Jobs",
                unit: "job",
            },
        )
        .unwrap()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Setting the same slug again is still fine.
    run(&format!("set-service {FACTORY} otto-factory"))
        .await
        .unwrap();
    let err = run(&format!("set-service {FACTORY} otto-jobs"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("declared meters"), "{err}");
    assert_eq!(
        resources::get(&db, FACTORY)
            .await
            .unwrap()
            .unwrap()
            .service
            .as_deref(),
        Some("otto-factory")
    );
}

// ---------------------------------------------------------- metered usage

const EVALS: &str = "otto-flags/evaluations";
const JOBS: &str = "otto-factory/jobs";

/// `world()` with service slugs assigned and one meter declared per service:
/// otto-flags declares `evaluations`, otto-factory declares `jobs`.
async fn metered_world(pool: PgPool) -> World {
    let w = world(pool).await;
    for (uri, service, secret, key, name, unit) in [
        (
            FLAGS,
            "otto-flags",
            &w.flags_secret,
            EVALS,
            "Flag evaluations",
            "evaluation",
        ),
        (
            FACTORY,
            "otto-factory",
            &w.factory_secret,
            JOBS,
            "Jobs completed",
            "job",
        ),
    ] {
        resources::set_service(&w.db, uri, service).await.unwrap();
        let (status, body) = put_meters(
            &w.db,
            &basic(uri, secret),
            json!([{"key": key, "display_name": name, "unit": unit}]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["declared"], json!([key]));
    }
    w
}

impl World {
    fn flags_basic(&self) -> String {
        basic(FLAGS, &self.flags_secret)
    }

    async fn status(&self, auth: &str) -> Value {
        let (status, body) = get(
            &self.db,
            auth,
            &format!("/internal/orgs/{}/usage-status", self.org),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn metered(org: OrgId, meter: &str, quantity: Option<u64>) -> Value {
    let mut ev = usage_event(org, None, Uuid::new_v4(), true);
    ev["meter"] = json!(meter);
    if let Some(q) = quantity {
        ev["quantity"] = json!(q);
    }
    ev
}

/// The reason codes of a receipt's rejections, in order.
fn rejection_codes(receipt: &Value) -> Vec<String> {
    receipt["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let reason = r["reason"].as_str().unwrap();
            reason.split(':').next().unwrap().to_owned()
        })
        .collect()
}

async fn meter_quantity(db: &Db, meter: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT quantity FROM org_meter_period_usage WHERE meter = $1")
        .bind(meter)
        .fetch_optional(db.pool())
        .await
        .unwrap()
}

async fn service_pool(db: &Db, service: &str) -> Option<(i64, i64)> {
    sqlx::query_as(
        "SELECT billable_count, total_count FROM org_service_period_usage WHERE service = $1",
    )
    .bind(service)
    .fetch_optional(db.pool())
    .await
    .unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_undeclared_meter_is_rejected_per_event_and_the_rest_counted(pool: PgPool) {
    let w = metered_world(pool).await;
    let auth = w.flags_basic();
    let undeclared = metered(w.org, "otto-flags/clicks", Some(3));
    let undeclared_id = undeclared["event_id"].clone();
    let mut free = usage_event(w.org, None, Uuid::new_v4(), false);
    free["service"] = json!("otto-flags");
    let batch = vec![
        metered(w.org, EVALS, Some(5)),
        undeclared,
        free,
        // Another service's declared meter is not this caller's.
        metered(w.org, JOBS, Some(1)),
        // A meter with no quantity counts one.
        metered(w.org, EVALS, None),
    ];

    let (status, receipt) = post_usage(&w.db, &auth, batch.clone()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["accepted"], 3, "{receipt}");
    assert_eq!(
        rejection_codes(&receipt),
        ["unknown_meter", "unknown_meter"]
    );
    assert_eq!(receipt["rejected"][0]["event_id"], undeclared_id);
    assert!(receipt["rejected"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("otto-flags/clicks"));

    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(6));
    assert_eq!(meter_quantity(&w.db, JOBS).await, None);
    assert_eq!(meter_quantity(&w.db, "otto-flags/clicks").await, None);
    // Every accepted event counts in the shipper's pool, metered or not.
    assert_eq!(service_pool(&w.db, "otto-flags").await, Some((2, 3)));
    assert_eq!(service_pool(&w.db, "otto-factory").await, None);
    // And in the legacy family-wide bucket, exactly as before.
    let legacy: (i64, i64) =
        sqlx::query_as("SELECT billable_count, total_count FROM org_period_usage")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(legacy, (2, 3));

    // The event rows carry who shipped them and what they metered.
    let rows: Vec<(Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT resource_uri, meter, quantity FROM usage_events ORDER BY quantity NULLS FIRST",
    )
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            (Some(FLAGS.to_owned()), None, None),
            (Some(FLAGS.to_owned()), Some(EVALS.to_owned()), Some(1)),
            (Some(FLAGS.to_owned()), Some(EVALS.to_owned()), Some(5)),
        ]
    );

    // A replay counts nothing twice, meters included; the rejected events are
    // still rejected, not duplicates.
    let (_, again) = post_usage(&w.db, &auth, batch).await;
    assert_eq!(
        (again["accepted"].clone(), again["duplicates"].clone()),
        (json!(0), json!(3))
    );
    assert_eq!(rejection_codes(&again), ["unknown_meter", "unknown_meter"]);
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(6));
    assert_eq!(service_pool(&w.db, "otto-flags").await, Some((2, 3)));

    // A rejected event left no trace, so it can be corrected and resent under
    // the same id.
    let mut fixed = metered(w.org, EVALS, Some(3));
    fixed["event_id"] = undeclared_id;
    assert_eq!(post_usage(&w.db, &auth, vec![fixed]).await.1["accepted"], 1);
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(9));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_service_other_than_the_callers_is_a_mismatch(pool: PgPool) {
    let w = metered_world(pool).await;
    let mut theirs = metered(w.org, EVALS, Some(1));
    theirs["service"] = json!("otto-factory");
    let mut unmetered_theirs = usage_event(w.org, None, Uuid::new_v4(), true);
    unmetered_theirs["service"] = json!("otto-factory");
    let mut mine = metered(w.org, EVALS, Some(2));
    mine["service"] = json!("otto-flags");

    let (_, receipt) = post_usage(
        &w.db,
        &w.flags_basic(),
        vec![theirs, unmetered_theirs, mine],
    )
    .await;
    assert_eq!(receipt["accepted"], 1, "{receipt}");
    assert_eq!(
        rejection_codes(&receipt),
        ["service_mismatch", "service_mismatch"]
    );
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(2));
    assert_eq!(service_pool(&w.db, "otto-factory").await, None);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_caller_without_a_service_ships_only_unmetered_usage(pool: PgPool) {
    let w = world(pool).await;
    let auth = w.factory_basic();
    let mut named = usage_event(w.org, None, Uuid::new_v4(), true);
    named["service"] = json!("otto-factory");
    let (_, receipt) = post_usage(
        &w.db,
        &auth,
        vec![
            usage_event(w.org, None, Uuid::new_v4(), true),
            metered(w.org, JOBS, Some(1)),
            named,
        ],
    )
    .await;
    assert_eq!(receipt["accepted"], 1, "{receipt}");
    assert_eq!(
        rejection_codes(&receipt),
        ["unknown_meter", "service_mismatch"]
    );
    // No pool to count in: only the legacy bucket moved.
    let pools: i64 = sqlx::query_scalar("SELECT count(*) FROM org_service_period_usage")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(pools, 0);

    let status = w.status(&auth).await;
    assert_eq!(status["total_count"], 1);
    assert!(status.get("service").is_none(), "{status}");
    assert_eq!(status["meters"], json!([]));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn quantities_are_bounded_per_event(pool: PgPool) {
    let w = metered_world(pool).await;
    assert_eq!(
        otto_resource::MAX_METER_QUANTITY,
        otto_billing::usage::MAX_METER_QUANTITY
    );
    let mut quantity_without_meter = usage_event(w.org, None, Uuid::new_v4(), true);
    quantity_without_meter["quantity"] = json!(4);
    let mut negative = metered(w.org, EVALS, None);
    negative["quantity"] = json!(-1);

    // The review threshold is raised past the largest event, which the
    // default would hold.
    let (status, receipt) = post_usage_held_at(
        &w.db,
        &w.flags_basic(),
        10_000_000_000,
        vec![
            metered(w.org, EVALS, Some(0)),
            metered(w.org, EVALS, Some(1_000_000_001)),
            quantity_without_meter,
            metered(w.org, EVALS, Some(1)),
            metered(w.org, EVALS, Some(1_000_000_000)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["accepted"], 2, "{receipt}");
    assert_eq!(
        rejection_codes(&receipt),
        ["invalid_quantity", "invalid_quantity", "invalid_quantity"]
    );
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(1_000_000_001));

    // A quantity that is not a u64 at all is a malformed body, like any other
    // type error, and counts nothing.
    let (status, _) = post_usage(&w.db, &w.flags_basic(), vec![negative]).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(1_000_000_001));
}

/// `UsageEvent` exactly as `otto-resource` shipped it before value meters.
#[derive(serde::Serialize, serde::Deserialize)]
struct OldUsageEvent {
    event_id: Uuid,
    org_id: Uuid,
    user_id: Option<Uuid>,
    tool: String,
    billable: bool,
    occurred_at: chrono::DateTime<Utc>,
}

/// `UsageStatus` exactly as a resource server pinned before value meters
/// parses it, with its blocking rule.
#[derive(serde::Deserialize)]
struct OldUsageStatus {
    #[allow(dead_code)]
    org_id: Uuid,
    #[allow(dead_code)]
    plan: String,
    #[allow(dead_code)]
    period_start: chrono::NaiveDate,
    billable_count: i64,
    #[allow(dead_code)]
    total_count: i64,
    included_ops: i64,
    hard_stop: bool,
    #[serde(default)]
    #[allow(dead_code)]
    features: std::collections::BTreeMap<String, Value>,
}

impl OldUsageStatus {
    fn is_blocked(&self) -> bool {
        self.hard_stop && self.billable_count >= self.included_ops
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn old_and_new_shapes_round_trip(pool: PgPool) {
    let w = metered_world(pool).await;
    let base = serve(&w.db).await;
    let auth = w.flags_basic();

    // An old client's event, serialized by the old type, ingests as unmetered.
    let old = OldUsageEvent {
        event_id: Uuid::new_v4(),
        org_id: w.org.as_uuid(),
        user_id: Some(w.user.as_uuid()),
        tool: "flag.set".into(),
        billable: true,
        occurred_at: Utc::now(),
    };
    let old_json = serde_json::to_value(&old).unwrap();
    let parsed: UsageEvent = serde_json::from_value(old_json.clone()).unwrap();
    assert_eq!(
        (parsed.service, parsed.meter, parsed.quantity),
        (None, None, None)
    );
    let (_, receipt) = post_usage(&w.db, &auth, vec![old_json]).await;
    assert_eq!(receipt["accepted"], 1, "{receipt}");

    // A new unmetered event is byte-for-byte the old shape on the wire, and a
    // new metered one still parses as the old type.
    let new_unmetered = UsageEvent {
        event_id: old.event_id,
        org_id: old.org_id,
        user_id: old.user_id,
        tool: old.tool.clone(),
        billable: old.billable,
        occurred_at: old.occurred_at,
        service: None,
        meter: None,
        quantity: None,
    };
    assert_eq!(
        serde_json::to_value(&new_unmetered).unwrap(),
        serde_json::to_value(&old).unwrap()
    );
    let new_metered = UsageEvent {
        service: Some("otto-flags".into()),
        meter: Some(EVALS.into()),
        quantity: Some(12),
        event_id: Uuid::new_v4(),
        ..new_unmetered
    };
    let wire = serde_json::to_value(&new_metered).unwrap();
    assert_eq!(wire["meter"], EVALS);
    serde_json::from_value::<OldUsageEvent>(wire).unwrap();

    // Shipped through the client, the metered event counts in its meter.
    let client = PlatformClient::new(ClientConfig::new(&base, FLAGS, &w.flags_secret)).unwrap();
    let receipt = client.ship_usage(&[new_metered]).await.unwrap();
    assert_eq!(receipt.accepted, 1);

    // The new status body parses as the old shape, and as the new one.
    let body = w.status(&auth).await;
    let old_status: OldUsageStatus = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(old_status.billable_count, 2);
    assert!(!old_status.hard_stop);
    let status = client.usage_status(w.org.as_uuid()).await.unwrap();
    assert_eq!(status.service.as_deref(), Some("otto-flags"));
    assert_eq!(
        status.meters,
        [otto_resource::MeterUsage {
            meter: EVALS.into(),
            display_name: "Flag evaluations".into(),
            unit: "evaluation".into(),
            quantity: 12,
        }]
    );
    assert_eq!(status.meter(EVALS).unwrap().quantity, 12);

    // And an old platform's body (no `service`, no `meters`, no `features`)
    // still parses as the new type.
    let older = json!({
        "org_id": w.org,
        "plan": "free",
        "period_start": "2026-10-01",
        "billable_count": 1,
        "total_count": 1,
        "included_ops": 500,
        "hard_stop": true,
    });
    let s: otto_resource::UsageStatus = serde_json::from_value(older).unwrap();
    assert!(s.service.is_none() && s.meters.is_empty());
    // A new status re-serialized is readable by the old type too.
    serde_json::from_value::<OldUsageStatus>(serde_json::to_value(&status).unwrap()).unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn heavy_usage_never_blocks_an_old_client(pool: PgPool) {
    let w = metered_world(pool).await;
    let base = serve(&w.db).await;
    let auth = w.flags_basic();

    // Well past the free plan's 500-operation bucket, which hard-stops.
    for _ in 0..2 {
        let batch: Vec<Value> = (0..400)
            .map(|i| {
                if i % 2 == 0 {
                    metered(w.org, EVALS, Some(1000))
                } else {
                    usage_event(w.org, None, Uuid::new_v4(), true)
                }
            })
            .collect();
        assert_eq!(post_usage(&w.db, &auth, batch).await.1["accepted"], 400);
    }
    let plan_hard_stop: bool =
        sqlx::query_scalar("SELECT hard_stop FROM plans WHERE plan = 'free'")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert!(
        plan_hard_stop,
        "the free plan still hard-stops in the plan table"
    );

    let old: OldUsageStatus = serde_json::from_value(w.status(&auth).await).unwrap();
    assert!(old.billable_count >= old.included_ops);
    assert!(!old.hard_stop);
    assert!(!old.is_blocked());

    let client = PlatformClient::new(ClientConfig::new(&base, FLAGS, &w.flags_secret)).unwrap();
    let status = client.usage_status(w.org.as_uuid()).await.unwrap();
    assert!(status.over_limit() && !status.is_blocked());
    assert_eq!(status.meter(EVALS).unwrap().quantity, 400_000);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_from_one_service_never_changes_anothers_status(pool: PgPool) {
    let w = metered_world(pool).await;
    let flags = w.flags_basic();
    let factory = w.factory_basic();

    // The service-scoped part of a status, and the old client's verdict.
    let scoped = |body: &Value| {
        let old: OldUsageStatus = serde_json::from_value(body.clone()).unwrap();
        (
            body["service"].clone(),
            body["meters"].clone(),
            body["hard_stop"].clone(),
            old.is_blocked(),
        )
    };

    let factory_before = w.status(&factory).await;
    assert_eq!(factory_before["service"], "otto-factory");
    assert_eq!(
        factory_before["meters"],
        json!([{"meter": JOBS, "display_name": "Jobs completed", "unit": "job", "quantity": 0}])
    );

    for _ in 0..2 {
        let batch: Vec<Value> = (0..300)
            .map(|_| metered(w.org, EVALS, Some(1_000)))
            .collect();
        assert_eq!(post_usage(&w.db, &flags, batch).await.1["accepted"], 300);
    }

    let factory_after = w.status(&factory).await;
    assert_eq!(scoped(&factory_after), scoped(&factory_before));
    assert_eq!(service_pool(&w.db, "otto-factory").await, None);

    // The shipper sees its own usage, and only its own meters.
    let flags_status = w.status(&flags).await;
    assert_eq!(flags_status["service"], "otto-flags");
    assert_eq!(
        flags_status["meters"],
        json!([{
            "meter": EVALS,
            "display_name": "Flag evaluations",
            "unit": "evaluation",
            "quantity": 600_000,
        }])
    );
    assert_eq!(service_pool(&w.db, "otto-flags").await, Some((600, 600)));

    // And the other way round.
    let (_, r) = post_usage(&w.db, &factory, vec![metered(w.org, JOBS, Some(7))]).await;
    assert_eq!(r["accepted"], 1);
    assert_eq!(scoped(&w.status(&flags).await), scoped(&flags_status));
    assert_eq!(w.status(&factory).await["meters"][0]["quantity"], 7);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn meter_usage_is_counted_per_org(pool: PgPool) {
    let w = metered_world(pool).await;
    let other = w.db.create_org("globex", "Globex").await.unwrap();
    authorize_both(&w.db, other.id).await;
    let (_, r) = post_usage(
        &w.db,
        &w.flags_basic(),
        vec![
            metered(w.org, EVALS, Some(5)),
            metered(other.id, EVALS, Some(11)),
        ],
    )
    .await;
    assert_eq!(r["accepted"], 2, "{r}");
    assert_eq!(w.status(&w.flags_basic()).await["meters"][0]["quantity"], 5);
    let (_, theirs) = get(
        &w.db,
        &w.flags_basic(),
        &format!("/internal/orgs/{}/usage-status", other.id),
    )
    .await;
    assert_eq!(theirs["meters"][0]["quantity"], 11);
}

// --------------------------------------- authorization and the sanity limit

/// `POST /internal/usage` through a router with the review threshold set.
async fn post_usage_held_at(
    db: &Db,
    auth: &str,
    threshold: i64,
    events: Vec<Value>,
) -> (StatusCode, Value) {
    let res = otto_platform_server::internal::router_with_hold_threshold(
        db.clone(),
        otto_platform_server::Billing::Enabled,
        threshold,
    )
    .oneshot(
        Request::post("/internal/usage")
            .header("authorization", auth)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "events": events }).to_string()))
            .unwrap(),
    )
    .await
    .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_for_an_org_that_never_authorized_the_caller_is_rejected_per_event(pool: PgPool) {
    let w = metered_world(pool).await;
    // An org that authorized otto-flags only, and one that authorized nothing.
    let flags_only = w.db.create_org("flags-only", "Flags only").await.unwrap();
    w.db.add_member(flags_only.id, w.user, Role::Admin)
        .await
        .unwrap();
    authorize(&w.db, flags_only.id, w.user, FLAGS).await;
    let nobody = w.db.create_org("nobody", "Nobody").await.unwrap();

    let mine = metered(w.org, JOBS, Some(3));
    let theirs = metered(flags_only.id, JOBS, Some(5));
    let stranger = metered(nobody.id, JOBS, Some(7));
    let (status, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![mine.clone(), theirs.clone(), stranger.clone()],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["accepted"], 1, "{r}");
    assert_eq!(
        rejection_codes(&r),
        ["not_authorized", "not_authorized"],
        "{r}"
    );
    let ids: Vec<_> = r["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["event_id"].clone())
        .collect();
    for rejected in [&theirs, &stranger] {
        assert!(ids.contains(&rejected["event_id"]), "{ids:?}");
    }

    // Nothing was billed to either, and the refused events were not claimed:
    // the same ids are accepted once the org has authorized the caller.
    for org in [flags_only.id, nobody.id] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE org_id = $1")
            .bind(org)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
    authorize(&w.db, flags_only.id, w.user, FACTORY).await;
    let (_, r) = post_usage(&w.db, &w.factory_basic(), vec![theirs]).await;
    assert_eq!(r["accepted"], 1, "{r}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_revoked_expired_or_swept_grant_still_authorizes_usage_already_earned(pool: PgPool) {
    let w = metered_world(pool).await;
    let org = w.db.create_org("late", "Late").await.unwrap();
    w.db.add_member(org.id, w.user, Role::Admin).await.unwrap();
    authorize_with_token(&w.db, org.id, w.user, FACTORY).await;
    // Revoked and expired, then swept away by `tokens::sweep`: the grant is
    // remembered anyway.
    sqlx::query("UPDATE access_tokens SET revoked_at = now(), expires_at = now() - interval '8 days' WHERE org_id = $1")
        .bind(org.id)
        .execute(w.db.pool())
        .await
        .unwrap();
    assert!(tokens::sweep(&w.db).await.unwrap() >= 1);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM access_tokens WHERE org_id = $1")
        .bind(org.id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![metered(org.id, JOBS, Some(1))],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_past_the_sanity_limit_is_held_not_billed_and_listed_for_the_operator(pool: PgPool) {
    let w = metered_world(pool).await;
    let auth = w.factory_basic();
    let first = metered(w.org, JOBS, Some(6));
    let over = metered(w.org, JOBS, Some(5));
    let small = metered(w.org, JOBS, Some(4));
    // 6 fits a limit of 10; 6 + 5 does not; 6 + 4 does.
    let (status, r) = post_usage_held_at(&w.db, &auth, 10, vec![first, over.clone(), small]).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["accepted"], 2, "{r}");
    assert_eq!(rejection_codes(&r), ["held_for_review"], "{r}");
    assert_eq!(r["rejected"][0]["event_id"], over["event_id"]);
    assert_eq!(meter_quantity(&w.db, JOBS).await, Some(10));

    // A resend is a duplicate and is not held a second time.
    let (_, r) = post_usage_held_at(&w.db, &auth, 10, vec![over.clone()]).await;
    assert_eq!(r["duplicates"], 1, "{r}");
    let (_, r) = post_usage_held_at(&w.db, &auth, 1_000, vec![over.clone()]).await;
    assert_eq!(r["duplicates"], 1, "{r}");

    // Held: no usage row, no billing, one row for the operator.
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE org_id = $1")
        .bind(w.org)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(events, 2);
    let mut out = Vec::new();
    otto_platform_server::usage_cmd::execute(
        &w.db,
        otto_platform_server::usage_cmd::Command::Held,
        &mut out,
    )
    .await
    .unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains(&over["event_id"].as_str().unwrap().to_string()),
        "{out}"
    );
    assert!(out.contains("quantity=5"), "{out}");
    assert!(out.contains("held_for_review"), "{out}");
    assert!(out.contains("1 usage event(s) held"), "{out}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_sanity_limit_is_per_org_and_per_meter(pool: PgPool) {
    let w = metered_world(pool).await;
    let other = w.db.create_org("other", "Other").await.unwrap();
    authorize_both(&w.db, other.id).await;
    w.db.add_member(other.id, w.user, Role::Admin)
        .await
        .unwrap();
    authorize(&w.db, other.id, w.user, FACTORY).await;
    let auth = w.factory_basic();
    // Each org may use the limit in full: one org's total never holds another's.
    let batch = vec![
        metered(w.org, JOBS, Some(10)),
        metered(other.id, JOBS, Some(10)),
        // An unmetered event never counts toward the limit.
        usage_event(w.org, None, Uuid::new_v4(), true),
    ];
    let (_, r) = post_usage_held_at(&w.db, &auth, 10, batch).await;
    assert_eq!(r["accepted"], 3, "{r}");
    let (_, r) = post_usage_held_at(&w.db, &auth, 10, vec![metered(other.id, JOBS, Some(1))]).await;
    assert_eq!(rejection_codes(&r), ["held_for_review"], "{r}");
}

// ---------------------------------------------------------- service rename

/// The meter otto-factory declares in `metered_world`, after the rename.
const TOWER_JOBS: &str = "otto-tower/jobs";

async fn run_resource_cmd(db: &Db, line: &str) -> anyhow::Result<String> {
    use otto_platform_server::resource_cmd::{execute, parse};
    let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let cmd = parse(&args).map_err(anyhow::Error::msg)?;
    let mut out = Vec::new();
    execute(db, None, cmd, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

/// [`run_resource_cmd`], keeping what the command printed when it fails.
async fn run_resource_cmd_output(db: &Db, line: &str) -> (String, Option<anyhow::Error>) {
    use otto_platform_server::resource_cmd::{execute, parse};
    let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let cmd = parse(&args).unwrap();
    let mut out = Vec::new();
    let err = execute(db, None, cmd, &mut out).await.err();
    (String::from_utf8(out).unwrap(), err)
}

/// A price for `meter` in effect from this month, written as the test pool's
/// superuser (`otto_app` cannot write the price book). Returns its version id.
async fn price(db: &Db, meter: &str) -> Uuid {
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ($1, date_trunc('month', now() AT TIME ZONE 'UTC')::date) RETURNING id",
    )
    .bind(meter)
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, NULL, 5)",
    )
    .bind(version)
    .execute(db.pool())
    .await
    .unwrap();
    version
}

/// A budget and a fired 50% alert for `service` in `org`. Written as the
/// superuser, which row-level security does not apply to.
async fn budget(db: &Db, org: OrgId, service: &str) {
    sqlx::query(
        "INSERT INTO service_budgets (org_id, service, monthly_budget_cents) VALUES ($1, $2, 1000)",
    )
    .bind(org.as_uuid())
    .bind(service)
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO budget_alerts (org_id, service, period_start, threshold) \
         VALUES ($1, $2, date_trunc('month', now() AT TIME ZONE 'UTC')::date, 50)",
    )
    .bind(org.as_uuid())
    .bind(service)
    .execute(db.pool())
    .await
    .unwrap();
}

/// How many rows of `table` have `column = value`, every org's.
async fn rows_with(db: &Db, table: &str, column: &str, value: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE {column} = $1"))
        .bind(value)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Ships one unmetered event for `org` as otto-factory: it lands in the
/// otto-factory pool and in `usage_events` with no meter.
async fn unmetered_factory_usage(w: &World, org: OrgId) {
    let (status, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![usage_event(org, None, Uuid::new_v4(), true)],
    )
    .await;
    assert_eq!(
        (status, r["accepted"].clone()),
        (StatusCode::OK, json!(1)),
        "{r}"
    );
}

/// The meters `GET /api/plans` lists, as `service/meter`.
async fn catalog_meters(db: &Db) -> Vec<String> {
    let config = otto_platform_server::Config {
        database_url: "unused".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: "https://otto.test".into(),
        encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        client_ip_header: None,
        enforce_quotas: false,
        static_dir: None,
        run_migrations: true,
        log_format: otto_platform_server::LogFormat::Text,
        email: None,
        stripe: None,
        usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
    };
    let res = otto_platform_server::app(db.clone(), &config)
        .unwrap()
        .oneshot(Request::get("/api/plans").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    body["meters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}/{}",
                m["service"].as_str().unwrap(),
                m["meter"].as_str().unwrap()
            )
        })
        .collect()
}

/// Everything keyed by the old slug moves: the meter, its price, and in every
/// org the service pool (unmetered usage does not block), the budget and its
/// alert. Another service's rows stay where they are, and the plan catalog
/// lists the meter under its new name.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rename_service_moves_everything_keyed_by_the_old_slug(pool: PgPool) {
    let w = metered_world(pool).await;
    let other = w.db.create_org("globex", "Globex").await.unwrap().id;
    authorize_both(&w.db, other).await;
    let jobs_price = price(&w.db, JOBS).await;
    price(&w.db, EVALS).await;
    for org in [w.org, other] {
        budget(&w.db, org, "otto-factory").await;
        unmetered_factory_usage(&w, org).await;
    }
    budget(&w.db, w.org, "otto-flags").await;
    let (_, r) = post_usage(
        &w.db,
        &w.flags_basic(),
        vec![metered(w.org, EVALS, Some(4))],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
    assert_eq!(
        catalog_meters(&w.db).await,
        ["otto-factory/jobs", "otto-flags/evaluations"]
    );

    let out = run_resource_cmd(&w.db, &format!("rename-service {FACTORY} otto-tower"))
        .await
        .unwrap();
    assert!(
        out.contains("service=otto-tower (was otto-factory)"),
        "{out}"
    );
    assert!(
        out.contains(
            "moved: 1 meter(s), 1 price version(s), 2 usage pool(s), 2 budget(s), 2 budget alert(s)"
        ),
        "{out}"
    );

    let stored: Vec<String> = stored_meters(&w.db, "otto-tower")
        .await
        .into_iter()
        .map(|m| m.key)
        .collect();
    assert_eq!(stored, [TOWER_JOBS]);
    assert!(stored_meters(&w.db, "otto-factory").await.is_empty());
    let moved_price: String = sqlx::query_scalar("SELECT meter FROM price_versions WHERE id = $1")
        .bind(jobs_price)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(moved_price, TOWER_JOBS);
    for (table, column) in [
        ("org_service_period_usage", "service"),
        ("service_budgets", "service"),
        ("budget_alerts", "service"),
    ] {
        assert_eq!(
            rows_with(&w.db, table, column, "otto-factory").await,
            0,
            "{table}"
        );
        assert_eq!(
            rows_with(&w.db, table, column, "otto-tower").await,
            2,
            "{table}"
        );
        assert_eq!(
            rows_with(&w.db, table, column, "otto-flags").await,
            1,
            "{table}"
        );
    }
    assert_eq!(service_pool(&w.db, "otto-flags").await, Some((1, 1)));
    assert_eq!(meter_quantity(&w.db, EVALS).await, Some(4));
    assert_eq!(
        resources::get(&w.db, FACTORY)
            .await
            .unwrap()
            .unwrap()
            .service
            .as_deref(),
        Some("otto-tower")
    );
    assert_eq!(
        catalog_meters(&w.db).await,
        ["otto-flags/evaluations", "otto-tower/jobs"]
    );

    // The service carries on under the new name: it redeclares its meter
    // (idempotently) and its metered usage counts, while the old key is
    // unknown.
    let (status, body) = put_meters(
        &w.db,
        &w.factory_basic(),
        json!([{"key": TOWER_JOBS, "display_name": "Jobs completed", "unit": "job"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![
            metered(w.org, TOWER_JOBS, Some(3)),
            metered(w.org, JOBS, Some(1)),
        ],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
    assert_eq!(rejection_codes(&r), ["unknown_meter"]);
    assert_eq!(meter_quantity(&w.db, TOWER_JOBS).await, Some(3));

    // Now that metered usage exists under it, otto-tower cannot be renamed,
    // and set-service is still refused once meters are declared.
    let err = run_resource_cmd(&w.db, &format!("rename-service {FACTORY} otto-jobs"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("1 usage_events"), "{err}");
    let err = run_resource_cmd(&w.db, &format!("set-service {FACTORY} otto-jobs"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("declared meters"), "{err}");
}

/// Each kind of billing data under an old meter refuses the rename on its
/// own, named with its count, and nothing moves. Usage in another service,
/// and a Stripe event name that only looks similar, block nothing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn each_kind_of_billing_data_under_the_old_meters_refuses_a_rename(pool: PgPool) {
    use otto_billing::stripe::meter_event_name;

    let w = metered_world(pool).await;
    let db = w.db.pool();
    let org = w.org.as_uuid();
    let version = price(&w.db, JOBS).await;
    budget(&w.db, w.org, "otto-factory").await;

    // Not blockers: another service's billing data, and a Stripe event name
    // for `otto-factory-x/jobs`, whose encoding shares a prefix with ours.
    let (_, r) = post_usage(
        &w.db,
        &w.flags_basic(),
        vec![metered(w.org, EVALS, Some(2))],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
    for name in [
        meter_event_name("otto-flags", "evaluations").unwrap(),
        meter_event_name("otto-factory-x", "jobs").unwrap(),
        meter_event_name("otto-factory-", "jobs").unwrap(),
    ] {
        sqlx::query(
            "INSERT INTO stripe_meter_outbox (org_id, event_name, stripe_customer_id, value, bucket_start) \
             VALUES ($1, $2, 'cus_x', 1, date_trunc('hour', now()))",
        )
        .bind(org)
        .bind(&name)
        .execute(db)
        .await
        .unwrap();
    }

    let plain = meter_event_name("otto-factory", "jobs").unwrap();
    // A key never declared still blocks if Stripe has heard of it; this one
    // takes the escaped encoding.
    let escaped = meter_event_name("otto-factory", "a__b").unwrap();
    let blockers: Vec<(&str, String, String)> = vec![
        (
            "usage_events",
            format!(
                "INSERT INTO usage_events (org_id, tool, billable, resource_uri, meter, quantity) \
                 VALUES ('{org}', 'job.done', true, '{FACTORY}', '{JOBS}', 1)"
            ),
            "DELETE FROM usage_events WHERE meter IS NOT NULL AND meter <> 'otto-flags/evaluations'"
                .into(),
        ),
        (
            "org_meter_period_usage",
            format!(
                "INSERT INTO org_meter_period_usage (org_id, meter, period_start, quantity) \
                 VALUES ('{org}', '{JOBS}', date_trunc('month', now())::date, 1)"
            ),
            format!("DELETE FROM org_meter_period_usage WHERE meter = '{JOBS}'"),
        ),
        (
            "stripe_meters",
            format!(
                "INSERT INTO stripe_meters (meter, stripe_meter_id, event_name) \
                 VALUES ('{JOBS}', 'mtr_1', '{plain}')"
            ),
            "DELETE FROM stripe_meters".into(),
        ),
        (
            "stripe_prices",
            format!(
                "INSERT INTO stripe_prices (price_version_id, meter, stripe_price_id) \
                 VALUES ('{version}', '{JOBS}', 'price_1')"
            ),
            "DELETE FROM stripe_prices".into(),
        ),
        (
            "stripe_meter_outbox",
            format!(
                "INSERT INTO stripe_meter_outbox (org_id, event_name, stripe_customer_id, value, bucket_start) \
                 VALUES ('{org}', '{plain}', 'cus_x', 1, date_trunc('hour', now()))"
            ),
            format!("DELETE FROM stripe_meter_outbox WHERE event_name = '{plain}'"),
        ),
        (
            "stripe_meter_outbox",
            format!(
                "INSERT INTO stripe_meter_outbox (org_id, event_name, stripe_customer_id, value, bucket_start) \
                 VALUES ('{org}', '{escaped}', 'cus_x', 1, date_trunc('hour', now()))"
            ),
            format!("DELETE FROM stripe_meter_outbox WHERE event_name = '{escaped}'"),
        ),
    ];

    for (table, insert, delete) in &blockers {
        sqlx::query(insert).execute(db).await.unwrap();
        let err = resources::rename_service(&w.db, FACTORY, "otto-tower")
            .await
            .expect_err(table);
        let msg = err.to_string();
        assert!(
            matches!(err, otto_auth::AuthError::InvalidRequest(_)),
            "{table}: {msg}"
        );
        assert!(
            msg.ends_with(&format!("has billing data under its meters: 1 {table}")),
            "{table}: {msg}"
        );
        assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1, "{table}");
        assert_eq!(
            rows_with(&w.db, "service_budgets", "service", "otto-factory").await,
            1
        );
        sqlx::query(delete).execute(db).await.unwrap();
    }

    // Several at once are all named, each with its count.
    sqlx::query(&blockers[0].1).execute(db).await.unwrap();
    sqlx::query(&blockers[0].1).execute(db).await.unwrap();
    sqlx::query(&blockers[2].1).execute(db).await.unwrap();
    let err = run_resource_cmd(&w.db, &format!("rename-service {FACTORY} otto-tower"))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .ends_with("has billing data under its meters: 2 usage_events, 1 stripe_meters"),
        "{err}"
    );
    sqlx::query(&blockers[0].2).execute(db).await.unwrap();
    sqlx::query(&blockers[2].2).execute(db).await.unwrap();

    // With the blockers gone (the decoys still there) it goes through.
    let renamed = resources::rename_service(&w.db, FACTORY, "otto-tower")
        .await
        .unwrap();
    assert_eq!(renamed.previous_service, "otto-factory");
    assert_eq!(renamed.moved.meters, 1);
}

/// The new slug is validated and must be free; the resource server must exist
/// and already have a slug; renaming to the slug it has is a no-op.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rename_service_validates_the_new_slug_and_the_resource(pool: PgPool) {
    let w = metered_world(pool).await;

    for bad in ["Otto", "otto_tower", "-otto", ""] {
        let err = resources::rename_service(&w.db, FACTORY, bad)
            .await
            .expect_err(bad);
        assert!(err.to_string().contains("lower-case slug"), "{bad}: {err}");
    }
    let err = resources::rename_service(&w.db, FACTORY, "otto-flags")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already assigned"), "{err}");
    let err = resources::rename_service(&w.db, "https://nope.example/mcp", "otto-nope")
        .await
        .unwrap_err();
    assert!(
        matches!(err, otto_auth::AuthError::InvalidTarget(_)),
        "{err}"
    );
    resources::register(
        &w.db,
        ResourceServerSpec {
            resource_uri: "https://new.example/mcp",
            name: "new",
            scopes: &["a"],
            default_scopes: &[],
        },
    )
    .await
    .unwrap();
    let err = resources::rename_service(&w.db, "https://new.example/mcp", "otto-new")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("set-service"), "{err}");

    // Pools or budgets an earlier service of the new name left behind would
    // collide with (or silently merge into) the moved ones. Such rows predate
    // the foreign keys of migration 0024, which refuse a new one, so the
    // fixture skips them the way a row written before it did.
    let mut tx = w.db.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO service_budgets (org_id, service, monthly_budget_cents) \
         VALUES ($1, 'otto-tower', 1000)",
    )
    .bind(w.org.as_uuid())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let err = resources::rename_service(&w.db, FACTORY, "otto-tower")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("earlier service"), "{err}");
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);

    let same = resources::rename_service(&w.db, FACTORY, "otto-factory")
        .await
        .unwrap();
    assert_eq!(same.previous_service, "otto-factory");
    assert_eq!(same.moved, resources::ServiceRenameCounts::default());
    assert_eq!(same.resource.service.as_deref(), Some("otto-factory"));
}

/// Tenant code cannot rename a service: `otto_app` has no EXECUTE on the
/// function.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_cannot_rename_a_service(pool: PgPool) {
    let w = metered_world(pool).await;
    let mut tx = w.db.begin(w.org).await.unwrap();
    let err = sqlx::query("SELECT * FROM rename_service($1, 'otto-tower')")
        .bind(FACTORY)
        .fetch_all(tx.conn())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

/// Tenant code gets none of the operator functions or the alias table, and
/// the migrations prove it (they refuse to finish otherwise); ingest gets the
/// canonical-URI lookup it writes usage through.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_code_holds_no_rename_privileges_after_migrating(pool: PgPool) {
    let (rename, blockers, aliases, canonical): (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_function_privilege('otto_app', 'rename_service(text, text)', 'EXECUTE'), \
                has_function_privilege('otto_app', 'service_rename_blockers(text)', 'EXECUTE'), \
                has_table_privilege('otto_app', 'resource_server_aliases', \
                                    'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'), \
                has_function_privilege('otto_app', 'canonical_resource_uri(text)', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!rename, "otto_app may execute rename_service");
    assert!(!blockers, "otto_app may execute service_rename_blockers");
    assert!(
        !aliases,
        "otto_app has privileges on resource_server_aliases"
    );
    assert!(
        canonical,
        "ingest (otto_app) cannot resolve a canonical URI"
    );

    // And the blocker counts refuse a pinned transaction, as the rename does.
    let w = metered_world(pool).await;
    let mut tx = w.db.begin(w.org).await.unwrap();
    let err = sqlx::query("SELECT * FROM service_rename_blockers('otto-factory')")
        .fetch_all(tx.conn())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

/// The managed-Postgres shape, where neither the operator's role nor the
/// function's owner is a superuser or BYPASSRLS, so every FORCE ROW LEVEL
/// SECURITY table applies its policies to both. A plain query there sees no
/// org's rows; the function must still see a blocker that belongs to an org
/// nobody pinned, and still move every org's rows.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_blocker_in_another_org_is_seen_without_an_rls_exemption(pool: PgPool) {
    const ROLE: &str = "otto_rename_test_operator";

    let w = metered_world(pool).await;
    let db = w.db.pool();
    let other = w.db.create_org("globex", "Globex").await.unwrap().id;
    authorize_both(&w.db, other).await;
    for org in [w.org, other] {
        budget(&w.db, org, "otto-factory").await;
        unmetered_factory_usage(&w, org).await;
    }

    // Roles are cluster-wide and test databases share the cluster, so this
    // tolerates another run having created it. It is left in place on purpose:
    // NOLOGIN and holding nothing outside the throwaway databases, it is
    // harmless, and dropping it would race a concurrent run still using it.
    sqlx::query(&format!(
        "DO $$ BEGIN \
           CREATE ROLE {ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; \
         END $$"
    ))
    .execute(db)
    .await
    .unwrap();
    for stmt in [
        format!("GRANT USAGE ON SCHEMA public TO {ROLE}"),
        format!(
            "GRANT SELECT ON usage_events, org_meter_period_usage, stripe_meters, \
             stripe_prices, stripe_meter_outbox TO {ROLE}"
        ),
        format!(
            "GRANT SELECT, UPDATE ON resource_servers, meters, price_versions, \
             org_service_period_usage, service_budgets, budget_alerts TO {ROLE}"
        ),
        format!("ALTER FUNCTION rename_service(text, text) OWNER TO {ROLE}"),
        // It counts the blockers through this one, which must not be the
        // exempt superuser either.
        format!("ALTER FUNCTION service_rename_blockers(text) OWNER TO {ROLE}"),
    ] {
        sqlx::query(&stmt).execute(db).await.unwrap();
    }

    let as_role = || async {
        let mut tx = db.begin().await.unwrap();
        sqlx::query(&format!("SET LOCAL ROLE {ROLE}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        let exempt: (bool, bool) = sqlx::query_as(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(exempt, (false, false));
        tx
    };

    // The blocker belongs to the second org, which no transaction here pins.
    sqlx::query(&format!(
        "INSERT INTO usage_events (org_id, tool, billable, resource_uri, meter, quantity) \
         VALUES ($1, 'job.done', true, '{FACTORY}', '{JOBS}', 1)"
    ))
    .bind(other.as_uuid())
    .execute(db)
    .await
    .unwrap();

    let mut tx = as_role().await;
    // Row-level security really applies to this role: a plain count finds
    // nothing, which is the vacuous pass the function must not fall for.
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(visible, 0);
    let err = sqlx::query("SELECT * FROM rename_service($1, 'otto-tower')")
        .bind(FACTORY)
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("has billing data under its meters: 1 usage_events"),
        "{err}"
    );
    drop(tx);

    sqlx::query("DELETE FROM usage_events WHERE meter IS NOT NULL")
        .execute(db)
        .await
        .unwrap();
    let mut tx = as_role().await;
    let moved: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT meters, service_pools, service_budgets, budget_alerts \
         FROM rename_service($1, 'otto-tower')",
    )
    .bind(FACTORY)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    // The opt-in is closed again for the rest of the transaction.
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM org_service_period_usage")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(moved, (1, 2, 2, 2));
    assert_eq!(visible, 0);
    for table in [
        "org_service_period_usage",
        "service_budgets",
        "budget_alerts",
    ] {
        assert_eq!(
            rows_with(&w.db, table, "service", "otto-tower").await,
            2,
            "{table}"
        );
    }
}

/// The function's own refusals that the Rust wrapper normally gets in first:
/// a malformed slug, and an org-pinned transaction (where the tenant policy
/// would show it one org's rows), here as the owning superuser so it is the
/// function refusing and not a missing grant.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_rename_function_refuses_a_bad_slug_and_a_pinned_transaction(pool: PgPool) {
    let w = metered_world(pool).await;
    let code = |e: sqlx::Error| e.as_database_error().unwrap().code().unwrap().into_owned();

    let err = sqlx::query("SELECT * FROM rename_service($1, 'Otto_Tower')")
        .bind(FACTORY)
        .fetch_all(w.db.pool())
        .await
        .unwrap_err();
    assert_eq!(code(err), "22023");

    let mut tx = w.db.pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('app.org_id', $1, true)")
        .bind(w.org.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = sqlx::query("SELECT * FROM rename_service($1, 'otto-tower')")
        .bind(FACTORY)
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(code(err), "0A000");
    drop(tx);
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);
}

/// After a rename nothing can be written under the old slug or meter keys:
/// the foreign keys of migration 0024 refuse it, whoever writes it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn nothing_can_be_written_under_a_renamed_slug(pool: PgPool) {
    let w = metered_world(pool).await;
    resources::rename_service(&w.db, FACTORY, "otto-tower")
        .await
        .unwrap();
    let org = w.org.as_uuid();
    for stmt in [
        format!(
            "INSERT INTO usage_events (org_id, tool, billable, meter, quantity) \
             VALUES ('{org}', 't', true, '{JOBS}', 1)"
        ),
        format!(
            "INSERT INTO org_meter_period_usage (org_id, meter, period_start, quantity) \
             VALUES ('{org}', '{JOBS}', date_trunc('month', now())::date, 1)"
        ),
        format!(
            "INSERT INTO org_service_period_usage (org_id, service, period_start) \
             VALUES ('{org}', 'otto-factory', date_trunc('month', now())::date)"
        ),
        format!(
            "INSERT INTO service_budgets (org_id, service, monthly_budget_cents) \
             VALUES ('{org}', 'otto-factory', 100)"
        ),
        format!(
            "INSERT INTO budget_alerts (org_id, service, period_start, threshold) \
             VALUES ('{org}', 'otto-factory', date_trunc('month', now())::date, 50)"
        ),
    ] {
        let err = sqlx::query(&stmt)
            .execute(w.db.pool())
            .await
            .expect_err(&stmt);
        assert!(
            err.as_database_error()
                .is_some_and(|d| d.is_foreign_key_violation()),
            "{stmt}: {err}"
        );
    }
}

/// An ingest transaction for `w.org`, shaped exactly as `POST
/// /internal/usage` runs one, that has counted one otto-factory event (metered
/// under `meter`, or not) and is still open.
async fn open_factory_ingest(w: &World, meter: Option<&'static str>) -> otto_tenant::Tx<'static> {
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{IngestOutcome, Metered, ShippedUsage, UsageExt};

    let mut tx = w.db.begin(w.org).await.unwrap();
    otto_billing::usage::lock_org_ingest(&mut tx).await.unwrap();
    let out = tx
        .ingest_usage_deferred(
            FACTORY,
            &ShippedUsage {
                event_id: Uuid::new_v4(),
                user: None,
                tool: "t",
                billable: true,
                occurred_at: Utc::now(),
                service: Some("otto-factory"),
                metered: meter.map(|meter| Metered { meter, quantity: 1 }),
            },
            &mut PendingBudgets::default(),
        )
        .await
        .unwrap();
    assert_eq!(out, IngestOutcome::Counted);
    tx
}

/// Waits until `task` is blocked on a lock in this test's database, as
/// Postgres reports it, and returns whether it is still unfinished. Panics
/// after a deadline: the task never came to wait on anything.
async fn waiting_on_a_lock<T>(pool: &PgPool, task: &tokio::task::JoinHandle<T>) -> bool {
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
            return !task.is_finished();
        }
        assert!(
            !task.is_finished(),
            "the task finished without waiting on a lock"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "nothing came to wait on a lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A rename started while an ingest transaction is open waits for it, and
/// then sees what it wrote: an unmetered event's pool is moved with the rest,
/// a metered one blocks the rename. Either way nothing is left under the old
/// slug.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_waits_for_an_open_ingest_and_then_counts_it(pool: PgPool) {
    let w = metered_world(pool).await;

    // Unmetered: the pool row it wrote moves.
    let ingest = open_factory_ingest(&w, None).await;
    let db = w.db.clone();
    let rename =
        tokio::spawn(async move { resources::rename_service(&db, FACTORY, "otto-tower").await });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);
    ingest.commit().await.unwrap();
    let renamed = rename.await.unwrap().unwrap();
    assert_eq!(renamed.moved.service_pools, 1);
    assert_eq!(service_pool(&w.db, "otto-tower").await, Some((1, 1)));
    assert_eq!(service_pool(&w.db, "otto-factory").await, None);

    // Metered: back to the old slug (nothing is metered yet), then the usage
    // an open ingest wrote blocks the rename.
    resources::rename_service(&w.db, FACTORY, "otto-factory")
        .await
        .unwrap();
    let ingest = open_factory_ingest(&w, Some(JOBS)).await;
    let db = w.db.clone();
    let rename =
        tokio::spawn(async move { resources::rename_service(&db, FACTORY, "otto-tower").await });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);
    ingest.commit().await.unwrap();
    let err = rename.await.unwrap().unwrap_err();
    assert!(
        err.to_string().ends_with(
            "has billing data under its meters: 1 usage_events, 1 org_meter_period_usage"
        ),
        "{err}"
    );
    assert_eq!(meter_quantity(&w.db, JOBS).await, Some(1));
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);
}

/// A batch in flight when a rename commits (it authenticated, and so read the
/// old slug, before the rename committed, and reached its writes after) is
/// refused with a retriable 503 and writes nothing. Resent, it is judged
/// against the new slug: the unmetered event counts in the otto-tower pool,
/// the event under the old meter key is `unknown_meter`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_batch_in_flight_across_a_rename_is_refused_retriably_and_strands_nothing(pool: PgPool) {
    let w = metered_world(pool).await;

    // The rename, run and held open: it holds the pool table lock that every
    // ingest statement needs.
    let mut rename = w.db.pool().begin().await.unwrap();
    sqlx::query("SELECT * FROM rename_service($1, 'otto-tower')")
        .bind(FACTORY)
        .fetch_all(&mut *rename)
        .await
        .unwrap();

    let batch = vec![
        usage_event(w.org, None, Uuid::new_v4(), true),
        metered(w.org, JOBS, Some(2)),
    ];
    let (db, auth, sent) = (w.db.clone(), w.factory_basic(), batch.clone());
    let ingest = tokio::spawn(async move {
        let res = otto_platform_server::router(db.clone(), otto_platform_server::Billing::Enabled)
            .oneshot(
                Request::post("/internal/usage")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "events": sent }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let retry_after = res.headers().get("retry-after").cloned();
        let status = res.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        (status, retry_after, body)
    });
    assert!(waiting_on_a_lock(w.db.pool(), &ingest).await);
    rename.commit().await.unwrap();

    let (status, retry_after, body) = ingest.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(retry_after.as_ref().map(|v| v.to_str().unwrap()), Some("5"));
    assert_eq!(body["error"], "temporarily_unavailable", "{body}");
    assert!(otto_resource::Error::Status {
        status: status.as_u16(),
        body: body.to_string(),
    }
    .is_retriable());
    for (table, column) in [
        ("org_service_period_usage", "service"),
        ("usage_events", "meter"),
        ("org_meter_period_usage", "meter"),
    ] {
        let value = if column == "service" {
            "otto-factory"
        } else {
            JOBS
        };
        assert_eq!(rows_with(&w.db, table, column, value).await, 0, "{table}");
    }
    let claimed: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_event_ids")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        claimed, 0,
        "a refused batch must leave its event ids unclaimed"
    );

    let (status, receipt) = post_usage(&w.db, &w.factory_basic(), batch).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["accepted"], 1, "{receipt}");
    assert_eq!(rejection_codes(&receipt), ["unknown_meter"]);
    assert_eq!(service_pool(&w.db, "otto-tower").await, Some((1, 1)));
    assert_eq!(service_pool(&w.db, "otto-factory").await, None);
}

/// A cancelled CONCURRENTLY build leaves `usage_events_meter` invalid, and
/// 0025 never retries it; without it the rename's lookups are full scans run
/// while all ingest waits, so it refuses until the index is repaired.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_refuses_while_the_meter_index_is_invalid(pool: PgPool) {
    let w = metered_world(pool).await;
    let set_valid = |valid: bool| {
        let db = w.db.clone();
        async move {
            sqlx::query(
                "UPDATE pg_index SET indisvalid = $1 \
                 WHERE indexrelid = 'usage_events_meter'::regclass",
            )
            .bind(valid)
            .execute(db.pool())
            .await
            .unwrap();
        }
    };
    set_valid(false).await;
    let err = run_resource_cmd(&w.db, &format!("rename-service {FACTORY} otto-tower"))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("run REINDEX INDEX CONCURRENTLY usage_events_meter"),
        "{err}"
    );
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);

    set_valid(true).await;
    resources::rename_service(&w.db, FACTORY, "otto-tower")
        .await
        .unwrap();
}

/// With shipping not paused, an ingest transaction holding the pool table
/// makes the rename give up after its short lock_timeout, saying so, rather
/// than queue every ingest behind it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_gives_up_quickly_while_ingest_holds_the_tables(pool: PgPool) {
    let w = metered_world(pool).await;
    let ingest = open_factory_ingest(&w, None).await;
    let err = resources::rename_service(&w.db, FACTORY, "otto-tower")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("usage shipping is not paused"),
        "{err}"
    );
    ingest.commit().await.unwrap();
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);
    assert_eq!(service_pool(&w.db, "otto-factory").await, Some((1, 1)));
}

/// Stripe data for an old meter written while the rename runs (after its
/// blocker count) fails the rename on the Stripe table's foreign key, which
/// is reported as billing data appearing, with nothing changed.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn stripe_data_appearing_mid_rename_fails_it_cleanly(pool: PgPool) {
    let w = metered_world(pool).await;
    let mut stripe = w.db.pool().begin().await.unwrap();
    sqlx::query(
        "INSERT INTO stripe_meters (meter, stripe_meter_id, event_name) \
         VALUES ($1, 'mtr_1', 'otto_factory__jobs')",
    )
    .bind(JOBS)
    .execute(&mut *stripe)
    .await
    .unwrap();
    // The uncommitted row is invisible to the blocker count, and its key lock
    // on the meter makes the rename's key update wait.
    let db = w.db.clone();
    let rename =
        tokio::spawn(async move { resources::rename_service(&db, FACTORY, "otto-tower").await });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);
    stripe.commit().await.unwrap();
    let err = rename.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("billing data appeared"), "{err}");
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);
    assert_eq!(
        resources::get(&w.db, FACTORY)
            .await
            .unwrap()
            .unwrap()
            .service
            .as_deref(),
        Some("otto-factory")
    );
}

/// `set-service` (allowed only before any meter is declared) carries the
/// service's unmetered pools to the new slug, and refuses, saying why, when a
/// pool an earlier service of the target name left behind is in the way.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_service_carries_pools_and_refuses_an_orphan_pool_in_the_way(pool: PgPool) {
    let w = world(pool).await;
    resources::set_service(&w.db, FACTORY, "otto-a")
        .await
        .unwrap();
    unmetered_factory_usage(&w, w.org).await;

    let out = run_resource_cmd(&w.db, &format!("set-service {FACTORY} otto-b"))
        .await
        .unwrap();
    assert!(out.contains("service=otto-b"), "{out}");
    assert_eq!(service_pool(&w.db, "otto-b").await, Some((1, 1)));
    assert_eq!(service_pool(&w.db, "otto-a").await, None);

    // A pool from before migration 0024's foreign keys, under a slug no
    // resource server holds; the fixture skips the key as that row did.
    let mut tx = w.db.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO org_service_period_usage (org_id, service, period_start) \
         VALUES ($1, 'otto-c', date_trunc('month', now() AT TIME ZONE 'utc')::date)",
    )
    .bind(w.org.as_uuid())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let err = run_resource_cmd(&w.db, &format!("set-service {FACTORY} otto-c"))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("usage pools from an earlier service"),
        "{err}"
    );
    assert!(
        !err.to_string().contains("another resource server"),
        "{err}"
    );
    assert_eq!(service_pool(&w.db, "otto-b").await, Some((1, 1)));
}

// ------------------------------------------------------ resource URI rename

/// Where otto-factory moves to in these tests.
const TOWER: &str = "https://otto-tower.example/mcp";

fn alias_sunset() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::days(90)
}

/// Moves otto-factory to `TOWER`, leaving `FACTORY` a live alias.
async fn rename_factory(w: &World) {
    resources::rename(
        &w.db,
        FACTORY,
        TOWER,
        Some(alias_sunset()),
        Some("otto-tower"),
    )
    .await
    .unwrap();
}

async fn set_alias_sunset(db: &Db, alias: &str, sql_offset: &str) {
    sqlx::query(&format!(
        "UPDATE resource_server_aliases SET sunset_at = now() + interval '{sql_offset}' \
         WHERE alias_uri = $1"
    ))
    .bind(alias)
    .execute(db.pool())
    .await
    .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn after_a_rename_the_caller_gets_the_audience_it_authenticated_as(pool: PgPool) {
    let w = world(pool).await;
    let before = w.oauth_token(FACTORY, &["jobs:read"]).await;
    rename_factory(&w).await;
    let after = w.oauth_token(TOWER, &["jobs:read"]).await;

    let bearer = format!("Bearer {}", w.factory_secret);
    for (auth, aud) in [
        // The running binary, still configured with the old URI.
        (basic(FACTORY, &w.factory_secret), FACTORY),
        // The binary after its env flips to the new URI.
        (basic(TOWER, &w.factory_secret), TOWER),
        // Bearer names no URI: canonical.
        (bearer, TOWER),
    ] {
        for token in [&before, &after] {
            let (status, body) = introspect(&w.db, Some(&auth), token).await;
            assert_eq!(status, StatusCode::OK, "{aud}");
            assert_eq!(body["active"], true, "{aud}: {body}");
            assert_eq!(body["aud"], aud);
            assert_eq!(body["sub"], w.user.to_string());
        }
    }

    // The alias is not a way to read a sibling's tokens.
    let flags_token = w.oauth_token(FLAGS, &["flags:read"]).await;
    let (_, body) = introspect(&w.db, Some(&w.factory_basic()), &flags_token).await;
    assert_eq!(body, json!({ "active": false }));
    // Nor a way in with a sibling's credential.
    let (status, _) = introspect(&w.db, Some(&basic(FACTORY, &w.flags_secret)), &before).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_old_binarys_client_keeps_working_through_the_alias(pool: PgPool) {
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;
    rename_factory(&w).await;

    // otto-resource checks `aud` against its own configured URI, so this is
    // what the running otto-factory sees between the rename and its env flip.
    let old = PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();
    let claims = old.introspect(&token).await.unwrap().expect("active");
    assert_eq!(claims.resource, FACTORY);
    let new = PlatformClient::new(ClientConfig::new(&base, TOWER, &w.factory_secret)).unwrap();
    let claims = new.introspect(&token).await.unwrap().expect("active");
    assert_eq!(claims.resource, TOWER);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_expired_or_dropped_alias_fails_authentication(pool: PgPool) {
    let w = world(pool).await;
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;
    rename_factory(&w).await;
    let usage_status = format!("/internal/orgs/{}/usage-status", w.org);
    let tower = basic(TOWER, &w.factory_secret);

    set_alias_sunset(&w.db, FACTORY, "-1 second").await;
    let (status, body) = introspect(&w.db, Some(&w.factory_basic()), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(
        get(&w.db, &w.factory_basic(), &usage_status).await.0,
        StatusCode::UNAUTHORIZED
    );
    // The canonical URI is unaffected.
    assert_eq!(
        introspect(&w.db, Some(&tower), &token).await.1["active"],
        true
    );

    set_alias_sunset(&w.db, FACTORY, "1 day").await;
    assert_eq!(
        introspect(&w.db, Some(&w.factory_basic()), &token).await.0,
        StatusCode::OK
    );
    resources::drop_alias(&w.db, FACTORY).await.unwrap();
    let (status, body) = introspect(&w.db, Some(&w.factory_basic()), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "dropped");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(
        get(&w.db, &w.factory_basic(), &usage_status).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        introspect(&w.db, Some(&tower), &token).await.1["active"],
        true
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn usage_through_the_alias_dedupes_against_the_canonical_uri(pool: PgPool) {
    let w = world(pool).await;
    let (shipped, fresh) = (Uuid::new_v4(), Uuid::new_v4());
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![usage_event(w.org, None, shipped, true)],
    )
    .await;
    assert_eq!(r["accepted"], 1);
    rename_factory(&w).await;

    // The old binary resends the batch (its response was lost) plus a new one.
    let batch = vec![
        usage_event(w.org, None, shipped, true),
        usage_event(w.org, None, fresh, true),
    ];
    let (status, r) = post_usage(&w.db, &w.factory_basic(), batch.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(r, json!({ "accepted": 1, "duplicates": 1, "rejected": [] }));
    // After the env flip it resends again under the new URI.
    let (_, r) = post_usage(&w.db, &basic(TOWER, &w.factory_secret), batch).await;
    assert_eq!(r, json!({ "accepted": 0, "duplicates": 2, "rejected": [] }));

    // Everything is keyed by the canonical URI.
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", FACTORY).await,
        0
    );
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", TOWER).await,
        2
    );
    let shipped_under: Vec<Option<String>> =
        sqlx::query_scalar("SELECT resource_uri FROM usage_events ORDER BY created_at")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        shipped_under,
        [Some(FACTORY.to_owned()), Some(TOWER.to_owned())],
        "history keeps the URI it was shipped under; new usage is canonical"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_renames_shows_and_drops_aliases(pool: PgPool) {
    let w = world(pool).await;
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    // A sunset is required, and must be RFC 3339.
    let err = run_resource_cmd(&w.db, &format!("rename {FACTORY} {TOWER}"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--alias-until"), "{err}");
    assert!(run_resource_cmd(
        &w.db,
        &format!("rename {FACTORY} {TOWER} --alias-until 2099-01-01")
    )
    .await
    .is_err());
    // Onto another server's URI.
    assert!(run_resource_cmd(
        &w.db,
        &format!("rename {FACTORY} {FLAGS} --alias-until 2099-01-01T00:00:00Z")
    )
    .await
    .is_err());

    let out = run_resource_cmd(
        &w.db,
        &format!("rename {FACTORY} {TOWER} --alias-until 2099-01-01T00:00:00Z --name otto-tower"),
    )
    .await
    .unwrap();
    assert!(
        out.contains(&format!("renamed {FACTORY} -> {TOWER} (otto-tower)")),
        "{out}"
    );
    let alias_line = format!("  alias {FACTORY}\tsunset=2099-01-01T00:00:00Z\tlive");
    assert!(out.contains(&alias_line), "{out}");
    assert!(out.contains("1 access token(s)"), "{out}");

    // `list` shows the alias under its server, as the runbook checks.
    let list = run_resource_cmd(&w.db, "list").await.unwrap();
    let lines: Vec<&str> = list.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(&format!("{TOWER}\totto-tower\tenabled")))
        .unwrap_or_else(|| panic!("{list}"));
    assert_eq!(lines[at + 1], alias_line, "{list}");
    assert!(!list.lines().any(|l| l.starts_with(FACTORY)), "{list}");
    let described = run_resource_cmd(
        &w.db,
        &format!("describe {TOWER} --scope-description jobs:read=Read"),
    )
    .await
    .unwrap();
    assert!(described.contains(&alias_line), "{described}");

    // Registering the retired URI is refused.
    let err = run_resource_cmd(
        &w.db,
        &format!("register {FACTORY} --name squatter --scopes x"),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("never reused"), "{err}");

    // The rollback swaps the two back, then forward again.
    let out = run_resource_cmd(
        &w.db,
        &format!("rename {TOWER} {FACTORY} --name otto-factory"),
    )
    .await
    .unwrap();
    assert!(
        out.contains(&format!("swapped {TOWER} -> {FACTORY}")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "  alias {TOWER}\tsunset=2099-01-01T00:00:00Z\tlive"
        )),
        "{out}"
    );
    assert_eq!(
        introspect(&w.db, Some(&w.factory_basic()), &token).await.1["aud"],
        FACTORY
    );
    run_resource_cmd(&w.db, &format!("rename {FACTORY} {TOWER}"))
        .await
        .unwrap();

    let out = run_resource_cmd(&w.db, &format!("drop-alias {FACTORY}"))
        .await
        .unwrap();
    assert!(
        out.contains(&format!(
            "  alias {FACTORY}\tsunset=2099-01-01T00:00:00Z\tdropped"
        )),
        "{out}"
    );
    assert!(run_resource_cmd(&w.db, "list")
        .await
        .unwrap()
        .contains(&format!(
            "  alias {FACTORY}\tsunset=2099-01-01T00:00:00Z\tdropped"
        )));
    assert_eq!(
        introspect(&w.db, Some(&w.factory_basic()), &token).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(run_resource_cmd(&w.db, &format!("drop-alias {TOWER}"))
        .await
        .is_err());
}

/// An open ingest transaction for `w.org` that has claimed `event` under
/// `uri` (unmetered, no service), shaped as `POST /internal/usage` runs one.
async fn open_unmetered_ingest(w: &World, uri: &str, event: Uuid) -> otto_tenant::Tx<'static> {
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{IngestOutcome, ShippedUsage, UsageExt};

    let mut tx = w.db.begin(w.org).await.unwrap();
    otto_billing::usage::lock_org_ingest(&mut tx).await.unwrap();
    let out = tx
        .ingest_usage_deferred(
            uri,
            &ShippedUsage {
                event_id: event,
                user: None,
                tool: "t",
                billable: true,
                occurred_at: Utc::now(),
                service: None,
                metered: None,
            },
            &mut PendingBudgets::default(),
        )
        .await
        .unwrap();
    assert_eq!(out, IngestOutcome::Counted);
    tx
}

/// A claim made under the old URI and still uncommitted when the rename
/// starts: the rename waits for it, then rewrites it, so the event cannot be
/// counted again under the new URI.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_uri_rename_waits_for_an_open_claim_and_then_rewrites_it(pool: PgPool) {
    let w = world(pool).await;
    let event = Uuid::new_v4();
    let ingest = open_unmetered_ingest(&w, FACTORY, event).await;

    let db = w.db.clone();
    let rename = tokio::spawn(async move {
        resources::rename(&db, FACTORY, TOWER, Some(alias_sunset()), None).await
    });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);
    ingest.commit().await.unwrap();
    let renamed = rename.await.unwrap().unwrap();
    assert_eq!(renamed.rewritten.usage_event_ids, 1);

    let (_, r) = post_usage(
        &w.db,
        &basic(TOWER, &w.factory_secret),
        vec![usage_event(w.org, None, event, true)],
    )
    .await;
    assert_eq!(r, json!({ "accepted": 0, "duplicates": 1, "rejected": [] }));
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", FACTORY).await,
        0
    );
}

/// A claim that arrives while a rename is running (here: a transaction holding
/// the rename's lock with the rename written but not committed) waits for it,
/// then files under the new canonical URI, though the batch authenticated
/// against the old one.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_claim_during_a_uri_rename_waits_and_files_under_the_new_uri(pool: PgPool) {
    let w = world(pool).await;
    let event = Uuid::new_v4();
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![usage_event(w.org, None, event, true)],
    )
    .await;
    assert_eq!(r["accepted"], 1);

    // The rename's steps, held open: the ledger locks of both URIs, as
    // `resources::rename` takes them, then its writes.
    let mut renaming = w.db.pool().begin().await.unwrap();
    for uri in [FACTORY, TOWER] {
        sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
            .bind(resources::USAGE_LEDGER_LOCK_NAMESPACE)
            .bind(uri)
            .execute(&mut *renaming)
            .await
            .unwrap();
    }
    for (sql, binds) in [
        (
            "UPDATE resource_servers SET resource_uri = $2 WHERE resource_uri = $1",
            [FACTORY, TOWER],
        ),
        (
            "INSERT INTO resource_server_aliases (alias_uri, resource_uri, sunset_at) \
             VALUES ($1, $2, now() + interval '1 day')",
            [FACTORY, TOWER],
        ),
        (
            "UPDATE usage_event_ids SET resource_uri = $2 WHERE resource_uri = $1",
            [FACTORY, TOWER],
        ),
    ] {
        sqlx::query(sql)
            .bind(binds[0])
            .bind(binds[1])
            .execute(&mut *renaming)
            .await
            .unwrap();
    }

    // The old binary resends the event under the old URI, which (as far as
    // anything committed says) is still canonical, with a new one.
    let fresh = Uuid::new_v4();
    let db = w.db.clone();
    let auth = w.factory_basic();
    let org = w.org;
    let resend = tokio::spawn(async move {
        post_usage(
            &db,
            &auth,
            vec![
                usage_event(org, None, event, true),
                usage_event(org, None, fresh, true),
            ],
        )
        .await
    });
    assert!(waiting_on_a_lock(w.db.pool(), &resend).await);
    renaming.commit().await.unwrap();
    let (status, r) = resend.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(r, json!({ "accepted": 1, "duplicates": 1, "rejected": [] }));
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", FACTORY).await,
        0
    );
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", TOWER).await,
        2
    );
    // The new event's usage row is canonical too, though its batch
    // authenticated as the old URI; the one shipped before keeps its URI.
    let shipped_under: Vec<Option<String>> =
        sqlx::query_scalar("SELECT resource_uri FROM usage_events ORDER BY created_at")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        shipped_under,
        [Some(FACTORY.to_owned()), Some(TOWER.to_owned())]
    );
}

// ------------------------------------------------ lock order (otto_auth::resources)

/// An org deletion revokes the org's tokens, then enqueues its lifecycle
/// event, which takes `FOR KEY SHARE` on every resource server row with a
/// webhook. A URI rename started in between waits for the deletion's token
/// rows without holding the server's row, so the deletion's event goes
/// through and both commit. (Locking the server's row first deadlocked here.)
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_uri_rename_and_an_org_deletion_do_not_deadlock(pool: PgPool) {
    use otto_core::lifecycle::{self, LifecycleEvent};

    let w = world(pool).await;
    resources::set_webhook(&w.db, &cipher(), FACTORY, Some("https://hooks.example/h"))
        .await
        .unwrap();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    // `delete_org`'s steps, held open before its event.
    let mut deleting = w.db.begin(w.org).await.unwrap();
    sqlx::query("UPDATE orgs SET deleted_at = now() WHERE id = $1")
        .bind(w.org)
        .execute(deleting.conn())
        .await
        .unwrap();
    for table in ["access_tokens", "refresh_tokens"] {
        sqlx::query(&format!(
            "UPDATE {table} SET revoked_at = now() WHERE org_id = $1 AND revoked_at IS NULL"
        ))
        .bind(w.org)
        .execute(deleting.conn())
        .await
        .unwrap();
    }

    let db = w.db.clone();
    let rename = tokio::spawn(async move {
        resources::rename(&db, FACTORY, TOWER, Some(alias_sunset()), None).await
    });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);

    lifecycle::enqueue(deleting.conn(), &LifecycleEvent::OrgDeleted { org: w.org })
        .await
        .expect("the deletion's event must not wait on the rename");
    deleting.commit().await.unwrap();
    let renamed = rename
        .await
        .unwrap()
        .expect("the rename finishes after the deletion");
    // The token was revoked by then, so nothing usable was left to rewrite.
    assert_eq!(renamed.rewritten.access_tokens, 0);
    assert_eq!(
        introspect(&w.db, Some(&basic(TOWER, &w.factory_secret)), &token)
            .await
            .1["active"],
        false
    );
    // The deletion's delivery moved with the server.
    assert_eq!(
        rows_with(&w.db, "webhook_deliveries", "resource_uri", TOWER).await,
        1
    );
}

/// The member-removal route revokes the member's tokens before it enqueues
/// the event, the same order, so it cannot deadlock with a rename either.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_uri_rename_and_a_member_removal_do_not_deadlock(pool: PgPool) {
    use otto_core::lifecycle::{self, LifecycleEvent};

    let w = world(pool).await;
    resources::set_webhook(&w.db, &cipher(), FACTORY, Some("https://hooks.example/h"))
        .await
        .unwrap();
    w.oauth_token(FACTORY, &["jobs:read"]).await;

    let mut removing = w.db.begin(w.org).await.unwrap();
    otto_auth::tokens::revoke_all_in_org_tx(removing.conn(), w.user, w.org)
        .await
        .unwrap();
    let db = w.db.clone();
    let rename = tokio::spawn(async move {
        resources::rename(&db, FACTORY, TOWER, Some(alias_sunset()), None).await
    });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);
    lifecycle::enqueue(
        removing.conn(),
        &LifecycleEvent::MemberRemoved {
            org: w.org,
            user: w.user,
        },
    )
    .await
    .unwrap();
    removing.commit().await.unwrap();
    rename.await.unwrap().unwrap();
}

/// The usage-ledger lock is per URI: a rename queued behind one server's
/// claim in flight holds up only that server. Another server's ingest goes
/// straight through (with one global lock it queued behind the rename's
/// exclusive request).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_uri_rename_does_not_hold_up_another_servers_ingest(pool: PgPool) {
    let w = world(pool).await;
    assert_ne!(
        resources::USAGE_LEDGER_LOCK_NAMESPACE,
        otto_billing::usage::INGEST_LOCK_NAMESPACE,
        "the two two-key advisory locks must not share a key space"
    );
    let ingest = open_unmetered_ingest(&w, FACTORY, Uuid::new_v4()).await;
    let db = w.db.clone();
    let rename = tokio::spawn(async move {
        resources::rename(&db, FACTORY, TOWER, Some(alias_sunset()), None).await
    });
    assert!(waiting_on_a_lock(w.db.pool(), &rename).await);

    // Another org, so the open ingest's org lock is not what it waits for.
    let other = w.db.create_org("globex", "Globex").await.unwrap().id;
    authorize_both(&w.db, other).await;
    let (status, r) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        post_usage(
            &w.db,
            &w.flags_basic(),
            vec![usage_event(other, None, Uuid::new_v4(), true)],
        ),
    )
    .await
    .expect("otto-flags' ingest waited for otto-factory's rename");
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["accepted"], 1);

    assert!(!rename.is_finished());
    ingest.commit().await.unwrap();
    rename.await.unwrap().unwrap();
}

/// An ingest that waits past its lock timeout (here for a rename's ledger
/// lock held open) gives up with a retriable 503 rather than a 500, having
/// recorded nothing, and the resend after the rename is counted once.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_ingest_that_waits_too_long_is_a_retriable_503(pool: PgPool) {
    let w = world(pool).await;
    let mut renaming = w.db.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(resources::USAGE_LEDGER_LOCK_NAMESPACE)
        .bind(FACTORY)
        .execute(&mut *renaming)
        .await
        .unwrap();

    let event = usage_event(w.org, None, Uuid::new_v4(), true);
    let (status, body) = post_usage(&w.db, &w.factory_basic(), vec![event.clone()]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable", "{body}");
    assert_eq!(
        rows_with(&w.db, "usage_event_ids", "resource_uri", FACTORY).await,
        0
    );

    renaming.rollback().await.unwrap();
    let (status, r) = post_usage(&w.db, &w.factory_basic(), vec![event]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(r, json!({ "accepted": 1, "duplicates": 0, "rejected": [] }));
}

/// An open ingest transaction that updated an existing pool row and then
/// writes a new period's pool row (which takes `FOR KEY SHARE` on the server's
/// row) cannot deadlock with `set-service`: set-service waits for the ingest's
/// table lock before it touches the server's row, then carries both pools.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_service_and_an_open_ingest_do_not_deadlock(pool: PgPool) {
    let w = world(pool).await;
    resources::set_service(&w.db, FACTORY, "otto-factory")
        .await
        .unwrap();
    // This month's pool, then an ingest that updates it, held open.
    open_factory_ingest(&w, None).await.commit().await.unwrap();
    let mut ingest = open_factory_ingest(&w, None).await;

    let db = w.db.clone();
    let set = tokio::spawn(async move { resources::set_service(&db, FACTORY, "otto-b").await });
    assert!(waiting_on_a_lock(w.db.pool(), &set).await);

    // A new period's pool row, as an event of another month writes one.
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        sqlx::query(
            "INSERT INTO org_service_period_usage \
               (org_id, service, period_start, billable_count, total_count) \
             VALUES ($1, 'otto-factory', DATE '2000-01-01', 1, 1)",
        )
        .bind(w.org)
        .execute(ingest.conn()),
    )
    .await
    .expect("the ingest waited on set-service")
    .unwrap();
    ingest.commit().await.unwrap();

    let rs = set.await.unwrap().unwrap();
    assert_eq!(rs.service.as_deref(), Some("otto-b"));
    assert_eq!(
        rows_with(&w.db, "org_service_period_usage", "service", "otto-b").await,
        2
    );
}

/// `set-service` takes the service tables before the server's row, as
/// rename-service does: with a rename-service's table lock held, it waits on
/// the table without holding the row, so the rename-service's next step (the
/// row) goes through instead of deadlocking.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn set_service_and_rename_service_take_locks_in_one_order(pool: PgPool) {
    let w = world(pool).await;
    let mut renaming = w.db.pool().begin().await.unwrap();
    sqlx::query(
        "LOCK TABLE org_service_period_usage, service_budgets, budget_alerts \
         IN SHARE ROW EXCLUSIVE MODE",
    )
    .execute(&mut *renaming)
    .await
    .unwrap();

    let db = w.db.clone();
    let set = tokio::spawn(async move { resources::set_service(&db, FACTORY, "otto-a").await });
    assert!(waiting_on_a_lock(w.db.pool(), &set).await);
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        sqlx::query("SELECT 1 FROM resource_servers WHERE resource_uri = $1 FOR UPDATE")
            .bind(FACTORY)
            .execute(&mut *renaming),
    )
    .await
    .expect("set-service held the row while waiting for the tables")
    .unwrap();
    renaming.commit().await.unwrap();
    let rs = set.await.unwrap().unwrap();
    assert_eq!(rs.service.as_deref(), Some("otto-a"));
}

// ------------------------------------------------ read-only preflight

/// `show` reads only: the service, its meters, its aliases and what blocks
/// rename-service, and it changes nothing (unlike `describe`, which writes).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_operator_cli_shows_a_resource_server_without_changing_it(pool: PgPool) {
    let w = metered_world(pool).await;
    resources::set_scope_descriptions(&w.db, FACTORY, &[("jobs:read", "Read jobs")])
        .await
        .unwrap();
    let before = resources::get(&w.db, FACTORY).await.unwrap().unwrap();

    let out = run_resource_cmd(&w.db, &format!("show {FACTORY}"))
        .await
        .unwrap();
    assert!(
        out.starts_with(&format!(
            "{FACTORY}\totto-factory\tenabled\twebhook=-\tservice=otto-factory\n"
        )),
        "{out}"
    );
    assert!(out.contains("scopes: jobs:read admin"), "{out}");
    assert!(
        out.contains(&format!("  meter {JOBS}\tJobs completed\tunit=job")),
        "{out}"
    );
    assert!(
        out.contains(
            "rename-service blockers: 0 usage_events, 0 org_meter_period_usage, \
             0 stripe_meters, 0 stripe_prices, 0 stripe_meter_outbox (none: it may be renamed)"
        ),
        "{out}"
    );

    // A metered event in another org is a blocker it counts.
    let other = w.db.create_org("globex", "Globex").await.unwrap().id;
    authorize_both(&w.db, other).await;
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![metered(other, JOBS, Some(2))],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
    let out = run_resource_cmd(&w.db, &format!("show {FACTORY}"))
        .await
        .unwrap();
    assert!(
        out.contains("blockers: 1 usage_events, 1 org_meter_period_usage"),
        "{out}"
    );
    assert!(out.contains("(it cannot be renamed)"), "{out}");

    // Aliases, with their state.
    rename_factory(&w).await;
    let out = run_resource_cmd(&w.db, &format!("show {TOWER}"))
        .await
        .unwrap();
    assert!(
        out.contains(&format!("  alias {FACTORY}\tsunset=")),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("  alias {FACTORY}")) && l.ends_with("\tlive")),
        "{out}"
    );
    // By its canonical URI only.
    assert!(run_resource_cmd(&w.db, &format!("show {FACTORY}"))
        .await
        .is_err());

    // Nothing it read was written.
    let after = resources::get(&w.db, TOWER).await.unwrap().unwrap();
    assert_eq!(after.scope_descriptions, before.scope_descriptions);
    assert_eq!(after.service, before.service);

    // A server with no service says so.
    resources::register(
        &w.db,
        ResourceServerSpec {
            resource_uri: "https://bare.example/mcp",
            name: "bare",
            scopes: &["x"],
            default_scopes: &[],
        },
    )
    .await
    .unwrap();
    let out = run_resource_cmd(&w.db, "show https://bare.example/mcp")
        .await
        .unwrap();
    assert!(out.contains("meters: none (no service"), "{out}");
}

/// `rename-service --dry-run` runs the real checks and always rolls back:
/// it prints what would move, or why it is refused, and changes nothing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rename_service_dry_run_reports_and_changes_nothing(pool: PgPool) {
    let w = metered_world(pool).await;
    budget(&w.db, w.org, "otto-factory").await;
    unmetered_factory_usage(&w, w.org).await;

    let out = run_resource_cmd(
        &w.db,
        &format!("rename-service {FACTORY} otto-tower --dry-run"),
    )
    .await
    .unwrap();
    assert!(
        out.contains(&format!(
            "dry run: would rename {FACTORY} service=otto-factory -> otto-tower"
        )),
        "{out}"
    );
    assert!(
        out.contains("would move: 1 meter(s), 0 price version(s), 1 usage pool(s), 1 budget(s)"),
        "{out}"
    );
    assert!(out.contains("nothing changed"), "{out}");
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);
    assert_eq!(rows_with(&w.db, "meters", "key", TOWER_JOBS).await, 0);
    assert_eq!(
        service_pool(&w.db, "otto-factory").await.map(|p| p.1),
        Some(1)
    );
    assert_eq!(
        resources::get(&w.db, FACTORY)
            .await
            .unwrap()
            .unwrap()
            .service
            .as_deref(),
        Some("otto-factory")
    );

    // The same slug, and a refusal, are answers too.
    let out = run_resource_cmd(
        &w.db,
        &format!("rename-service {FACTORY} otto-factory --dry-run"),
    )
    .await
    .unwrap();
    assert!(out.contains("nothing would change"), "{out}");
    let (_, r) = post_usage(
        &w.db,
        &w.factory_basic(),
        vec![metered(w.org, JOBS, Some(1))],
    )
    .await;
    assert_eq!(r["accepted"], 1, "{r}");
    // A refusal prints why and fails the command (a non-zero exit).
    let (out, err) = run_resource_cmd_output(
        &w.db,
        &format!("rename-service {FACTORY} otto-tower --dry-run"),
    )
    .await;
    assert!(err.is_some(), "{out}");
    assert!(out.contains("dry run: refused by its data:"), "{out}");
    assert!(out.contains("1 usage_events"), "{out}");
    assert_eq!(rows_with(&w.db, "meters", "key", JOBS).await, 1);

    // A lost lock wait is told apart from a refusal: an ingest holding the
    // service tables makes the dry run give up after its 2 s lock timeout.
    sqlx::query("DELETE FROM usage_events WHERE meter IS NOT NULL")
        .execute(w.db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM org_meter_period_usage")
        .execute(w.db.pool())
        .await
        .unwrap();
    let ingest = open_factory_ingest(&w, None).await;
    let (out, err) = run_resource_cmd_output(
        &w.db,
        &format!("rename-service {FACTORY} otto-tower --dry-run"),
    )
    .await;
    ingest.commit().await.unwrap();
    assert!(err.is_some(), "{out}");
    assert!(out.contains("dry run: busy, gave up waiting"), "{out}");
    assert!(!out.contains("refused"), "{out}");

    // Not a registered resource is still an error.
    assert!(run_resource_cmd(
        &w.db,
        "rename-service https://nope.example/mcp otto-nope --dry-run"
    )
    .await
    .is_err());
}
