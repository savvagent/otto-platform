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
    World {
        db,
        flags_secret: secrets.pop().unwrap(),
        factory_secret: secrets.pop().unwrap(),
        org: org.id,
        user: user.id,
    }
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
    let res = otto_platform_server::router(db.clone())
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
        Some(basic(FACTORY, "otto_rs_wrong")),
        // Flags' secret presented as the factory.
        Some(basic(FACTORY, &w.flags_secret)),
        Some(basic("https://nobody.example/mcp", &w.factory_secret)),
        Some("Bearer otto_rs_wrong".to_owned()),
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
    assert_eq!(body["hard_stop"], true);
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
        let (status, _) = get(&w.db, "Bearer otto_rs_nope", &path).await;
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
    assert!(secret.starts_with("otto_whsec_"));

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
    assert!(otto_resource::webhook::verify("otto_whsec_other", sig, body).is_err());
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
    let app = otto_platform_server::router(db.clone());
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

    let client = PlatformClient::new(ClientConfig::new(&base, FACTORY, "otto_rs_wrong")).unwrap();
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
    let w = world(pool).await;
    let base = serve(&w.db).await;
    let mut cfg = ClientConfig::new(&base, FACTORY, &w.factory_secret);
    cfg.member_ttl = std::time::Duration::from_millis(400);
    cfg.member_negative_ttl = std::time::Duration::from_millis(400);
    let client = PlatformClient::new(cfg).unwrap();
    let (org, user) = (w.org.as_uuid(), w.user.as_uuid());

    let mut tx = w.db.begin(w.org).await.unwrap();
    let team = tx.create_team("platform", "Platform").await.unwrap();
    tx.add_team_member(team.id, w.user).await.unwrap();
    tx.commit().await.unwrap();
    let newcomer = w.db.upsert_user("new@acme.example", None).await.unwrap();

    assert_eq!(
        client.member(org, user).await.unwrap().unwrap().role,
        otto_resource::Role::Admin
    );
    assert_eq!(
        client.member_teams(org, user).await.unwrap().unwrap().len(),
        1
    );
    // Not a member yet; remembered.
    assert!(client
        .member(org, newcomer.id.as_uuid())
        .await
        .unwrap()
        .is_none());

    // Platform-side changes are invisible inside the TTL...
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

    // ...and visible after it.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert_eq!(
        client.member(org, user).await.unwrap().unwrap().role,
        otto_resource::Role::Member
    );
    assert!(client
        .member_teams(org, user)
        .await
        .unwrap()
        .unwrap()
        .is_empty());
    assert!(client
        .member(org, newcomer.id.as_uuid())
        .await
        .unwrap()
        .is_some());

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
    };
    assert!(!s.is_blocked());
    s.billable_count = 500;
    assert!(s.is_blocked());
    s.hard_stop = false;
    assert!(!s.is_blocked() && s.over_limit());
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
    let secret = secret_in(&run(&format!("rotate-secret {FLAGS}")).await, "otto_rs_");
    let hook = run(&format!("set-webhook {FLAGS} https://flags.example/hooks")).await;
    secret_in(&hook, "otto_whsec_");
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
    let newer = secret_in(&run(&format!("rotate-secret {FLAGS}")).await, "otto_rs_");
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
        "storing a signing secret needs OTTO_ENCRYPTION_KEY"
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
async fn a_late_event_is_counted_in_the_month_it_happened(pool: PgPool) {
    let w = world(pool).await;
    let when = otto_billing::usage::earliest_occurred_at(Utc::now()) + chrono::Duration::hours(1);
    let mut ev = usage_event(w.org, None, Uuid::new_v4(), true);
    ev["occurred_at"] = json!(when);
    assert_eq!(
        post_usage(&w.db, &w.factory_basic(), vec![ev]).await.1["accepted"],
        1
    );

    let periods: Vec<(chrono::NaiveDate, i64)> =
        sqlx::query_as("SELECT period_start, billable_count FROM org_period_usage")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(periods, [(when.date_naive().with_day_one(), 1)]);
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
    assert!(otto_resource::looks_like_token(&oauth), "{oauth}");
    assert!(otto_resource::looks_like_token(&pat), "{pat}");

    for junk in [
        "",
        "Bearer x",
        "otto_at_short",
        "otto_rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "otto_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "otto_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!A",
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
    assert!(client.introspect("otto_at_x").await.unwrap().is_none());
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
    };
    let app = || otto_platform_server::app(w.db.clone(), &config).unwrap();
    let token = w.oauth_token(FACTORY, &["jobs:read"]).await;

    // Control: the guard is live on the browser surface for this same request shape.
    let res = app()
        .oneshot(
            Request::post("/api/auth/logout")
                .header("origin", "https://evil.example")
                .header("cookie", "__Host-otto_session=x")
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
                .header("cookie", "__Host-otto_session=x")
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
