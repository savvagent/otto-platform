//! Per-service budgets at ingest and in usage-status, end to end against a
//! real Postgres: alerts fire exactly once per threshold and period, emails go
//! to owners and admins only, a hard stop blocks only its own service, and
//! nothing about budgets can fail an event.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use otto_auth::resources::{self, ResourceServerSpec};
use otto_core::orgs::{OrgsExt, Role};
use otto_resource::{ClientConfig, PlatformClient};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const FACTORY: &str = "https://otto-factory.example/mcp";
const FLAGS: &str = "https://otto-flags.example/mcp";
const EVALS: &str = "otto-flags/evaluations";
const JOBS: &str = "otto-factory/jobs";

/// One cent, in millionths of a cent.
const CENT: i64 = 1_000_000;

struct World {
    db: Db,
    flags: String,
    factory: String,
    flags_secret: String,
    factory_secret: String,
    org: OrgId,
    admin: UserId,
}

/// Two services with one meter each, an org whose admin is
/// `admin@acme.example`. `otto-flags/evaluations` costs a cent this month;
/// `otto-factory/jobs` has no price.
async fn world(pool: PgPool) -> World {
    let db = Db::from_pool(pool);
    let mut secrets = Vec::new();
    for (uri, service, key) in [
        (FACTORY, "otto-factory", JOBS),
        (FLAGS, "otto-flags", EVALS),
    ] {
        resources::register(
            &db,
            ResourceServerSpec {
                resource_uri: uri,
                name: service,
                scopes: &["read"],
                default_scopes: &["read"],
            },
        )
        .await
        .unwrap();
        resources::set_service(&db, uri, service).await.unwrap();
        let secret = resources::rotate_introspection_secret(&db, uri)
            .await
            .unwrap();
        let (status, body) = send(
            &db,
            Request::put("/internal/meters")
                .header("authorization", basic(uri, &secret))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "meters": [{ "key": key, "display_name": "Units", "unit": "unit" }] })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        secrets.push(secret);
    }
    price(&db, EVALS, 0, &[(None, CENT)]).await;

    let org = db.create_org("acme", "Acme").await.unwrap();
    let admin = db
        .upsert_user("admin@acme.example", Some("Admin"))
        .await
        .unwrap();
    db.add_member(org.id, admin.id, Role::Admin).await.unwrap();
    let flags_secret = secrets.pop().unwrap();
    let factory_secret = secrets.pop().unwrap();
    World {
        flags: basic(FLAGS, &flags_secret),
        factory: basic(FACTORY, &factory_secret),
        flags_secret,
        factory_secret,
        db,
        org: org.id,
        admin: admin.id,
    }
}

/// A price for `meter` from `months_from_now` (0 is this month), written
/// directly as the price-book tests do: `pricebook set` refuses any month
/// that is not in the future.
async fn price(db: &Db, meter: &str, months_from_now: i32, tiers: &[(Option<i64>, i64)]) {
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ($1, (date_trunc('month', now() AT TIME ZONE 'UTC') \
                      + make_interval(months => $2))::date) RETURNING id",
    )
    .bind(meter)
    .bind(months_from_now)
    .fetch_one(db.pool())
    .await
    .unwrap();
    for (position, (up_to, amount)) in tiers.iter().enumerate() {
        sqlx::query(
            "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(version)
        .bind(i16::try_from(position).unwrap())
        .bind(up_to)
        .bind(amount)
        .execute(db.pool())
        .await
        .unwrap();
    }
}

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

fn event(org: OrgId, meter: Option<&str>, quantity: Option<u64>) -> Value {
    let mut ev = json!({
        "event_id": Uuid::new_v4(),
        "org_id": org,
        "user_id": null,
        "tool": "tool.call",
        "billable": true,
        "occurred_at": Utc::now(),
    });
    if let Some(m) = meter {
        ev["meter"] = json!(m);
        ev["quantity"] = json!(quantity);
    }
    ev
}

impl World {
    async fn ship(&self, auth: &str, events: Vec<Value>) -> Value {
        let n = events.len();
        let (status, receipt) = send(
            &self.db,
            Request::post("/internal/usage")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "events": events }).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(
            receipt["accepted"].as_u64().unwrap() + receipt["duplicates"].as_u64().unwrap(),
            n as u64,
            "every event is counted, never rejected: {receipt}"
        );
        receipt
    }

    async fn evals(&self, quantity: u64) {
        self.ship(
            &self.flags,
            vec![event(self.org, Some(EVALS), Some(quantity))],
        )
        .await;
    }

    async fn status(&self, auth: &str) -> Value {
        let (status, body) = send(
            &self.db,
            Request::get(format!("/internal/orgs/{}/usage-status", self.org))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn set_budget(&self, service: &str, cents: i64, hard_stop: bool) {
        let mut tx = self.db.begin(self.org).await.unwrap();
        otto_billing::budgets::set_budget(&mut tx, service, cents, hard_stop, self.admin)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn add(&self, email: &str, role: Role) -> UserId {
        let user = self.db.upsert_user(email, None).await.unwrap();
        self.db.add_member(self.org, user.id, role).await.unwrap();
        user.id
    }

    async fn alerts(&self) -> Vec<(String, i16)> {
        sqlx::query_as("SELECT service, threshold FROM budget_alerts ORDER BY service, threshold")
            .fetch_all(self.db.pool())
            .await
            .unwrap()
    }

    /// `(recipient, subject)` of every queued email, oldest first.
    async fn emails(&self) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT recipient, subject FROM notification_outbox ORDER BY created_at, recipient",
        )
        .fetch_all(self.db.pool())
        .await
        .unwrap()
    }
}

fn subjects(emails: &[(String, String)]) -> Vec<(&str, &str)> {
    emails
        .iter()
        .map(|(r, s)| (r.as_str(), s.as_str()))
        .collect()
}

#[test]
fn the_wire_and_the_platform_agree_on_the_reason() {
    assert_eq!(
        otto_resource::BUDGET_EXCEEDED,
        otto_billing::budgets::BUDGET_EXCEEDED
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn each_threshold_fires_once_and_emails_only_owners_and_admins(pool: PgPool) {
    let w = world(pool).await;
    w.add("owner@acme.example", Role::Owner).await;
    w.add("member@acme.example", Role::Member).await;
    let gone = w.add("gone@acme.example", Role::Admin).await;
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(gone)
        .execute(w.db.pool())
        .await
        .unwrap();
    // An admin of another org hears nothing about this one.
    let globex = w.db.create_org("globex", "Globex").await.unwrap();
    let stranger = w.db.upsert_user("x@globex.example", None).await.unwrap();
    w.db.add_member(globex.id, stranger.id, Role::Admin)
        .await
        .unwrap();
    // A $10.00 budget; evaluations are a cent each.
    w.set_budget("otto-flags", 1_000, false).await;

    w.evals(499).await;
    assert!(w.alerts().await.is_empty());
    assert!(w.emails().await.is_empty());

    w.evals(1).await;
    assert_eq!(w.alerts().await, [("otto-flags".into(), 50)]);
    let to = ["admin@acme.example", "owner@acme.example"];
    let fifty = "otto-flags has reached 50% of its monthly budget in acme";
    assert_eq!(
        subjects(&w.emails().await),
        [(to[0], fifty), (to[1], fifty)]
    );

    // More usage under the next threshold, and a replayed event, fire nothing.
    w.evals(1).await;
    let replay = event(w.org, Some(EVALS), Some(400));
    w.ship(&w.flags, vec![replay.clone()]).await;
    let receipt = w.ship(&w.flags, vec![replay]).await;
    assert_eq!(receipt["duplicates"], 1);
    assert_eq!(w.alerts().await.len(), 2, "{:?}", w.alerts().await);
    assert_eq!(w.emails().await.len(), 4);

    // 901 cents: 80% fired with the replayed event, once.
    let eighty = "otto-flags has reached 80% of its monthly budget in acme";
    let emails = w.emails().await;
    assert_eq!(subjects(&emails[2..]), [(to[0], eighty), (to[1], eighty)]);

    // A batch that crosses 100% partway fires it once.
    w.ship(
        &w.flags,
        (0..5)
            .map(|_| event(w.org, Some(EVALS), Some(50)))
            .collect(),
    )
    .await;
    w.evals(10_000).await;
    assert_eq!(
        w.alerts().await,
        [
            ("otto-flags".into(), 50),
            ("otto-flags".into(), 80),
            ("otto-flags".into(), 100)
        ]
    );
    let emails = w.emails().await;
    assert_eq!(emails.len(), 6, "{emails:?}");
    let hundred = "otto-flags has reached 100% of its monthly budget in acme";
    assert_eq!(subjects(&emails[4..]), [(to[0], hundred), (to[1], hundred)]);
    let body: String =
        sqlx::query_scalar("SELECT body_text FROM notification_outbox WHERE subject = $1 LIMIT 1")
            .bind(hundred)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert!(body.contains("Hard stop is off"), "{body}");
    assert!(body.contains("Monthly budget: $10.00"), "{body}");

    // Without a hard stop, nothing is blocked however far over.
    let status = w.status(&w.flags).await;
    assert_eq!(
        status["budget"],
        json!({
            "monthly_budget_cents": 1_000,
            "spend_cents": 11_151,
            "percent_used": 1_115,
            "thresholds_reached": [50, 80, 100],
            "hard_stop": false,
            "blocked": false,
            "reason": null,
        })
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_lowered_budget_fires_each_newly_reached_threshold_once(pool: PgPool) {
    let w = world(pool).await;
    w.set_budget("otto-flags", 10_000, false).await;
    w.evals(900).await;
    assert!(w.alerts().await.is_empty());

    // Lowered to $10.00, 900 cents is past 50 and 80 at once.
    w.set_budget("otto-flags", 1_000, false).await;
    assert!(w.alerts().await.is_empty(), "alerts fire at ingest only");
    w.evals(1).await;
    assert_eq!(
        w.alerts().await,
        [("otto-flags".into(), 50), ("otto-flags".into(), 80)]
    );
    // One email per recipient, naming the highest.
    assert_eq!(
        subjects(&w.emails().await),
        [(
            "admin@acme.example",
            "otto-flags has reached 80% of its monthly budget in acme"
        )]
    );

    // Clearing and setting it again does not refire them this month.
    let mut tx = w.db.begin(w.org).await.unwrap();
    otto_billing::budgets::clear_budget(&mut tx, "otto-flags")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    w.set_budget("otto-flags", 1_000, false).await;
    w.evals(1).await;
    assert_eq!(w.alerts().await.len(), 2);
    assert_eq!(w.emails().await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_hard_stop_on_one_service_leaves_another_unblocked(pool: PgPool) {
    let w = world(pool).await;
    price(&w.db, JOBS, 0, &[(None, CENT)]).await;
    w.set_budget("otto-flags", 100, true).await;
    w.set_budget("otto-factory", 100, true).await;

    w.evals(99).await;
    assert_eq!(w.status(&w.flags).await["budget"]["blocked"], false);
    w.evals(1).await;
    let flags = w.status(&w.flags).await;
    assert_eq!(flags["budget"]["blocked"], true);
    assert_eq!(flags["budget"]["reason"], "budget_exceeded");
    assert_eq!(flags["budget"]["percent_used"], 100);

    // The factory's budget is its own: untouched by the flags spend.
    let factory = w.status(&w.factory).await;
    assert_eq!(factory["service"], "otto-factory");
    assert_eq!(
        factory["budget"],
        json!({
            "monthly_budget_cents": 100,
            "spend_cents": 0,
            "percent_used": 0,
            "thresholds_reached": [],
            "hard_stop": true,
            "blocked": false,
            "reason": null,
        })
    );

    // Through the client, as a resource server reads it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = otto_platform_server::router(w.db.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let org = w.org.as_uuid();
    let flags_client =
        PlatformClient::new(ClientConfig::new(&base, FLAGS, &w.flags_secret)).unwrap();
    let factory_client =
        PlatformClient::new(ClientConfig::new(&base, FACTORY, &w.factory_secret)).unwrap();
    let flags = flags_client.usage_status(org).await.unwrap();
    assert!(flags.budget_exceeded());
    assert_eq!(
        flags.budget.unwrap().reason.as_deref(),
        Some(otto_resource::BUDGET_EXCEEDED)
    );
    assert!(!factory_client
        .usage_status(org)
        .await
        .unwrap()
        .budget_exceeded());

    // Usage is still counted while blocked: the platform never refuses it.
    w.evals(5).await;
    assert_eq!(w.status(&w.flags).await["budget"]["spend_cents"], 105);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn with_no_budget_nothing_is_ever_blocked(pool: PgPool) {
    let w = world(pool).await;
    w.evals(1_000_000_000).await;
    w.evals(1_000_000_000).await;

    for auth in [&w.flags, &w.factory] {
        let status = w.status(auth).await;
        assert!(status.get("budget").is_none(), "{status}");
        let parsed: otto_resource::UsageStatus = serde_json::from_value(status).unwrap();
        assert!(!parsed.budget_exceeded());
    }
    assert!(w.alerts().await.is_empty());
    assert!(w.emails().await.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn unmetered_events_never_move_spend(pool: PgPool) {
    let w = world(pool).await;
    w.set_budget("otto-flags", 1, true).await;
    w.ship(
        &w.flags,
        (0..300).map(|_| event(w.org, None, None)).collect(),
    )
    .await;

    let status = w.status(&w.flags).await;
    assert_eq!(status["budget"]["spend_cents"], 0);
    assert_eq!(status["budget"]["blocked"], false);
    assert_eq!(status["billable_count"], 300);
    assert!(w.alerts().await.is_empty());

    // Nor does an unpriced meter.
    w.set_budget("otto-factory", 1, true).await;
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(1_000))])
        .await;
    let status = w.status(&w.factory).await;
    assert_eq!(status["meters"][0]["quantity"], 1_000);
    assert_eq!(status["budget"]["spend_cents"], 0);
    assert_eq!(status["budget"]["blocked"], false);
    assert!(w.alerts().await.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_late_event_is_rated_and_alerted_in_its_own_month(pool: PgPool) {
    let w = world(pool).await;
    // Last month evaluations cost ten cents each.
    price(&w.db, EVALS, -1, &[(None, 10 * CENT)]).await;
    w.set_budget("otto-flags", 1_000, false).await;

    let last_month = otto_billing::usage::earliest_occurred_at(Utc::now());
    let mut late = event(w.org, Some(EVALS), Some(85));
    late["occurred_at"] = json!(last_month + chrono::Duration::hours(1));
    w.ship(&w.flags, vec![late]).await;

    let fired: Vec<(chrono::NaiveDate, i16)> =
        sqlx::query_as("SELECT period_start, threshold FROM budget_alerts ORDER BY threshold")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        fired,
        [(last_month.date_naive(), 50), (last_month.date_naive(), 80)],
        "850 cents at last month's price"
    );
    // This month is untouched.
    let status = w.status(&w.flags).await;
    assert_eq!(status["budget"]["spend_cents"], 0);
    assert_eq!(status["budget"]["thresholds_reached"], json!([]));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_failing_budget_step_never_fails_the_event(pool: PgPool) {
    let w = world(pool).await;
    // An address the outbox refuses is skipped; the others still get mail.
    let bad = w.add("bad@acme.example", Role::Owner).await;
    sqlx::query("UPDATE users SET email = 'not an address' WHERE id = $1")
        .bind(bad)
        .execute(w.db.pool())
        .await
        .unwrap();
    w.set_budget("otto-flags", 100, false).await;
    w.evals(50).await;
    assert_eq!(w.alerts().await.len(), 1);
    assert_eq!(
        w.emails()
            .await
            .into_iter()
            .map(|(to, _)| to)
            .collect::<Vec<_>>(),
        ["admin@acme.example"]
    );

    // A price version edited by hand into a shape the rater refuses (a
    // bounded last tier) makes the spend uncomputable. The events still count.
    price(&w.db, JOBS, 0, &[(Some(10), CENT)]).await;
    w.set_budget("otto-factory", 1, true).await;
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(500))])
        .await;
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(500))])
        .await;
    let status = w.status(&w.factory).await;
    assert_eq!(status["meters"][0]["quantity"], 1_000);
    // The budget it cannot compute is left out: enforcement fails open.
    assert!(status.get("budget").is_none(), "{status}");
    assert_eq!(w.alerts().await.len(), 1);
}
