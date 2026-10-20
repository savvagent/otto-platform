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
    send_with(db, otto_platform_server::Billing::Enabled, req).await
}

async fn send_with(
    db: &Db,
    billing: otto_platform_server::Billing,
    req: Request<Body>,
) -> (StatusCode, Value) {
    let res = otto_platform_server::router(db.clone(), billing)
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
        self.status_with(auth, otto_platform_server::Billing::Enabled)
            .await
    }

    async fn status_with(&self, auth: &str, billing: otto_platform_server::Billing) -> Value {
        let (status, body) = send_with(
            &self.db,
            billing,
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

    /// Give the org a live Stripe subscription, as setup and the webhooks
    /// leave it.
    async fn subscribe(&self) {
        sqlx::query(
            "INSERT INTO subscriptions (org_id, stripe_customer_id, stripe_subscription_id, status) \
             VALUES ($1, 'cus_acme', 'sub_acme', 'active') \
             ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = 'cus_acme', \
               stripe_subscription_id = 'sub_acme', status = 'active'",
        )
        .bind(self.org)
        .execute(self.db.pool())
        .await
        .unwrap();
    }

    /// Set the subscription's status and the card's, each with how long ago
    /// it became so (`None`: unknown), as the webhooks record them.
    async fn billing_state(
        &self,
        status: &str,
        past_due_for: Option<chrono::Duration>,
        card: &str,
        card_for: Option<chrono::Duration>,
    ) {
        let ago = |d: Option<chrono::Duration>| d.map(|d| Utc::now() - d);
        sqlx::query(
            "UPDATE subscriptions SET status = $2, past_due_since = $3, \
               payment_method_status = $4, payment_method_event_at = $5 \
             WHERE org_id = $1",
        )
        .bind(self.org)
        .bind(status)
        .bind(ago(past_due_for))
        .bind(card)
        .bind(ago(card_for))
        .execute(self.db.pool())
        .await
        .unwrap();
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
    assert_eq!(
        otto_resource::PAYMENT_REQUIRED,
        otto_billing::budgets::PAYMENT_REQUIRED
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
    let app = otto_platform_server::router(w.db.clone(), otto_platform_server::Billing::Enabled);
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
async fn with_no_budget_and_a_subscription_nothing_is_ever_blocked(pool: PgPool) {
    let w = world(pool).await;
    w.subscribe().await;
    w.evals(1_000_000_000).await;
    w.evals(1_000_000_000).await;

    for auth in [&w.flags, &w.factory] {
        let status = w.status(auth).await;
        assert!(status.get("budget").is_none(), "{status}");
        assert!(status.get("blocked_reason").is_none(), "{status}");
        let parsed: otto_resource::UsageStatus = serde_json::from_value(status).unwrap();
        assert!(!parsed.budget_exceeded());
        assert!(!parsed.billable_blocked());
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
async fn a_late_event_is_rated_and_alerted_in_the_period_it_is_billed_in(pool: PgPool) {
    use otto_billing::period::{self, Month};

    let w = world(pool).await;
    // Last month evaluations cost ten cents each.
    price(&w.db, EVALS, -1, &[(None, 10 * CENT)]).await;
    w.set_budget("otto-flags", 1_000, false).await;

    let now = Utc::now();
    let last_month = otto_billing::usage::earliest_occurred_at(now);
    let mut late = event(w.org, Some(EVALS), Some(85));
    late["occurred_at"] = json!(last_month + chrono::Duration::hours(1));
    w.ship(&w.flags, vec![late]).await;

    let fired: Vec<(chrono::NaiveDate, i16)> =
        sqlx::query_as("SELECT period_start, threshold FROM budget_alerts ORDER BY threshold")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    let status = w.status(&w.flags).await;
    if period::period_closed(Month::of(last_month), Utc::now()) {
        // Last month has closed: the event is billed now, at this month's
        // price (a cent), so 85 cents of a $10 budget fires nothing.
        assert!(fired.is_empty(), "{fired:?}");
        assert_eq!(status["budget"]["spend_cents"], 85);
    } else {
        // Inside the grace: still last month's, at last month's price.
        assert_eq!(
            fired,
            [(last_month.date_naive(), 50), (last_month.date_naive(), 80)],
            "850 cents at last month's price"
        );
        assert_eq!(status["budget"]["spend_cents"], 0);
        assert_eq!(status["budget"]["thresholds_reached"], json!([]));
    }
}

/// An event inside its month's grace is billed in its own month; one after
/// it, in the month it arrived in. With the clock fixed, both cases run.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_period_close_decides_the_month_an_event_counts_in(pool: PgPool) {
    use chrono::TimeZone;
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{IngestOutcome, Metered, ShippedUsage, UsageExt};

    let w = world(pool).await;
    let at = |d, h, m| {
        Utc.with_ymd_and_hms(2026, if d > 1 { 10 } else { 11 }, d, h, m, 0)
            .unwrap()
    };
    let ingest = |occurred_at, now| {
        let db = w.db.clone();
        let org = w.org;
        async move {
            let mut tx = db.begin(org).await.unwrap();
            otto_billing::usage::lock_org_ingest(&mut tx).await.unwrap();
            let mut budgets = PendingBudgets::default();
            let out = tx
                .ingest_usage_deferred_at(
                    FLAGS,
                    &ShippedUsage {
                        event_id: Uuid::new_v4(),
                        user: None,
                        tool: "t",
                        billable: true,
                        occurred_at,
                        service: Some("otto-flags"),
                        metered: Some(Metered {
                            meter: EVALS,
                            quantity: 1,
                        }),
                    },
                    &mut budgets,
                    now,
                )
                .await
                .unwrap();
            budgets.run(&mut tx).await.unwrap();
            tx.commit().await.unwrap();
            out
        }
    };
    // 23:30 on 31 October, arriving at 01:59 and at 02:00 on 1 November.
    let late = at(31, 23, 30);
    assert_eq!(ingest(late, at(1, 1, 59)).await, IngestOutcome::Counted);
    assert_eq!(ingest(late, at(1, 2, 0)).await, IngestOutcome::Counted);
    let periods: Vec<(chrono::NaiveDate, i64)> = sqlx::query_as(
        "SELECT period_start, quantity FROM org_meter_period_usage          WHERE org_id = $1 ORDER BY period_start",
    )
    .bind(w.org)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    let day = |m, d| chrono::NaiveDate::from_ymd_opt(2026, m, d).unwrap();
    assert_eq!(periods, [(day(10, 1), 1), (day(11, 1), 1)]);
    let billed: Vec<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT created_at FROM usage_events ORDER BY created_at")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        billed,
        [late, at(1, 2, 0)],
        "the ledger keeps the billed instant"
    );
}

/// Two batches for one org, each straddling a month boundary, in opposite
/// orders, at once: without the org's ingest lock their counter rows would
/// be locked in opposite orders and deadlock. Both commit.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn concurrent_batches_straddling_a_month_boundary_both_commit(pool: PgPool) {
    use chrono::TimeZone;
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{IngestOutcome, Metered, ShippedUsage, UsageExt};

    let w = world(pool).await;
    let now = Utc.with_ymd_and_hms(2026, 11, 1, 1, 0, 0).unwrap();
    let october = Utc.with_ymd_and_hms(2026, 10, 31, 23, 30, 0).unwrap();
    let november = Utc.with_ymd_and_hms(2026, 11, 1, 0, 30, 0).unwrap();
    let batch = |order: [chrono::DateTime<Utc>; 2], hold: std::time::Duration| {
        let db = w.db.clone();
        let org = w.org;
        async move {
            let mut tx = db.begin(org).await.unwrap();
            otto_billing::usage::lock_org_ingest(&mut tx).await.unwrap();
            let mut budgets = PendingBudgets::default();
            for (i, occurred_at) in order.into_iter().enumerate() {
                let out = tx
                    .ingest_usage_deferred_at(
                        FLAGS,
                        &ShippedUsage {
                            event_id: Uuid::new_v4(),
                            user: None,
                            tool: "t",
                            billable: true,
                            occurred_at,
                            service: Some("otto-flags"),
                            metered: Some(Metered {
                                meter: EVALS,
                                quantity: 1,
                            }),
                        },
                        &mut budgets,
                        now,
                    )
                    .await
                    .unwrap();
                assert_eq!(out, IngestOutcome::Counted);
                if i == 0 {
                    // Give the other batch time to take its first row.
                    tokio::time::sleep(hold).await;
                }
            }
            budgets.run(&mut tx).await.unwrap();
            tx.commit().await.unwrap();
        }
    };
    let hold = std::time::Duration::from_millis(300);
    let a = tokio::spawn(batch([october, november], hold));
    let b = tokio::spawn(batch([november, october], hold));
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        (a.await, b.await)
    })
    .await
    .expect("neither batch hangs");
    a.expect("the first batch commits");
    b.expect("the second batch commits");

    let periods: Vec<(chrono::NaiveDate, i64)> = sqlx::query_as(
        "SELECT period_start, quantity FROM org_meter_period_usage          WHERE org_id = $1 ORDER BY period_start",
    )
    .bind(w.org)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    let day = |m, d| chrono::NaiveDate::from_ymd_opt(2026, m, d).unwrap();
    assert_eq!(periods, [(day(10, 1), 2), (day(11, 1), 2)]);
}

/// The same, through `POST /internal/usage`: two concurrent batches for one
/// org whose events come in opposite orders both succeed.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn concurrent_http_batches_for_one_org_both_succeed(pool: PgPool) {
    let w = world(pool).await;
    let now = Utc::now();
    let events: Vec<Value> = (0..50)
        .map(|i| {
            let mut ev = event(w.org, Some(EVALS), Some(1));
            ev["occurred_at"] = json!(now - chrono::Duration::seconds(i));
            ev
        })
        .collect();
    let mut reversed = events
        .iter()
        .map(|ev| {
            let mut ev = ev.clone();
            ev["event_id"] = json!(Uuid::new_v4());
            ev
        })
        .collect::<Vec<_>>();
    reversed.reverse();
    let (a, b) = tokio::join!(w.ship(&w.flags, events), w.ship(&w.flags, reversed));
    assert_eq!(
        (a["accepted"].clone(), b["accepted"].clone()),
        (json!(50), json!(50))
    );
    assert_eq!(w.status(&w.flags).await["meters"][0]["quantity"], 100);
}

/// An org with no live subscription must add a card before billable use of a
/// service past its free tiers; only that service is blocked, a budget's hard
/// stop wins, and a live subscription lifts it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn billable_use_past_free_tiers_needs_a_payment_method(pool: PgPool) {
    let w = world(pool).await;
    // Ten jobs a month free, then a cent each.
    price(&w.db, JOBS, 0, &[(Some(10), 0), (None, CENT)]).await;
    let reason = |status: &Value| status.get("blocked_reason").cloned();

    // Nothing used: nothing blocked.
    for auth in [&w.flags, &w.factory] {
        assert_eq!(reason(&w.status(auth).await), None);
    }
    // Within the free tier: spend 0, not blocked.
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(10))])
        .await;
    let factory = w.status(&w.factory).await;
    assert_eq!(reason(&factory), None, "{factory}");
    assert!(factory.get("budget").is_none());
    // Past it: payment required, for the factory only.
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(1))])
        .await;
    let factory = w.status(&w.factory).await;
    assert_eq!(reason(&factory), Some(json!("payment_required")));
    assert!(factory.get("budget").is_none(), "no budget is set");
    let parsed: otto_resource::UsageStatus = serde_json::from_value(factory).unwrap();
    assert!(parsed.billable_blocked() && !parsed.budget_exceeded());
    assert_eq!(
        reason(&w.status(&w.flags).await),
        None,
        "another service is unaffected"
    );

    // A hard stop and no card: the budget wins.
    w.set_budget("otto-flags", 3, true).await;
    w.evals(5).await;
    let flags = w.status(&w.flags).await;
    assert_eq!(reason(&flags), Some(json!("budget_exceeded")));
    assert_eq!(flags["budget"]["blocked"], true);

    // A live subscription lifts payment_required, not the hard stop.
    w.subscribe().await;
    assert_eq!(reason(&w.status(&w.factory).await), None);
    assert_eq!(
        reason(&w.status(&w.flags).await),
        Some(json!("budget_exceeded"))
    );
    // A canceled one does not.
    w.billing_state("canceled", None, "active", None).await;
    assert_eq!(
        reason(&w.status(&w.factory).await),
        Some(json!("payment_required"))
    );
}

/// A failed payment keeps billable use going for the grace only: past due
/// (or a failed or detached card) for less than `PAYMENT_GRACE` is allowed,
/// past it, or `unpaid` at all, needs a working card. The budget's hard stop
/// still wins, and with billing disabled nothing is required.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_failed_payment_is_allowed_only_within_the_grace(pool: PgPool) {
    use otto_billing::billing::gate::PAYMENT_GRACE;
    use otto_platform_server::Billing;
    let w = world(pool).await;
    price(&w.db, JOBS, 0, &[(Some(10), 0), (None, CENT)]).await;
    let reason = |status: &Value| status.get("blocked_reason").cloned();
    let required = Some(json!("payment_required"));
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(50))])
        .await;
    let inside = Some(PAYMENT_GRACE - chrono::Duration::hours(1));
    let beyond = Some(PAYMENT_GRACE + chrono::Duration::minutes(1));

    w.subscribe().await;
    w.billing_state("active", None, "active", None).await;
    assert_eq!(reason(&w.status(&w.factory).await), None, "active");
    w.billing_state("trialing", None, "active", None).await;
    assert_eq!(reason(&w.status(&w.factory).await), None, "trialing");

    w.billing_state("past_due", inside, "failed", inside).await;
    assert_eq!(
        reason(&w.status(&w.factory).await),
        None,
        "past due in grace"
    );
    w.billing_state("past_due", beyond, "failed", inside).await;
    assert_eq!(reason(&w.status(&w.factory).await), required, "past due");
    w.billing_state("unpaid", inside, "failed", inside).await;
    assert_eq!(reason(&w.status(&w.factory).await), required, "unpaid");

    // A failed or detached card past the grace, even on an active
    // subscription.
    for card in ["failed", "detached"] {
        w.billing_state("active", None, card, inside).await;
        assert_eq!(reason(&w.status(&w.factory).await), None, "{card} in grace");
        w.billing_state("active", None, card, beyond).await;
        assert_eq!(reason(&w.status(&w.factory).await), required, "{card}");
    }

    // Still queued for Stripe while past due or unpaid: the usage is
    // invoiced if the card recovers.
    let queued_before: i64 =
        sqlx::query_scalar("SELECT COALESCE(sum(value), 0)::bigint FROM stripe_meter_outbox")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    w.billing_state("unpaid", None, "failed", beyond).await;
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(4))])
        .await;
    let queued_after: i64 =
        sqlx::query_scalar("SELECT COALESCE(sum(value), 0)::bigint FROM stripe_meter_outbox")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(queued_after - queued_before, 4);

    // The budget's hard stop wins; with billing disabled only it blocks.
    w.set_budget("otto-factory", 1, true).await;
    assert_eq!(
        reason(&w.status(&w.factory).await),
        Some(json!("budget_exceeded"))
    );
    w.set_budget("otto-factory", 1_000_000, false).await;
    assert_eq!(reason(&w.status(&w.factory).await), required);
    assert_eq!(
        reason(&w.status_with(&w.factory, Billing::Disabled).await),
        None
    );
}

/// With billing disabled (no Stripe secrets) no card can be put on file, so
/// payment is never required, however far past its free tiers a service is;
/// a budget's hard stop still blocks.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn payment_is_never_required_with_billing_disabled(pool: PgPool) {
    use otto_platform_server::Billing;
    let w = world(pool).await;
    price(&w.db, JOBS, 0, &[(Some(10), 0), (None, CENT)]).await;
    let reason = |status: &Value| status.get("blocked_reason").cloned();
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(50))])
        .await;
    // The same org and usage: required with billing on, not with it off.
    assert_eq!(
        reason(&w.status_with(&w.factory, Billing::Enabled).await),
        Some(json!("payment_required"))
    );
    let off = w.status_with(&w.factory, Billing::Disabled).await;
    assert_eq!(reason(&off), None, "{off}");
    assert!(off.get("budget").is_none(), "{off}");
    let parsed: otto_resource::UsageStatus = serde_json::from_value(off).unwrap();
    assert!(!parsed.billable_blocked());

    // A hard stop still blocks with billing off, and reports its budget.
    w.set_budget("otto-factory", 10, true).await;
    let off = w.status_with(&w.factory, Billing::Disabled).await;
    assert_eq!(reason(&off), Some(json!("budget_exceeded")), "{off}");
    assert_eq!(off["budget"]["blocked"], true);
}

/// With a live subscription and no budget, usage-status does not rate spend
/// at all, so a price the rater refuses cannot fail or degrade it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn spend_is_not_rated_when_no_answer_needs_it(pool: PgPool) {
    let w = world(pool).await;
    w.subscribe().await;
    // A bounded last tier: the rater refuses it.
    price(&w.db, JOBS, 0, &[(Some(10), CENT)]).await;
    w.ship(&w.factory, vec![event(w.org, Some(JOBS), Some(500))])
        .await;
    let status = w.status(&w.factory).await;
    assert!(status.get("budget").is_none(), "{status}");
    assert!(status.get("blocked_reason").is_none(), "{status}");
    assert_eq!(status["meters"][0]["quantity"], 500);
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
    // The budget is still reported, visibly unknown, and never blocks.
    assert_eq!(
        status["budget"],
        json!({
            "monthly_budget_cents": 1,
            "spend_cents": null,
            "percent_used": null,
            "thresholds_reached": [],
            "hard_stop": true,
            "blocked": false,
            "reason": "spend_unavailable",
        })
    );
    let parsed: otto_resource::UsageStatus = serde_json::from_value(status).unwrap();
    assert!(!parsed.budget_exceeded());
    assert_eq!(w.alerts().await.len(), 1);
    // The other service is unaffected.
    assert_eq!(w.status(&w.flags).await["budget"]["spend_cents"], 50);
}

/// Make every insert into `table` fail, as a broken table or a full disk
/// would. Returns the SQL that undoes it.
async fn break_inserts(db: &Db, table: &str) -> String {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION test_refuse_insert() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused by test'; END $$",
    )
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER test_refuse BEFORE INSERT ON {table} \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_insert()"
    ))
    .execute(db.pool())
    .await
    .unwrap();
    format!("DROP TRIGGER test_refuse ON {table}")
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_database_error_in_the_alert_step_never_fails_the_batch(pool: PgPool) {
    let w = world(pool).await;
    w.set_budget("otto-flags", 100, false).await;
    let undo = break_inserts(&w.db, "budget_alerts").await;

    // The whole batch counts and commits, the events after the crossing ones
    // and the unmetered one included.
    let receipt = w
        .ship(
            &w.flags,
            vec![
                event(w.org, Some(EVALS), Some(60)),
                event(w.org, Some(EVALS), Some(60)),
                event(w.org, None, None),
            ],
        )
        .await;
    assert_eq!(receipt["accepted"], 3, "{receipt}");
    assert_eq!(w.status(&w.flags).await["budget"]["spend_cents"], 120);
    assert!(w.alerts().await.is_empty());
    assert!(w.emails().await.is_empty());

    // Once the table accepts rows again, the next event fires what was missed.
    sqlx::query(&undo).execute(w.db.pool()).await.unwrap();
    w.evals(1).await;
    assert_eq!(
        w.alerts().await,
        [
            ("otto-flags".into(), 50),
            ("otto-flags".into(), 80),
            ("otto-flags".into(), 100)
        ]
    );
    assert_eq!(w.emails().await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_alert_whose_emails_cannot_be_queued_is_retried(pool: PgPool) {
    let w = world(pool).await;
    w.add("owner@acme.example", Role::Owner).await;
    w.set_budget("otto-flags", 100, false).await;
    let undo = break_inserts(&w.db, "notification_outbox").await;

    let receipt = w
        .ship(&w.flags, vec![event(w.org, Some(EVALS), Some(60))])
        .await;
    assert_eq!(receipt["accepted"], 1);
    assert_eq!(w.status(&w.flags).await["meters"][0]["quantity"], 60);
    // The alert rolled back with its emails rather than firing silently.
    assert!(w.alerts().await.is_empty());
    assert!(w.emails().await.is_empty());

    sqlx::query(&undo).execute(w.db.pool()).await.unwrap();
    w.evals(1).await;
    assert_eq!(w.alerts().await, [("otto-flags".into(), 50)]);
    let fifty = "otto-flags has reached 50% of its monthly budget in acme";
    assert_eq!(
        subjects(&w.emails().await),
        [("admin@acme.example", fifty), ("owner@acme.example", fifty)]
    );
}

/// Ingest `events` of `meter` in one transaction, the way the batch endpoint
/// does, and return how many budget steps ran.
async fn ingest_batch(w: &World, uri: &str, service: &str, meter: &str, events: usize) -> usize {
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{IngestOutcome, Metered, ShippedUsage, UsageExt};

    let mut tx = w.db.begin(w.org).await.unwrap();
    let mut pending = PendingBudgets::default();
    for _ in 0..events {
        let outcome = tx
            .ingest_usage_deferred(
                uri,
                &ShippedUsage {
                    event_id: Uuid::new_v4(),
                    user: None,
                    tool: "t",
                    billable: true,
                    occurred_at: Utc::now(),
                    service: Some(service),
                    metered: Some(Metered {
                        meter,
                        quantity: 10,
                    }),
                },
                &mut pending,
            )
            .await
            .unwrap();
        assert_eq!(outcome, IngestOutcome::Counted);
    }
    let steps = pending.run(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    steps
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_budget_step_runs_once_per_service_and_period_per_batch(pool: PgPool) {
    let w = world(pool).await;
    // No budget: no step at all.
    assert_eq!(ingest_batch(&w, FLAGS, "otto-flags", EVALS, 20).await, 0);

    w.set_budget("otto-flags", 300, false).await;
    // 20 more events, 400 cents in all: one step, which fires all three
    // thresholds.
    assert_eq!(ingest_batch(&w, FLAGS, "otto-flags", EVALS, 20).await, 1);
    assert_eq!(w.alerts().await.len(), 3);
    assert_eq!(w.emails().await.len(), 1);
    // Once 100% has fired nothing more can, and the step is skipped.
    assert_eq!(ingest_batch(&w, FLAGS, "otto-flags", EVALS, 20).await, 0);

    // Another budgeted service in its own batch: one step for it.
    w.set_budget("otto-factory", 1_000, false).await;
    assert_eq!(ingest_batch(&w, FACTORY, "otto-factory", JOBS, 5).await, 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn two_concurrent_ingests_crossing_a_threshold_fire_it_once(pool: PgPool) {
    use otto_billing::budgets::PendingBudgets;
    use otto_billing::usage::{Metered, ShippedUsage, UsageExt};

    let w = world(pool).await;
    w.set_budget("otto-flags", 100, false).await;
    w.evals(49).await;

    let ingest = |db: Db, org: OrgId| async move {
        let mut tx = db.begin(org).await.unwrap();
        let mut budgets = PendingBudgets::default();
        tx.ingest_usage_deferred(
            FLAGS,
            &ShippedUsage {
                event_id: Uuid::new_v4(),
                user: None,
                tool: "t",
                billable: true,
                occurred_at: Utc::now(),
                service: Some("otto-flags"),
                metered: Some(Metered {
                    meter: EVALS,
                    quantity: 1,
                }),
            },
            &mut budgets,
        )
        .await
        .unwrap();
        budgets.run(&mut tx).await.unwrap();
        tx
    };
    // The first holds its transaction open across the threshold; the second
    // waits on the first's counter row, then sees the alert already fired.
    let first = ingest(w.db.clone(), w.org).await;
    let second = tokio::spawn(ingest(w.db.clone(), w.org));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !second.is_finished(),
        "the second ingest waits for the first"
    );
    first.commit().await.unwrap();
    second.await.unwrap().commit().await.unwrap();

    assert_eq!(w.alerts().await, [("otto-flags".into(), 50)]);
    assert_eq!(w.emails().await.len(), 1);
    assert_eq!(w.status(&w.flags).await["budget"]["spend_cents"], 51);
}
