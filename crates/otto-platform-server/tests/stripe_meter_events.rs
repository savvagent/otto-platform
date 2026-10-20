//! Metered usage to Stripe meter events (#64), end to end against a real
//! Postgres and the local Stripe stand-in: ingest queues exactly the metered
//! events of orgs with a live subscription, never failing an event; the
//! shipper sends each once, retries under the same identifier, records
//! terminal failures visibly, reaches every org's rows under row-level
//! security, and does not run with billing disabled.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_billing::billing::mock::MockStripe;
use otto_billing::billing::Stripe;
use otto_billing::stripe::WebhookSecret;
use otto_billing::stripe_outbox::{self, OutboxStatus};
use otto_core::orgs::OrgsExt;
use otto_platform_server::stripe_shipper;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const FLAGS: &str = "https://otto-flags.example/mcp";
const EVALS: &str = "otto-flags/evaluations";
const EVENT_NAME: &str = "otto_flags__evaluations";
const METER_EVENTS: &str = "/v1/billing/meter_events";

struct World {
    db: Db,
    pool: PgPool,
    auth: String,
}

/// `otto-flags`, which declared `otto-flags/evaluations`.
async fn world(pool: PgPool) -> World {
    let db = Db::from_pool(pool.clone());
    resources::register(
        &db,
        ResourceServerSpec {
            resource_uri: FLAGS,
            name: "otto-flags",
            scopes: &["read"],
            default_scopes: &["read"],
        },
    )
    .await
    .unwrap();
    resources::set_service(&db, FLAGS, "otto-flags")
        .await
        .unwrap();
    let secret = resources::rotate_introspection_secret(&db, FLAGS)
        .await
        .unwrap();
    let auth = basic(FLAGS, &secret);
    let (status, body) = send(
        &db,
        Request::put("/internal/meters")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "meters": [{ "key": EVALS, "display_name": "Evals", "unit": "eval" }] })
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    World { db, pool, auth }
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

fn event(org: OrgId, quantity: Option<u64>) -> Value {
    let mut ev = json!({
        "event_id": Uuid::new_v4(),
        "org_id": org,
        "user_id": null,
        "tool": "flag.evaluate",
        "billable": true,
        "occurred_at": Utc::now(),
    });
    if let Some(q) = quantity {
        ev["meter"] = json!(EVALS);
        ev["quantity"] = json!(q);
    }
    ev
}

/// A Stripe subscription row for `org`, as setup and the webhooks leave it.
#[derive(Clone, Copy)]
enum Billing<'a> {
    /// Never started setup.
    None,
    /// A customer but no subscription yet (no card on file).
    CustomerOnly(&'a str),
    /// A customer and a subscription in this Stripe status.
    Subscribed(&'a str, &'a str),
}

impl World {
    async fn org(&self, slug: &str, billing: Billing<'_>) -> OrgId {
        let org = self.db.create_org(slug, slug).await.unwrap().id;
        let (customer, sub, status) = match billing {
            Billing::None => return org,
            Billing::CustomerOnly(c) => (Some(c), None, "active"),
            Billing::Subscribed(c, status) => (Some(c), Some(format!("sub_{slug}")), status),
        };
        sqlx::query(
            "INSERT INTO subscriptions (org_id, stripe_customer_id, stripe_subscription_id, status) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(org)
        .bind(customer)
        .bind(sub)
        .bind(status)
        .execute(&self.pool)
        .await
        .unwrap();
        org
    }

    async fn ship(&self, events: Vec<Value>) -> Value {
        let n = events.len() as u64;
        let (status, receipt) = send(
            &self.db,
            Request::post("/internal/usage")
                .header("authorization", &self.auth)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "events": events }).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(
            receipt["accepted"].as_u64().unwrap() + receipt["duplicates"].as_u64().unwrap(),
            n,
            "every event is counted, never rejected: {receipt}"
        );
        receipt
    }

    async fn rows(&self) -> Vec<Row> {
        sqlx::query_as(
            "SELECT org_id, identifier, event_name, stripe_customer_id, value, occurred_at, \
                    status, attempts, last_error \
             FROM stripe_meter_outbox ORDER BY created_at, identifier",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn row(&self, identifier: &str) -> Row {
        self.rows()
            .await
            .into_iter()
            .find(|r| r.identifier == identifier)
            .expect("an outbox row")
    }

    /// Make every pending row due now, as the backoff would after a while.
    async fn make_due(&self) {
        sqlx::query("UPDATE stripe_meter_outbox SET next_attempt_at = now()")
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn meter_quantity(&self, org: OrgId) -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE(sum(quantity), 0)::bigint FROM org_meter_period_usage \
             WHERE org_id = $1",
        )
        .bind(org)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct Row {
    org_id: Uuid,
    identifier: String,
    event_name: String,
    stripe_customer_id: String,
    value: i64,
    occurred_at: DateTime<Utc>,
    status: String,
    attempts: i32,
    last_error: Option<String>,
}

fn identifier_of(ev: &Value) -> String {
    format!("otto-flags:{}", ev["event_id"].as_str().unwrap())
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn only_metered_events_of_orgs_with_a_live_subscription_are_queued(pool: PgPool) {
    let w = world(pool).await;
    let live = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let past_due = w
        .org("pastdue", Billing::Subscribed("cus_pd", "past_due"))
        .await;
    let canceled = w
        .org("canceled", Billing::Subscribed("cus_cx", "canceled"))
        .await;
    let card_only = w.org("cardonly", Billing::CustomerOnly("cus_co")).await;
    let free = w.org("free", Billing::None).await;

    let metered = event(live, Some(7));
    let events = vec![
        metered.clone(),
        event(live, None),
        event(past_due, Some(2)),
        event(canceled, Some(3)),
        event(card_only, Some(4)),
        event(free, Some(5)),
    ];
    w.ship(events.clone()).await;

    let rows = w.rows().await;
    let mut got: Vec<_> = rows
        .iter()
        .map(|r| (r.value, r.org_id, r.stripe_customer_id.as_str()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            (2, past_due.as_uuid(), "cus_pd"),
            (7, live.as_uuid(), "cus_live")
        ],
        "only metered events of live subscriptions: {rows:?}"
    );
    let row = w.row(&identifier_of(&metered)).await;
    assert_eq!(row.event_name, EVENT_NAME);
    assert_eq!(row.status, "pending");
    assert_eq!(row.attempts, 0);
    let sent_at: DateTime<Utc> = metered["occurred_at"].as_str().unwrap().parse().unwrap();
    assert!((row.occurred_at - sent_at).num_milliseconds().abs() < 1);

    // Every event still counted, billed through Stripe or not.
    for (org, q) in [(live, 7), (canceled, 3), (card_only, 4), (free, 5)] {
        assert_eq!(w.meter_quantity(org).await, q);
    }

    // A replayed batch is a duplicate everywhere, the outbox included.
    let receipt = w.ship(events).await;
    assert_eq!(receipt["duplicates"], json!(6));
    assert_eq!(w.rows().await.len(), 2);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn queueing_never_fails_an_event(pool: PgPool) {
    let w = world(pool).await;
    let live = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let other = w.org("other", Billing::Subscribed("cus_o", "active")).await;
    // Another org's row already holds the identifier (a resource server that
    // reused an event id): the event is counted, and nothing is queued twice.
    let ev = event(live, Some(9));
    sqlx::query(
        "INSERT INTO stripe_meter_outbox \
           (org_id, identifier, event_name, stripe_customer_id, value, occurred_at) \
         VALUES ($1, $2, $3, 'cus_o', 1, now())",
    )
    .bind(other)
    .bind(identifier_of(&ev))
    .bind(EVENT_NAME)
    .execute(&w.pool)
    .await
    .unwrap();
    let receipt = w.ship(vec![ev]).await;
    assert_eq!(receipt["accepted"], json!(1));
    assert_eq!(w.meter_quantity(live).await, 9);
    assert_eq!(w.rows().await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_shipped_event_is_sent_once_and_marked_sent(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let ev = event(org, Some(42));
    w.ship(vec![ev.clone()]).await;

    assert_eq!(
        stripe_shipper::ship_due(&w.db, &mock.client())
            .await
            .unwrap(),
        1
    );
    let row = w.row(&identifier_of(&ev)).await;
    assert_eq!((row.status.as_str(), row.attempts), ("sent", 1));
    assert_eq!(row.last_error, None);

    let posts = mock.requests("POST", METER_EVENTS);
    assert_eq!(posts.len(), 1);
    let p = &posts[0];
    assert_eq!(p.field("event_name"), Some(EVENT_NAME));
    assert_eq!(p.field("identifier"), Some(identifier_of(&ev).as_str()));
    assert_eq!(p.field("payload[stripe_customer_id]"), Some("cus_live"));
    assert_eq!(p.field("payload[value]"), Some("42"));
    assert_eq!(
        p.field("timestamp"),
        Some(row.occurred_at.timestamp().to_string().as_str())
    );
    assert_eq!(
        p.idempotency_key.as_deref(),
        Some(format!("otto-mev-{}-1", identifier_of(&ev)).as_str())
    );

    // Nothing is due any more.
    w.make_due().await;
    assert_eq!(
        stripe_shipper::ship_due(&w.db, &mock.client())
            .await
            .unwrap(),
        0
    );
    assert_eq!(mock.meter_events().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_retry_reuses_the_identifier_and_lands_once(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let ev = event(org, Some(3));
    let id = identifier_of(&ev);
    w.ship(vec![ev]).await;

    for status in [500, 429] {
        mock.fail(METER_EVENTS, status);
        stripe_shipper::ship_due(&w.db, &mock.client())
            .await
            .unwrap();
        mock.clear_failures();
        let row = w.row(&id).await;
        assert_eq!(row.status, "pending", "{status} is retried");
        assert!(
            row.last_error
                .as_deref()
                .is_some_and(|e| e.contains(&status.to_string())),
            "{row:?}"
        );
        // Not due until the backoff has passed.
        assert_eq!(
            stripe_shipper::ship_due(&w.db, &mock.client())
                .await
                .unwrap(),
            0
        );
        w.make_due().await;
    }
    stripe_shipper::ship_due(&w.db, &mock.client())
        .await
        .unwrap();
    let row = w.row(&id).await;
    assert_eq!((row.status.as_str(), row.attempts), ("sent", 3));

    let posts = mock.requests("POST", METER_EVENTS);
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|p| p.field("identifier") == Some(&id)));
    assert!(posts.iter().all(|p| p.field("payload[value]") == Some("3")));
    // A new key per recorded failure: Stripe would replay a cached 500 under
    // the old one.
    let keys: Vec<_> = posts.iter().map(|p| p.idempotency_key.clone()).collect();
    assert_eq!(
        keys,
        (1..=3)
            .map(|n| Some(format!("otto-mev-{id}-{n}")))
            .collect::<Vec<_>>()
    );
    assert_eq!(mock.meter_events().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn terminal_failures_are_recorded_and_never_retried(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;

    // A 4xx other than 429: rejected.
    let refused = event(org, Some(1));
    w.ship(vec![refused.clone()]).await;
    mock.fail(METER_EVENTS, 400);
    stripe_shipper::ship_due(&w.db, &mock.client())
        .await
        .unwrap();
    mock.clear_failures();
    let row = w.row(&identifier_of(&refused)).await;
    assert_eq!((row.status.as_str(), row.attempts), ("rejected", 1));
    assert!(row.last_error.as_deref().is_some_and(|e| e.contains("400")));

    // Older than Stripe accepts: expired without a call.
    let old = event(org, Some(2));
    w.ship(vec![old.clone()]).await;
    sqlx::query(
        "UPDATE stripe_meter_outbox SET occurred_at = now() - interval '40 days' \
         WHERE identifier = $1",
    )
    .bind(identifier_of(&old))
    .execute(&w.pool)
    .await
    .unwrap();

    // Failing past its 12 h window: expired, not retried.
    let late = event(org, Some(3));
    w.ship(vec![late.clone()]).await;
    sqlx::query(
        "UPDATE stripe_meter_outbox SET first_attempt_at = now() - interval '11 hours 59 minutes', \
           attempts = 20 \
         WHERE identifier = $1",
    )
    .bind(identifier_of(&late))
    .execute(&w.pool)
    .await
    .unwrap();

    let posts_before = mock.requests("POST", METER_EVENTS).len();
    mock.fail(METER_EVENTS, 503);
    w.make_due().await;
    stripe_shipper::ship_due(&w.db, &mock.client())
        .await
        .unwrap();
    mock.clear_failures();
    assert_eq!(
        mock.requests("POST", METER_EVENTS).len(),
        posts_before + 1,
        "only the late row was sent; the old one never was"
    );

    let old_row = w.row(&identifier_of(&old)).await;
    assert_eq!((old_row.status.as_str(), old_row.attempts), ("expired", 0));
    assert!(old_row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("older than")));
    let late_row = w.row(&identifier_of(&late)).await;
    assert_eq!(late_row.status, "expired");
    assert!(late_row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("retry window closed") && e.contains("503")));

    // None of them is claimed again, and the lost ones are counted.
    w.make_due().await;
    assert_eq!(
        stripe_shipper::ship_due(&w.db, &mock.client())
            .await
            .unwrap(),
        0
    );
    let mut out = Vec::new();
    stripe_shipper::write_counts(&w.db, &mut out).await.unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("rejected  1"), "{out}");
    assert!(out.contains("expired   2"), "{out}");
    assert!(
        out.contains("3 metered event(s) never reached Stripe"),
        "{out}"
    );

    // A sweep keeps lost rows whatever their age.
    sqlx::query("UPDATE stripe_meter_outbox SET finished_at = now() - interval '90 days'")
        .execute(&w.pool)
        .await
        .unwrap();
    assert_eq!(stripe_outbox::sweep(&w.db, 35).await.unwrap(), 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_row_whose_window_closed_unsent_expires_without_a_call(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let ev = event(org, Some(1));
    w.ship(vec![ev.clone()]).await;
    // Claimed 13 h ago by a shipper that never recorded anything.
    sqlx::query("UPDATE stripe_meter_outbox SET first_attempt_at = now() - interval '13 hours'")
        .execute(&w.pool)
        .await
        .unwrap();
    stripe_shipper::ship_due(&w.db, &mock.client())
        .await
        .unwrap();
    assert!(mock.requests("POST", METER_EVENTS).is_empty());
    assert_eq!(w.row(&identifier_of(&ev)).await.status, "expired");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn sent_rows_are_swept_after_the_retention_period(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(1)), event(org, Some(2))]).await;
    stripe_shipper::ship_due(&w.db, &mock.client())
        .await
        .unwrap();
    assert_eq!(stripe_outbox::sweep(&w.db, 35).await.unwrap(), 0);
    sqlx::query(
        "UPDATE stripe_meter_outbox SET finished_at = now() - interval '36 days' \
         WHERE value = 1",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    assert_eq!(stripe_outbox::sweep(&w.db, 35).await.unwrap(), 1);
    assert_eq!(w.rows().await.len(), 1);
}

/// The shipper's functions on a pool whose every connection runs as
/// `otto_app` (neither owner nor superuser), so FORCE ROW LEVEL SECURITY and
/// the delivery policies decide, as on managed Postgres.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_shipper_reaches_every_org_under_row_level_security(pool: PgPool) {
    let w = world(pool.clone()).await;
    let mock = MockStripe::start().await;
    let acme = w.org("acme", Billing::Subscribed("cus_a", "active")).await;
    let globex = w
        .org("globex", Billing::Subscribed("cus_g", "trialing"))
        .await;
    w.ship(vec![event(acme, Some(1)), event(globex, Some(2))])
        .await;

    let restricted = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE otto_app").execute(conn).await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&restricted)
        .await
        .unwrap();
    assert_eq!(who, "otto_app");
    let app = Db::from_pool(restricted.clone());

    // Unpinned without the opt-in: nothing.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM stripe_meter_outbox")
        .fetch_one(&restricted)
        .await
        .unwrap();
    assert_eq!(n, 0, "an unpinned transaction without the opt-in saw rows");
    // Pinned: its own org's row only, opt-in or not.
    let mut tx = app.begin(acme).await.unwrap();
    sqlx::query("SELECT set_config('app.stripe_meter_delivery', 'on', true)")
        .execute(tx.conn())
        .await
        .unwrap();
    let orgs: Vec<Uuid> = sqlx::query_scalar("SELECT org_id FROM stripe_meter_outbox")
        .fetch_all(tx.conn())
        .await
        .unwrap();
    assert_eq!(orgs, vec![acme.as_uuid()]);
    drop(tx);

    assert_eq!(
        stripe_shipper::ship_due(&app, &mock.client())
            .await
            .unwrap(),
        2
    );
    let statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM stripe_meter_outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(statuses, ["sent", "sent"]);
    let counts = stripe_outbox::status_counts(&app).await.unwrap();
    assert!(counts.contains(&(OutboxStatus::Sent, 2)), "{counts:?}");

    // The delivery role can never create a row for any org.
    let mut tx = app.begin_unpinned().await.unwrap();
    sqlx::query("SELECT set_config('app.stripe_meter_delivery', 'on', true)")
        .execute(tx.conn())
        .await
        .unwrap();
    let insert = sqlx::query(
        "INSERT INTO stripe_meter_outbox \
           (org_id, identifier, event_name, stripe_customer_id, value, occurred_at) \
         VALUES ($1, 'x:1', 'x__y', 'cus_a', 1, now())",
    )
    .bind(acme)
    .execute(tx.conn())
    .await;
    assert!(insert.is_err(), "an unpinned insert was allowed");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_shipper_runs_only_when_billing_is_enabled(pool: PgPool) {
    let w = world(pool).await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let ev = event(org, Some(5));
    w.ship(vec![ev.clone()]).await;

    let (stop, rx) = tokio::sync::watch::channel(false);
    assert!(
        stripe_shipper::spawn(w.db.clone(), None, rx.clone()).is_none(),
        "billing disabled: no shipper"
    );

    let mock = MockStripe::start().await;
    let stripe = Stripe {
        client: mock.client(),
        webhook_secret: WebhookSecret::new("whsec_test").unwrap(),
    };
    let task = stripe_shipper::spawn(w.db.clone(), Some(&stripe), rx).expect("billing enabled");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while w.row(&identifier_of(&ev)).await.status != "sent" {
        assert!(tokio::time::Instant::now() < deadline, "never shipped");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    stop.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("stops on shutdown")
        .unwrap();
    assert_eq!(mock.meter_events().len(), 1);
}
