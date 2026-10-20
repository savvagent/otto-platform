//! Metered usage to Stripe meter events (#64), end to end against a real
//! Postgres and the local Stripe stand-in: ingest adds exactly the metered
//! events of orgs with a live subscription to one open row per org, meter,
//! customer and hour, never failing an event; the shipper sends each row
//! once, retries under the same identifier, records terminal failures
//! visibly, reaches every org's rows under row-level security, and does not
//! run with billing disabled.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use otto_auth::resources::{self, ResourceServerSpec};
use otto_billing::billing::mock::MockStripe;
use otto_billing::billing::Stripe;
use otto_billing::period::{self, Month};
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
    let w = World { db, pool, auth };
    w.sync_meter().await;
    w
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

/// Ten minutes into the previous hour: an hour that has ended, so its row is
/// due at once. Within the grace of the previous month if the current one has
/// just started, so never re-dated.
fn last_hour() -> DateTime<Utc> {
    period::hour_bucket(Utc::now()) - Duration::minutes(50)
}

fn event_at(org: OrgId, quantity: Option<u64>, at: DateTime<Utc>) -> Value {
    let mut ev = json!({
        "event_id": Uuid::new_v4(),
        "org_id": org,
        "user_id": null,
        "tool": "flag.evaluate",
        "billable": true,
        "occurred_at": at,
    });
    if let Some(q) = quantity {
        ev["meter"] = json!(EVALS);
        ev["quantity"] = json!(q);
    }
    ev
}

/// A metered (or, with `None`, unmetered) event of the last hour.
fn event(org: OrgId, quantity: Option<u64>) -> Value {
    event_at(org, quantity, last_hour())
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

/// SQL for the start of the UTC hour `n` hours ago, whatever the session's
/// time zone.
fn hours_ago(n: u32) -> String {
    format!("to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600 - {n} * 3600)")
}

impl World {
    async fn org(&self, slug: &str, billing: Billing<'_>) -> OrgId {
        let org = self.db.create_org(slug, slug).await.unwrap().id;
        self.bill(org, slug, billing).await;
        org
    }

    async fn bill(&self, org: OrgId, slug: &str, billing: Billing<'_>) {
        let (customer, sub, status) = match billing {
            Billing::None => return,
            Billing::CustomerOnly(c) => (Some(c), None, "active"),
            Billing::Subscribed(c, status) => (Some(c), Some(format!("sub_{slug}")), status),
        };
        sqlx::query(
            "INSERT INTO subscriptions (org_id, stripe_customer_id, stripe_subscription_id, status) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id, \
               stripe_subscription_id = EXCLUDED.stripe_subscription_id, status = EXCLUDED.status",
        )
        .bind(org)
        .bind(customer)
        .bind(sub)
        .bind(status)
        .execute(&self.pool)
        .await
        .unwrap();
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
            "SELECT id, org_id, identifier, event_name, stripe_customer_id, value, bucket_start, \
                    next_attempt_at, status, attempts, last_error \
             FROM stripe_meter_outbox ORDER BY created_at, value",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    /// The only row there is.
    async fn only_row(&self) -> Row {
        let mut rows = self.rows().await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        rows.remove(0)
    }

    /// The row most recently created.
    async fn newest(&self) -> Row {
        self.rows().await.pop().expect("an outbox row")
    }

    async fn row(&self, id: Uuid) -> Row {
        self.rows()
            .await
            .into_iter()
            .find(|r| r.id == id)
            .expect("the outbox row")
    }

    /// A row written straight to the table (as the owner, past row-level
    /// security), for shipper tests that need many: hour `hours_ago`.
    async fn insert_row(&self, org: OrgId, customer: &str, value: i64, hours: u32) -> Uuid {
        sqlx::query_scalar(&format!(
            "INSERT INTO stripe_meter_outbox \
               (org_id, event_name, stripe_customer_id, value, bucket_start) \
             VALUES ($1, $2, $3, $4, {}) RETURNING id",
            hours_ago(hours)
        ))
        .bind(org)
        .bind(EVENT_NAME)
        .bind(customer)
        .bind(value)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    /// Give the meter its Stripe billing meter, as `stripe sync` does.
    async fn sync_meter(&self) {
        sqlx::query(
            "INSERT INTO stripe_meters (meter, stripe_meter_id, event_name) \
             VALUES ($1, 'mtr_evals', $2)",
        )
        .bind(EVALS)
        .bind(EVENT_NAME)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn unsync_meter(&self) {
        sqlx::query("DELETE FROM stripe_meters")
            .execute(&self.pool)
            .await
            .unwrap();
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

    async fn ship_due(&self, mock: &MockStripe) -> stripe_shipper::PassReport {
        stripe_shipper::ship_due(&self.db, &mock.client())
            .await
            .unwrap()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct Row {
    id: Uuid,
    org_id: Uuid,
    identifier: String,
    event_name: String,
    stripe_customer_id: String,
    value: i64,
    bucket_start: DateTime<Utc>,
    next_attempt_at: DateTime<Utc>,
    status: String,
    attempts: i32,
    last_error: Option<String>,
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
    let row = rows.iter().find(|r| r.org_id == live.as_uuid()).unwrap();
    assert_eq!(row.event_name, EVENT_NAME);
    assert_eq!(row.status, "pending");
    assert_eq!(row.attempts, 0);
    assert!(row.identifier.starts_with("agg:"), "{}", row.identifier);
    let sent_at: DateTime<Utc> = metered["occurred_at"].as_str().unwrap().parse().unwrap();
    assert_eq!(row.bucket_start, period::hour_bucket(sent_at));
    assert_eq!(
        row.next_attempt_at,
        row.bucket_start + Duration::hours(1),
        "due when its hour ends"
    );

    // Every event still counted, billed through Stripe or not.
    for (org, q) in [(live, 7), (canceled, 3), (card_only, 4), (free, 5)] {
        assert_eq!(w.meter_quantity(org).await, q);
    }

    // A replayed batch is a duplicate everywhere: the ledger claim stops it
    // before it can add to the outbox.
    let receipt = w.ship(events).await;
    assert_eq!(receipt["duplicates"], json!(6));
    let again = w.rows().await;
    assert_eq!(
        again.iter().map(|r| r.value).collect::<Vec<_>>(),
        rows.iter().map(|r| r.value).collect::<Vec<_>>(),
        "a replay adds nothing"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_hours_events_are_one_row_and_one_stripe_call(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let hour = last_hour();
    // Forty events in one hour, in two batches.
    let events: Vec<_> = (1..=40u64)
        .map(|q| event_at(org, Some(q), hour + Duration::seconds(q as i64)))
        .collect();
    w.ship(events[..25].to_vec()).await;
    w.ship(events[25..].to_vec()).await;
    let row = w.only_row().await;
    assert_eq!(row.value, (1..=40).sum::<i64>());
    assert_eq!(row.bucket_start, period::hour_bucket(hour));

    let report = w.ship_due(&mock).await;
    assert_eq!((report.claimed, report.sent), (1, 1));
    let posts = mock.requests("POST", METER_EVENTS);
    assert_eq!(posts.len(), 1, "one call for the hour");
    assert_eq!(posts[0].field("payload[value]"), Some("820"));
    assert_eq!(
        posts[0].field("timestamp"),
        Some(row.bucket_start.timestamp().to_string().as_str()),
        "the hour's start"
    );
    assert_eq!(w.meter_quantity(org).await, 820);

    // Another hour is another row.
    let earlier = hour - Duration::hours(1);
    if Month::of(earlier) == Month::of(hour) {
        w.ship(vec![event_at(org, Some(5), earlier)]).await;
        let newest = w.newest().await;
        assert_eq!(
            (newest.value, newest.bucket_start),
            (5, period::hour_bucket(earlier))
        );
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_claimed_row_takes_no_more_usage(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(3))]).await;
    let first = stripe_outbox::claim_due(&w.db, 10).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].value, 3);

    // Same hour, after the claim: a new row with its own identifier.
    w.ship(vec![event(org, Some(4))]).await;
    let rows = w.rows().await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        w.row(first[0].id).await.value,
        3,
        "the claimed row is fixed"
    );
    let second = rows.iter().find(|r| r.id != first[0].id).unwrap();
    assert_eq!(second.value, 4);
    assert_eq!(second.bucket_start, first[0].bucket_start);
    assert_ne!(second.identifier, first[0].identifier);

    // A failed attempt keeps the row closed too.
    stripe_outbox::mark_retry(&w.db, &first[0], "HTTP 429", false)
        .await
        .unwrap();
    w.ship(vec![event(org, Some(5))]).await;
    assert_eq!(w.row(first[0].id).await.value, 3);
    assert_eq!(w.row(second.id).await.value, 9, "the open row took it");

    w.make_due().await;
    let report = w.ship_due(&mock).await;
    assert_eq!(report.sent, 2);
    let mut values: Vec<_> = mock
        .requests("POST", METER_EVENTS)
        .iter()
        .map(|p| p.field("payload[value]").unwrap().to_owned())
        .collect();
    values.sort();
    assert_eq!(values, ["3", "9"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_full_row_closes_and_queueing_never_fails_an_event(pool: PgPool) {
    let w = world(pool).await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(1))]).await;
    let row = w.only_row().await;
    // As full as an open row can be.
    sqlx::query("UPDATE stripe_meter_outbox SET value = $1")
        .bind(stripe_outbox::OPEN_ROW_MAX_VALUE)
        .execute(&w.pool)
        .await
        .unwrap();
    let max = otto_resource::MAX_METER_QUANTITY;
    let receipt = w.ship(vec![event(org, Some(max))]).await;
    assert_eq!(receipt["accepted"], json!(1));
    let full = stripe_outbox::OPEN_ROW_MAX_VALUE + max as i64;
    assert_eq!(w.row(row.id).await.value, full);
    // Past the open limit: the next event opens a new row.
    let receipt = w.ship(vec![event(org, Some(max))]).await;
    assert_eq!(receipt["accepted"], json!(1));
    let rows = w.rows().await;
    assert_eq!(rows.len(), 2);
    assert_eq!(w.row(row.id).await.value, full);
    assert!(full <= stripe_outbox::MAX_OUTBOX_VALUE);
    assert_eq!(w.meter_quantity(org).await, 1 + 2 * max as i64);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_shipped_row_is_sent_once_and_marked_sent(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(42))]).await;
    let queued = w.only_row().await;

    assert_eq!(w.ship_due(&mock).await.claimed, 1);
    let row = w.row(queued.id).await;
    assert_eq!((row.status.as_str(), row.attempts), ("sent", 1));
    assert_eq!(row.last_error, None);

    let posts = mock.requests("POST", METER_EVENTS);
    assert_eq!(posts.len(), 1);
    let p = &posts[0];
    assert_eq!(p.field("event_name"), Some(EVENT_NAME));
    assert_eq!(p.field("identifier"), Some(row.identifier.as_str()));
    assert_eq!(p.field("payload[stripe_customer_id]"), Some("cus_live"));
    assert_eq!(p.field("payload[value]"), Some("42"));
    assert_eq!(
        p.field("timestamp"),
        Some(row.bucket_start.timestamp().to_string().as_str())
    );
    assert_eq!(
        p.idempotency_key.as_deref(),
        Some(format!("otto-mev-{}-1", row.identifier).as_str())
    );

    // Nothing is due any more.
    w.make_due().await;
    assert_eq!(w.ship_due(&mock).await.claimed, 0);
    assert_eq!(mock.meter_events().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_row_of_the_current_hour_waits_for_the_hour_to_end(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event_at(org, Some(1), Utc::now())]).await;
    assert_eq!(w.ship_due(&mock).await.claimed, 0);
    w.make_due().await;
    assert_eq!(w.ship_due(&mock).await.sent, 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_retry_reuses_the_identifier_and_lands_once(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(3))]).await;
    let queued = w.only_row().await;
    let id = queued.identifier.clone();

    for status in [500, 429] {
        mock.fail(METER_EVENTS, status);
        w.ship_due(&mock).await;
        mock.clear_failures();
        let row = w.row(queued.id).await;
        assert_eq!(row.status, "pending", "{status} is retried");
        assert!(
            row.last_error
                .as_deref()
                .is_some_and(|e| e.contains(&status.to_string())),
            "{row:?}"
        );
        // Not due until the backoff has passed.
        assert_eq!(w.ship_due(&mock).await.claimed, 0);
        w.make_due().await;
    }
    w.ship_due(&mock).await;
    let row = w.row(queued.id).await;
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
    w.ship(vec![event(org, Some(1))]).await;
    let refused = w.newest().await;
    mock.fail(METER_EVENTS, 400);
    w.ship_due(&mock).await;
    mock.clear_failures();
    let row = w.row(refused.id).await;
    assert_eq!((row.status.as_str(), row.attempts), ("rejected", 1));
    assert!(row.last_error.as_deref().is_some_and(|e| e.contains("400")));

    // Older than Stripe accepts: expired without a call. (Moving its hour
    // also moves it off the open row's key.)
    w.ship(vec![event(org, Some(2))]).await;
    let old = w.newest().await;
    sqlx::query(&format!(
        "UPDATE stripe_meter_outbox SET bucket_start = {} WHERE id = $1",
        hours_ago(40 * 24)
    ))
    .bind(old.id)
    .execute(&w.pool)
    .await
    .unwrap();

    // Failing past its 12 h window: expired, not retried.
    w.ship(vec![event(org, Some(3))]).await;
    let late = w.newest().await;
    assert_ne!(late.id, old.id);
    sqlx::query(
        "UPDATE stripe_meter_outbox SET window_started_at = now() - interval '11 hours 59 minutes', \
           attempts = 20 \
         WHERE id = $1",
    )
    .bind(late.id)
    .execute(&w.pool)
    .await
    .unwrap();

    let posts_before = mock.requests("POST", METER_EVENTS).len();
    mock.fail(METER_EVENTS, 503);
    w.make_due().await;
    w.ship_due(&mock).await;
    mock.clear_failures();
    assert_eq!(
        mock.requests("POST", METER_EVENTS).len(),
        posts_before + 1,
        "only the late row was sent; the old one never was"
    );

    let old_row = w.row(old.id).await;
    assert_eq!((old_row.status.as_str(), old_row.attempts), ("expired", 0));
    assert!(old_row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("older than") && !e.contains("may have been delivered")));
    let late_row = w.row(late.id).await;
    assert_eq!(late_row.status, "expired");
    assert!(late_row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("retry window closed")
            && e.contains("503")
            && e.contains("may have been delivered")));

    // None of them is claimed again, and the lost ones are counted.
    w.make_due().await;
    assert_eq!(w.ship_due(&mock).await.claimed, 0);
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
    w.ship(vec![event(org, Some(1))]).await;
    // Claimed 13 h ago by a shipper that never recorded anything: its answer
    // was lost, so the window started then.
    sqlx::query("UPDATE stripe_meter_outbox SET sending_since = now() - interval '13 hours'")
        .execute(&w.pool)
        .await
        .unwrap();
    w.ship_due(&mock).await;
    assert!(mock.requests("POST", METER_EVENTS).is_empty());
    let row = w.only_row().await;
    assert_eq!(row.status, "expired");
    assert!(row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("may have been delivered")));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn sent_rows_are_swept_after_the_retention_period_in_batches(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let a = w.org("acme", Billing::Subscribed("cus_a", "active")).await;
    let b = w
        .org("globex", Billing::Subscribed("cus_b", "active"))
        .await;
    w.ship(vec![event(a, Some(1)), event(b, Some(2))]).await;
    w.ship_due(&mock).await;
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

    // More than one batch of old sent rows: all of them go, the rest stay.
    let n = stripe_outbox::SWEEP_BATCH + 7;
    sqlx::query(&format!(
        "INSERT INTO stripe_meter_outbox \
           (org_id, event_name, stripe_customer_id, value, bucket_start, status, attempts, \
            finished_at) \
         SELECT $1, $2, 'cus_a', 1, {}, 'sent', 1, now() - interval '40 days' \
         FROM generate_series(1, $3)",
        hours_ago(24 * 41)
    ))
    .bind(a)
    .bind(EVENT_NAME)
    .bind(n)
    .execute(&w.pool)
    .await
    .unwrap();
    assert_eq!(stripe_outbox::sweep(&w.db, 35).await.unwrap(), n as u64);
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

    // Ingest under otto_app adds to the open row through the tenant policy.
    let mut tx = app.begin(acme).await.unwrap();
    otto_billing::usage::lock_org_ingest(&mut tx).await.unwrap();
    let mut budgets = otto_billing::budgets::PendingBudgets::default();
    use otto_billing::usage::UsageExt;
    tx.ingest_usage_deferred(
        FLAGS,
        &otto_billing::usage::ShippedUsage {
            event_id: Uuid::new_v4(),
            user: None,
            tool: "t",
            billable: true,
            occurred_at: last_hour(),
            service: Some("otto-flags"),
            metered: Some(otto_billing::usage::Metered {
                meter: EVALS,
                quantity: 10,
            }),
        },
        &mut budgets,
    )
    .await
    .unwrap();
    budgets.run(&mut tx).await.unwrap();
    // Pinned, it reads its own org's pending usage.
    let before = period::hour_bucket(Utc::now()) + Duration::hours(1);
    assert!(stripe_outbox::has_pending_before(tx.conn(), acme, before)
        .await
        .unwrap());
    // Asking about another org through this pin is refused, not a false "no".
    assert!(stripe_outbox::has_pending_before(tx.conn(), globex, before)
        .await
        .is_err());
    tx.commit().await.unwrap();
    let mut values: Vec<i64> = sqlx::query_scalar("SELECT value FROM stripe_meter_outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    values.sort();
    assert_eq!(values, [2, 11]);

    // An unpinned transaction that did not opt in is refused too.
    let mut tx = app.begin_unpinned().await.unwrap();
    assert!(stripe_outbox::has_pending_before(tx.conn(), acme, before)
        .await
        .is_err());
    drop(tx);

    assert_eq!(
        stripe_shipper::ship_due(&app, &mock.client())
            .await
            .unwrap()
            .claimed,
        2
    );
    let statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM stripe_meter_outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(statuses, ["sent", "sent"]);
    let summary = stripe_outbox::outbox_summary(&app).await.unwrap();
    assert_eq!(summary.count(OutboxStatus::Sent), 2, "{summary:?}");
    let (deferred, _) = stripe_outbox::defer_unsynced(&app).await.unwrap();
    assert_eq!(deferred, 0);
    sqlx::query("UPDATE stripe_meter_outbox SET finished_at = now() - interval '40 days'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(stripe_outbox::sweep(&app, 35).await.unwrap(), 2);

    // The delivery role can never create a row for any org.
    let mut tx = app.begin_unpinned().await.unwrap();
    sqlx::query("SELECT set_config('app.stripe_meter_delivery', 'on', true)")
        .execute(tx.conn())
        .await
        .unwrap();
    let insert = sqlx::query(&format!(
        "INSERT INTO stripe_meter_outbox \
           (org_id, event_name, stripe_customer_id, value, bucket_start) \
         VALUES ($1, 'x__y', 'cus_a', 1, {})",
        hours_ago(1)
    ))
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
    w.ship(vec![event(org, Some(5))]).await;
    let queued = w.only_row().await;

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
    while w.row(queued.id).await.status != "sent" {
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

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_row_waits_until_stripe_knows_its_meter(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    w.unsync_meter().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(5))]).await;
    let stale = w.newest().await;
    sqlx::query(&format!(
        "UPDATE stripe_meter_outbox SET bucket_start = {} WHERE id = $1",
        hours_ago(40 * 24)
    ))
    .bind(stale.id)
    .execute(&w.pool)
    .await
    .unwrap();
    w.ship(vec![event(org, Some(4))]).await;
    let ev = w.newest().await;
    assert_ne!(ev.id, stale.id);

    // Not synced: nothing is claimed, and its window has not started.
    let report = w.ship_due(&mock).await;
    assert_eq!(report.claimed, 0);
    assert!(mock.requests("POST", METER_EVENTS).is_empty());
    let waiting: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT window_started_at FROM stripe_meter_outbox WHERE id = $1")
            .bind(ev.id)
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert_eq!(waiting, None);

    // Waiting rows are pushed back so they do not head the due index...
    let (deferred, oldest) = stripe_outbox::defer_unsynced(&w.db).await.unwrap();
    assert_eq!(deferred, 2);
    assert!(oldest.is_some());
    assert_eq!(stripe_outbox::defer_unsynced(&w.db).await.unwrap().0, 0);
    // ...stay open to the hour's usage...
    w.ship(vec![event(org, Some(6))]).await;
    assert_eq!(w.row(ev.id).await.value, 10);
    // ...and still expire by age.
    let expired = stripe_outbox::expire_stale(&w.db).await.unwrap();
    assert_eq!(expired.iter().map(|r| r.id).collect::<Vec<_>>(), [stale.id]);
    assert_eq!(w.row(stale.id).await.status, "expired");

    // Once sync has made the meter, it ships at its next recheck.
    w.sync_meter().await;
    assert_eq!(w.ship_due(&mock).await.claimed, 0);
    w.make_due().await;
    let report = w.ship_due(&mock).await;
    assert_eq!((report.claimed, report.sent), (1, 1));
    assert_eq!(w.row(ev.id).await.status, "sent");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn deferring_unsynced_rows_is_bounded(pool: PgPool) {
    let w = world(pool).await;
    w.unsync_meter().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let n = stripe_outbox::DEFER_BATCH + 5;
    sqlx::query(&format!(
        "INSERT INTO stripe_meter_outbox \
           (org_id, event_name, stripe_customer_id, value, bucket_start, attempts) \
         SELECT $1, $2, 'cus_live', 1, {}, 1 FROM generate_series(1, $3)",
        hours_ago(2)
    ))
    .bind(org)
    .bind(EVENT_NAME)
    .bind(n)
    .execute(&w.pool)
    .await
    .unwrap();
    let first = stripe_outbox::defer_unsynced(&w.db).await.unwrap().0;
    assert_eq!(first, stripe_outbox::DEFER_BATCH);
    assert_eq!(stripe_outbox::defer_unsynced(&w.db).await.unwrap().0, 5);
    assert_eq!(stripe_outbox::defer_unsynced(&w.db).await.unwrap().0, 0);
}

/// An earlier attempt reached Stripe but its answer was lost (here: a send
/// past the deadline that Stripe still processed). The retry goes out under
/// a new key with the same identifier; Stripe drops it as a duplicate,
/// answering either `200` or a duplicate-identifier `400`. Both are sent.
async fn lost_answer_then_duplicate(pool: PgPool, duplicate_is_error: bool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    mock.answer_duplicates_with_error(duplicate_is_error);
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(6))]).await;
    let queued = w.only_row().await;
    let id = queued.identifier.clone();

    mock.delay(METER_EVENTS, std::time::Duration::from_millis(600));
    let report = stripe_shipper::ship_due_with_deadline(
        &w.db,
        &mock.client(),
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!((report.claimed, report.sent), (1, 0));
    let row = w.row(queued.id).await;
    assert_eq!(row.status, "pending");
    assert!(row
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("no response")));
    let window: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT window_started_at FROM stripe_meter_outbox")
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert!(window.is_some(), "a timeout may have reached Stripe");

    // Stripe processed it anyway.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    mock.clear_delays();
    assert_eq!(mock.meter_events().len(), 1);

    w.make_due().await;
    w.ship_due(&mock).await;
    let row = w.row(queued.id).await;
    assert_eq!((row.status.as_str(), row.attempts), ("sent", 2));
    let keys: Vec<_> = mock
        .requests("POST", METER_EVENTS)
        .iter()
        .map(|p| p.idempotency_key.clone())
        .collect();
    assert_eq!(
        keys,
        [
            Some(format!("otto-mev-{id}-1")),
            Some(format!("otto-mev-{id}-2"))
        ]
    );
    assert_eq!(mock.meter_events().len(), 1, "counted once");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_lost_answer_retried_is_sent_when_stripe_answers_the_duplicate_ok(pool: PgPool) {
    lost_answer_then_duplicate(pool, false).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_lost_answer_retried_is_sent_when_stripe_refuses_the_duplicate(pool: PgPool) {
    lost_answer_then_duplicate(pool, true).await;
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn refusals_before_processing_do_not_start_the_retry_window(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(8))]).await;
    let queued = w.only_row().await;
    // Simulated clock: the usage is 13 h old, and the key has been refused
    // long enough for hour-long backoffs.
    sqlx::query(&format!(
        "UPDATE stripe_meter_outbox SET bucket_start = {}, attempts = 20",
        hours_ago(13)
    ))
    .execute(&w.pool)
    .await
    .unwrap();

    for status in [401, 403, 429, 401, 401] {
        mock.fail(METER_EVENTS, status);
        let report = w.ship_due(&mock).await;
        mock.clear_failures();
        assert_eq!(report.sent, 0);
        assert_eq!(report.claimed, 1, "{status}");
        // As if the backoff had passed, and the 13 h with it.
        w.make_due().await;
        let (status_now, window): (String, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT status, window_started_at FROM stripe_meter_outbox")
                .fetch_one(&w.pool)
                .await
                .unwrap();
        assert_eq!(status_now, "pending", "{status} must not expire the row");
        assert_eq!(window, None, "{status} must not start the window");
    }

    // The key is fixed: it ships.
    w.ship_due(&mock).await;
    assert_eq!(w.row(queued.id).await.status, "sent");
    assert_eq!(mock.meter_events().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn one_customer_and_meter_is_sent_one_at_a_time(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    for (slug, customer) in [("acme", "cus_a"), ("globex", "cus_b"), ("initech", "cus_c")] {
        let org = w.org(slug, Billing::Subscribed(customer, "active")).await;
        // Three closed hours each.
        for hours in 2..=4 {
            w.insert_row(org, customer, 1, hours).await;
        }
    }
    mock.delay(METER_EVENTS, std::time::Duration::from_millis(80));
    let report = w.ship_due(&mock).await;
    assert_eq!((report.claimed, report.sent), (9, 9));
    let (per_customer, total) = mock.max_meter_events_in_flight();
    assert_eq!(
        per_customer, 1,
        "never two calls for one customer and meter"
    );
    assert!(total >= 2, "different customers go in parallel: {total}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_pass_without_progress_does_not_start_the_next_at_once(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    // More than a batch, every send failing.
    for hours in 2..(2 + stripe_shipper::BATCH as u32 + 4) {
        w.insert_row(org, "cus_live", 1, hours).await;
    }
    mock.fail(METER_EVENTS, 500);

    let (stop, rx) = tokio::sync::watch::channel(false);
    let stripe = Stripe {
        client: mock.client(),
        webhook_secret: WebhookSecret::new("whsec_test").unwrap(),
    };
    let task = stripe_shipper::spawn(w.db.clone(), Some(&stripe), rx).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while mock.requests("POST", METER_EVENTS).len() < stripe_shipper::BATCH as usize {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first pass never ran"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Well inside POLL: a hot loop would have claimed the other 4 by now.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(
        mock.requests("POST", METER_EVENTS).len(),
        stripe_shipper::BATCH as usize
    );
    stop.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("stops on shutdown")
        .unwrap();
}

/// A shipper whose lease lapsed and was claimed again cannot record over the
/// new claim: all its writes are fenced by the claim's `sending_since`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stale_shipper_cannot_record_over_a_newer_claim(pool: PgPool) {
    let w = world(pool).await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    w.ship(vec![event(org, Some(2))]).await;

    let first = stripe_outbox::claim_due(&w.db, 10).await.unwrap().remove(0);
    // Its lease lapses; another shipper claims the row.
    sqlx::query("UPDATE stripe_meter_outbox SET next_attempt_at = now() - interval '1 second'")
        .execute(&w.pool)
        .await
        .unwrap();
    let second = stripe_outbox::claim_due(&w.db, 10).await.unwrap().remove(0);
    assert_ne!(first.claimed_at, second.claimed_at);
    // The first claim's answer was never recorded: the window starts there.
    assert_eq!(second.window_started_at, Some(first.claimed_at));

    let state = || async {
        sqlx::query_as::<_, (String, i32, Option<DateTime<Utc>>)>(
            "SELECT status, attempts, sending_since FROM stripe_meter_outbox",
        )
        .fetch_one(&w.pool)
        .await
        .unwrap()
    };
    // The stale shipper's definite failure, a terminal, and a success: no
    // effect.
    assert_eq!(
        stripe_outbox::mark_retry(&w.db, &first, "HTTP 401", false)
            .await
            .unwrap(),
        None
    );
    assert!(
        !stripe_outbox::mark_terminal(&w.db, &first, OutboxStatus::Rejected, "HTTP 400", true)
            .await
            .unwrap()
    );
    assert!(!stripe_outbox::mark_sent(&w.db, &first).await.unwrap());
    assert_eq!(
        state().await,
        ("pending".to_owned(), 0, Some(second.claimed_at)),
        "the newer claim's in-flight marker survives"
    );

    // The current claim records normally.
    assert_eq!(
        stripe_outbox::mark_retry(&w.db, &second, "HTTP 429", false)
            .await
            .unwrap(),
        Some(OutboxStatus::Pending)
    );
    assert_eq!(state().await, ("pending".to_owned(), 1, None));
    w.make_due().await;
    let third = stripe_outbox::claim_due(&w.db, 10).await.unwrap().remove(0);
    assert!(stripe_outbox::mark_sent(&w.db, &third).await.unwrap());
    assert_eq!(state().await, ("sent".to_owned(), 2, None));
}

/// Pending usage before an instant holds an invoice; sent and lost rows do
/// not.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn pending_usage_before_an_instant_is_reported(pool: PgPool) {
    let w = world(pool).await;
    let mock = MockStripe::start().await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let other = w.org("other", Billing::Subscribed("cus_o", "active")).await;
    let pending = |before: DateTime<Utc>| {
        let db = w.db.clone();
        async move {
            let mut tx = db.begin(org).await.unwrap();
            stripe_outbox::has_pending_before(tx.conn(), org, before)
                .await
                .unwrap()
        }
    };
    let hour = period::hour_bucket(last_hour());
    assert!(!pending(hour + Duration::hours(1)).await, "nothing queued");

    w.ship(vec![event(org, Some(1)), event(other, Some(1))])
        .await;
    assert!(pending(hour + Duration::hours(1)).await);
    // An opted-in unpinned transaction may ask too.
    let mut tx = w.db.begin_unpinned().await.unwrap();
    sqlx::query("SELECT set_config('app.stripe_meter_delivery', 'on', true)")
        .execute(tx.conn())
        .await
        .unwrap();
    assert!(
        stripe_outbox::has_pending_before(tx.conn(), other, hour + Duration::hours(1))
            .await
            .unwrap()
    );
    drop(tx);
    assert!(
        !pending(hour).await,
        "the row's hour starts at, not before, `hour`"
    );

    // Claimed but unsent still holds.
    let claimed = stripe_outbox::claim_due(&w.db, 10).await.unwrap();
    assert_eq!(claimed.len(), 2);
    assert!(pending(hour + Duration::hours(1)).await);
    for row in &claimed {
        let sent = row.org_id == org.as_uuid();
        if sent {
            stripe_outbox::mark_sent(&w.db, row).await.unwrap();
        } else {
            stripe_outbox::mark_retry(&w.db, row, "HTTP 500", true)
                .await
                .unwrap();
        }
    }
    assert!(
        !pending(hour + Duration::hours(1)).await,
        "sent; the other org's pending row is not this org's"
    );

    // A lost row does not hold an invoice either.
    w.ship(vec![event(org, Some(1))]).await;
    mock.fail(METER_EVENTS, 400);
    w.make_due().await;
    w.ship_due(&mock).await;
    assert!(!pending(hour + Duration::hours(1)).await);
    let lost: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM stripe_meter_outbox WHERE org_id = $1 AND status = 'rejected'",
    )
    .bind(org)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(lost, 1);
}

/// Usage counted before an org's subscription went live is queued once,
/// however often the backfill runs, and never on top of what ingest queued.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_backfill_queues_unqueued_usage_once(pool: PgPool) {
    let w = world(pool).await;
    let org = w.org("acme", Billing::CustomerOnly("cus_a")).await;
    let now = Utc::now();
    let month = Month::of(now);
    // Counted for the current month, but no live subscription: not queued.
    let at = |minutes| now - Duration::minutes(minutes);
    w.ship(vec![
        event_at(org, Some(5), at(1)),
        event_at(org, Some(7), at(2)),
    ])
    .await;
    assert!(w.rows().await.is_empty());

    let backfill = |month: Month| {
        let db = w.db.clone();
        async move {
            let mut tx = db.begin(org).await.unwrap();
            let r = stripe_outbox::backfill_period(&mut tx, month).await;
            tx.commit().await.unwrap();
            r
        }
    };
    // Still no live subscription: nothing to bill.
    assert_eq!(backfill(month).await.unwrap(), 0);

    w.bill(org, "acme", Billing::Subscribed("cus_a", "active"))
        .await;
    assert_eq!(backfill(month).await.unwrap(), 12);
    let row = w.only_row().await;
    assert_eq!((row.value, row.stripe_customer_id.as_str()), (12, "cus_a"));
    assert_eq!(row.bucket_start, period::hour_bucket(Utc::now()));
    assert_eq!(Month::of(row.bucket_start), month);
    // Idempotent.
    assert_eq!(backfill(month).await.unwrap(), 0);

    // Ingest after the subscription queues its own events, and a later
    // backfill adds nothing on top.
    w.ship(vec![event_at(org, Some(3), Utc::now())]).await;
    let total: i64 = w.rows().await.iter().map(|r| r.value).sum();
    assert_eq!(total, 15);
    assert_eq!(w.meter_quantity(org).await, 15);
    assert_eq!(backfill(month).await.unwrap(), 0);

    // Rows already sent (or lost) count as queued.
    sqlx::query(
        "UPDATE stripe_meter_outbox SET status = 'sent', finished_at = now(), attempts = 1",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    assert_eq!(backfill(month).await.unwrap(), 0);

    // A month that has not started is refused; a closed one too.
    let next = month.offset(1).unwrap();
    assert!(backfill(next).await.is_err());
    assert!(backfill(month.offset(-3).unwrap()).await.is_err());
    let previous = month.offset(-1).unwrap();
    assert_eq!(
        backfill(previous).await.is_err(),
        period::period_closed(previous, Utc::now()),
        "the previous month only during its grace"
    );
}

/// A late event is still accepted, and billed (counters, budget period and
/// outbox alike) in the period it arrived in, once its own has closed.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_late_event_is_billed_in_the_current_period(pool: PgPool) {
    let w = world(pool).await;
    let org = w
        .org("live", Billing::Subscribed("cus_live", "active"))
        .await;
    let now = Utc::now();
    let current = Month::of(now);
    let previous = current.offset(-1).unwrap();
    let late_at = period::starts_at(current) - Duration::minutes(30);
    let receipt = w.ship(vec![event_at(org, Some(9), late_at)]).await;
    assert_eq!(receipt["accepted"], json!(1), "a late event is accepted");

    let periods: Vec<chrono::NaiveDate> =
        sqlx::query_scalar("SELECT period_start FROM org_meter_period_usage WHERE org_id = $1")
            .bind(org)
            .fetch_all(&w.pool)
            .await
            .unwrap();
    let row = w.only_row().await;
    if period::period_closed(previous, Utc::now()) {
        assert_eq!(
            periods,
            [current.first_day()],
            "counted in the current period"
        );
        assert_eq!(Month::of(row.bucket_start), current);
        assert!(row.bucket_start >= period::hour_bucket(now));
    } else {
        // Inside the grace (the first two hours of a month): still on time.
        assert_eq!(periods, [previous.first_day()]);
        assert_eq!(row.bucket_start, period::hour_bucket(late_at));
    }
}
