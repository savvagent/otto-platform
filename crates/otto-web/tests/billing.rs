//! Card on file, the Stripe webhook, and billing switched off, end to end
//! against a real Postgres and a local mock Stripe (`otto_billing::billing::
//! mock`). No request leaves the machine.

mod common;

use chrono::{Datelike, TimeZone, Utc};
use common::{add_member, onboard, org_with_owner, register_resource, Call, Harness, PUBLIC_URL};
use http::StatusCode;
use otto_billing::billing::mock::MockStripe;
use otto_billing::billing::{self, Stripe};
use otto_billing::stripe::{
    sign_webhook, CreateCustomer, CreateSubscription, IdempotencyKey, WebhookSecret,
};
use otto_core::orgs::Role;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use otto_web::{AppState, Config};
use serde_json::{json, Value};
use sqlx::PgPool;

const WEBHOOK: &str = "/api/stripe/webhook";
const SECRET: &str = "whsec_test_billing_secret";

fn secret() -> WebhookSecret {
    WebhookSecret::new(SECRET).unwrap()
}

/// The console with billing on, against `mock`, or off with `None`.
async fn harness(pool: PgPool, mock: Option<&MockStripe>) -> Harness {
    let db = Db::from_pool(pool);
    register_resource(&db).await;
    let config = Config::new(PUBLIC_URL);
    let webauthn = otto_web::relying_party(&config).unwrap();
    let state =
        AppState::new(db.clone(), common::cipher(), webauthn, config).with_stripe(mock.map(|m| {
            Stripe {
                client: m.client(),
                webhook_secret: secret(),
            }
        }));
    Harness {
        db,
        router: otto_web::router(state),
        cipher: common::cipher(),
    }
}

/// A declared meter priced from the current month, as the operator CLI would
/// leave it (`pricebook set` refuses the current month, so it is written
/// directly, as `pricebook_cmd`'s own tests do). A fixture, not a real rate.
async fn price_a_meter(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
         VALUES ('https://svc.example/mcp', 'svc', '{a}', '{}', 'svc')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO meters (key, service, meter, display_name, unit) \
         VALUES ('svc/calls', 'svc', 'calls', 'Calls', 'call')",
    )
    .execute(pool)
    .await
    .unwrap();
    let version: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ('svc/calls', date_trunc('month', now() AT TIME ZONE 'UTC')::date) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, 1000, 0), ($1, 1, NULL, 150000)",
    )
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
}

/// The console with billing on against `mock`, over an existing pool.
fn harness_on(pool: PgPool, mock: &MockStripe) -> Harness {
    let db = Db::from_pool(pool);
    let config = Config::new(PUBLIC_URL);
    let webauthn = otto_web::relying_party(&config).unwrap();
    let state =
        AppState::new(db.clone(), common::cipher(), webauthn, config).with_stripe(Some(Stripe {
            client: mock.client(),
            webhook_secret: secret(),
        }));
    Harness {
        db,
        router: otto_web::router(state),
        cipher: common::cipher(),
    }
}

/// A Stripe event, signed now with the endpoint secret.
fn signed(
    id: &str,
    kind: &str,
    created: i64,
    object: Value,
    previous: Option<Value>,
) -> (Vec<u8>, String) {
    let mut data = json!({ "object": object });
    if let Some(p) = previous {
        data["previous_attributes"] = p;
    }
    let body = serde_json::to_vec(&json!({
        "id": id, "object": "event", "type": kind, "created": created,
        "livemode": false, "data": data,
    }))
    .unwrap();
    let header = sign_webhook(&secret(), Utc::now().timestamp(), &body);
    (body, header)
}

async fn deliver(h: &Harness, body: Vec<u8>, signature: &str) -> common::Reply {
    post_raw(h, body, Some(signature)).await
}

/// A webhook delivery as Stripe makes it: a raw JSON body, no cookie, no
/// `Origin`.
async fn post_raw(h: &Harness, body: Vec<u8>, signature: Option<&str>) -> common::Reply {
    use tower::ServiceExt;

    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(WEBHOOK)
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(sig) = signature {
        request = request.header("stripe-signature", sig);
    }
    let response = h
        .router
        .clone()
        .oneshot(request.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    common::Reply {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn audit_actions(pool: &PgPool, org: OrgId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE org_id = $1 AND action LIKE 'billing.%' ORDER BY id",
    )
    .bind(org)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn ledger(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT event_id FROM stripe_events ORDER BY event_id")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// 00:00 UTC on the first of next month, by the database's clock.
async fn next_first(pool: &PgPool) -> i64 {
    let first: chrono::NaiveDate = sqlx::query_scalar(
        "SELECT (date_trunc('month', now() AT TIME ZONE 'UTC') + interval '1 month')::date",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(first.day(), 1);
    Utc.from_utc_datetime(&first.and_hms_opt(0, 0, 0).unwrap())
        .timestamp()
}

struct Setup {
    h: Harness,
    mock: MockStripe,
    pool: PgPool,
    org: OrgId,
    owner_session: String,
    customer: String,
}

/// An org whose owner has started setup (so it has a Stripe customer), with
/// one meter priced and synced to Stripe.
async fn started(pool: PgPool) -> Setup {
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    price_a_meter(&pool).await;
    let report = billing::sync(&h.db, &mock.client()).await.unwrap();
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(report.prices_created.len(), 1);

    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await
        .expect(StatusCode::OK);
    let customer = mock.requests("POST", "/v1/customers")[0].clone();
    let customer = mock
        .seen()
        .into_iter()
        .find(|s| s.path == "/v1/checkout/sessions")
        .and_then(|s| s.field("customer").map(str::to_owned))
        .unwrap_or_else(|| panic!("no checkout session after {customer:?}"));
    Setup {
        h,
        mock,
        pool,
        org,
        owner_session: owner.session,
        customer,
    }
}

fn completed_session(customer: &str, org: OrgId, seti: &str) -> Value {
    json!({
        "id": "cs_test_1", "object": "checkout.session", "mode": "setup",
        "customer": customer, "setup_intent": seti, "status": "complete",
        "metadata": { "org_id": org.to_string() },
    })
}

/// Complete Checkout: Stripe has a succeeded setup intent with a card, and
/// tells us.
async fn complete(s: &Setup, event_id: &str, created: i64) -> common::Reply {
    complete_with(s, event_id, created, "seti_1", "pm_card_1").await
}

async fn complete_with(
    s: &Setup,
    event_id: &str,
    created: i64,
    seti: &str,
    pm: &str,
) -> common::Reply {
    s.mock.add_setup_intent(seti, &s.customer, pm, "succeeded");
    let (body, sig) = signed(
        event_id,
        "checkout.session.completed",
        created,
        completed_session(&s.customer, s.org, seti),
        None,
    );
    deliver(&s.h, body, &sig).await
}

/// An invoice of `subscription`, in API version 2025-03-31.basil's shape.
fn invoice(id: &str, customer: &str, subscription: &str) -> Value {
    json!({
        "id": id, "object": "invoice", "customer": customer,
        "parent": { "type": "subscription_details",
                    "subscription_details": { "subscription": subscription } },
    })
}

async fn deliver_event(s: &Setup, id: &str, kind: &str, at: i64, object: Value) -> common::Reply {
    let (b, h) = signed(id, kind, at, object, None);
    deliver(&s.h, b, &h).await
}

async fn current_subscription(s: &Setup) -> String {
    sqlx::query_scalar("SELECT stripe_subscription_id FROM subscriptions WHERE org_id = $1")
        .bind(s.org)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn billing_view(s: &Setup) -> Value {
    let r = Call::get("/api/orgs/acme/billing")
        .with_session(&s.owner_session)
        .send(&s.h.router)
        .await;
    r.expect(StatusCode::OK);
    r.body
}

// ------------------------------------------------------------------ setup

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_owner_starts_setup_and_gets_a_checkout_url(pool: PgPool) {
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;

    let before = Call::get("/api/orgs/acme/billing")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    before.expect(StatusCode::OK);
    assert_eq!(
        before.body,
        json!({
            "billingEnabled": true, "cardStatus": "none",
            "subscriptionStatus": null, "subscriptionLive": false,
            "billingStopped": false,
        })
    );

    let r = Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::OK);
    let url = r.body["url"].as_str().unwrap();
    assert!(url.starts_with("https://checkout.stripe.test/"), "{url}");

    // The customer: the org's name, the requesting owner's email, the org id.
    let customers = mock.requests("POST", "/v1/customers");
    assert_eq!(customers.len(), 1);
    let c = &customers[0];
    assert_eq!(c.field("email"), Some("owner@acme.test"));
    assert_eq!(c.field("name"), Some("acme"));
    assert_eq!(c.field("metadata[org_id]"), Some(org.to_string().as_str()));
    assert!(c
        .idempotency_key
        .as_deref()
        .is_some_and(|k| k.starts_with("otto-customer-")));
    // Looked for first, by the org id, so a customer left by an earlier
    // attempt is adopted rather than duplicated.
    let searches = mock.requests("GET", "/v1/customers/search");
    assert_eq!(searches.len(), 1);
    assert_eq!(
        searches[0].query_field("query"),
        Some(format!("metadata['org_id']:'{org}'").as_str())
    );

    // Checkout in setup mode, cards only, back to the console's billing page.
    let sessions = mock.requests("POST", "/v1/checkout/sessions");
    assert_eq!(sessions.len(), 1);
    let s = &sessions[0];
    assert_eq!(s.field("mode"), Some("setup"));
    assert_eq!(s.field("payment_method_types[0]"), Some("card"));
    assert_eq!(s.fields_starting("payment_method_types["), ["card"]);
    assert_eq!(s.field("currency"), None);
    assert_eq!(s.field("customer"), Some("cus_mock1"));
    assert_eq!(
        s.field("success_url"),
        Some("https://otto.test/o/acme/billing?setup=success")
    );
    assert_eq!(
        s.field("cancel_url"),
        Some("https://otto.test/o/acme/billing?setup=cancelled")
    );
    assert_eq!(s.field("metadata[org_id]"), Some(org.to_string().as_str()));
    assert!(s.idempotency_key.is_some());

    // A second start reuses the customer.
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await
        .expect(StatusCode::OK);
    assert_eq!(mock.requests("POST", "/v1/customers").len(), 1);
    assert_eq!(mock.requests("POST", "/v1/checkout/sessions").len(), 2);
    assert_eq!(
        mock.requests("POST", "/v1/checkout/sessions")[1].field("customer"),
        Some("cus_mock1")
    );

    // Audited, each time, by the owner.
    let rows: Vec<(String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT action, actor_user_id FROM audit_events \
         WHERE org_id = $1 AND action LIKE 'billing.%' ORDER BY id",
    )
    .bind(org)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    for (action, actor) in rows {
        assert_eq!(action, "billing.setup.started");
        assert_eq!(actor, Some(owner.user.as_uuid()));
    }

    // Still no card: Checkout's redirect proves nothing; the webhook does.
    let after = Call::get("/api/orgs/acme/billing")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    assert_eq!(after.body["cardStatus"], "none");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn only_an_owner_may_read_or_change_billing(pool: PgPool) {
    let mock = MockStripe::start().await;
    let h = harness(pool, Some(&mock)).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    let admin = onboard(&h, "admin@acme.test").await;
    let member = onboard(&h, "member@acme.test").await;
    let stranger = onboard(&h, "stranger@else.test").await;
    add_member(&h, org, admin.user, Role::Admin).await;
    add_member(&h, org, member.user, Role::Member).await;

    for who in [&admin, &member] {
        let r = Call::get("/api/orgs/acme/billing")
            .with_session(&who.session)
            .send(&h.router)
            .await;
        r.expect(StatusCode::FORBIDDEN);
        let r = Call::post("/api/orgs/acme/billing/setup")
            .with_session(&who.session)
            .send(&h.router)
            .await;
        r.expect(StatusCode::FORBIDDEN);
        assert_eq!(r.error_code(), Some("forbidden"));
    }
    // Not a member: the org does not exist, as everywhere else.
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&stranger.session)
        .send(&h.router)
        .await
        .expect(StatusCode::NOT_FOUND);
    // Not signed in.
    Call::get("/api/orgs/acme/billing")
        .send(&h.router)
        .await
        .expect(StatusCode::UNAUTHORIZED);

    assert!(mock.seen().is_empty(), "a refused caller reached Stripe");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn with_billing_disabled_the_routes_say_so(pool: PgPool) {
    let h = harness(pool.clone(), None).await;
    let owner = onboard(&h, "owner@acme.test").await;
    org_with_owner(&h, "acme", &owner).await;

    let r = Call::get("/api/orgs/acme/billing")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::OK);
    assert_eq!(r.body["billingEnabled"], false);
    assert_eq!(r.body["cardStatus"], "none");

    let r = Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_code(), Some("billing_disabled"));

    let (body, sig) = signed(
        "evt_off",
        "invoice.payment_failed",
        Utc::now().timestamp(),
        json!({}),
        None,
    );
    let r = deliver(&h, body, &sig).await;
    r.expect(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_code(), Some("billing_disabled"));
    assert!(ledger(&pool).await.is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stripe_outage_is_a_502_with_nothing_leaked(pool: PgPool) {
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    mock.fail("/v1/customers", 500);

    let r = Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::BAD_GATEWAY);
    assert_eq!(r.error_code(), Some("stripe_unavailable"));
    assert!(!r.text.contains("mock"), "{}", r.text);
    assert!(!r.text.contains("sk_test"), "{}", r.text);
    // Nothing half-done is recorded, and nothing is audited.
    assert!(audit_actions(&pool, org).await.is_empty());
}

// ---------------------------------------------------------------- webhook

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn checkout_completion_puts_the_card_on_file_and_subscribes(pool: PgPool) {
    let s = started(pool).await;
    let r = complete(&s, "evt_done", Utc::now().timestamp()).await;
    r.expect(StatusCode::OK);
    assert_eq!(r.body, json!({ "received": true }));

    // The card is the customer's default.
    let defaults = s
        .mock
        .requests("POST", &format!("/v1/customers/{}", s.customer));
    assert_eq!(defaults.len(), 1);
    assert_eq!(
        defaults[0].field("invoice_settings[default_payment_method]"),
        Some("pm_card_1")
    );
    assert!(defaults[0]
        .idempotency_key
        .as_deref()
        .is_some_and(|k| k.starts_with("otto-default-pm-")));

    // One subscription: an item per priced meter, anchored to 00:00 UTC on the
    // first of next month, no proration.
    let subs = s.mock.requests("POST", "/v1/subscriptions");
    assert_eq!(subs.len(), 1);
    let sub = &subs[0];
    assert_eq!(sub.field("customer"), Some(s.customer.as_str()));
    assert_eq!(
        sub.field("billing_cycle_anchor"),
        Some(next_first(&s.pool).await.to_string().as_str())
    );
    assert_eq!(sub.field("proration_behavior"), Some("none"));
    let price: String = sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(sub.fields_starting("items["), vec![price.as_str()]);
    assert_eq!(
        sub.field("metadata[org_id]"),
        Some(s.org.to_string().as_str())
    );

    assert_eq!(
        billing_view(&s).await,
        json!({
            "billingEnabled": true, "cardStatus": "active",
            "subscriptionStatus": "active", "subscriptionLive": true,
            "billingStopped": false,
        })
    );
    assert_eq!(
        audit_actions(&s.pool, s.org).await,
        [
            "billing.setup.started",
            "billing.card.added",
            "billing.subscription.created"
        ]
    );
    assert_eq!(ledger(&s.pool).await, ["evt_done"]);

    // What metered-usage shipping (#64) reads.
    let mut tx = s.h.db.begin(s.org).await.unwrap();
    let live = billing::live_subscription(&mut tx).await.unwrap().unwrap();
    assert_eq!(live.stripe_customer_id, s.customer);
    assert_eq!(live.stripe_subscription_id, s.mock.subscription_ids()[0]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_replayed_event_has_no_second_effect(pool: PgPool) {
    let s = started(pool).await;
    let now = Utc::now().timestamp();
    complete(&s, "evt_done", now).await.expect(StatusCode::OK);
    let requests = s.mock.seen().len();

    // The same delivery again: acknowledged, nothing sent, nothing written.
    complete(&s, "evt_done", now).await.expect(StatusCode::OK);
    assert_eq!(s.mock.seen().len(), requests, "a replay reached Stripe");

    // The same completion under a new event id (Stripe does not promise one
    // id per occurrence across retries of a resend): the handler itself is
    // idempotent, so still one subscription and one `card.added`.
    complete(&s, "evt_done_again", now)
        .await
        .expect(StatusCode::OK);
    assert_eq!(s.mock.subscription_ids().len(), 1);
    assert_eq!(s.mock.requests("POST", "/v1/subscriptions").len(), 1);
    assert_eq!(
        audit_actions(&s.pool, s.org).await,
        [
            "billing.setup.started",
            "billing.card.added",
            "billing.subscription.created"
        ]
    );
    assert_eq!(ledger(&s.pool).await, ["evt_done", "evt_done_again"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_bad_signature_is_refused_and_does_nothing(pool: PgPool) {
    let s = started(pool).await;
    s.mock
        .add_setup_intent("seti_1", &s.customer, "pm_card_1", "succeeded");
    let (body, _) = signed(
        "evt_forged",
        "checkout.session.completed",
        Utc::now().timestamp(),
        completed_session(&s.customer, s.org, "seti_1"),
        None,
    );
    let requests = s.mock.seen().len();

    let other = WebhookSecret::new("whsec_someone_else").unwrap();
    let forged = sign_webhook(&other, Utc::now().timestamp(), &body);
    let stale = sign_webhook(&secret(), Utc::now().timestamp() - 3600, &body);
    for header in [forged.as_str(), stale.as_str(), "t=1,v1=nothex", ""] {
        let r = deliver(&s.h, body.clone(), header).await;
        r.expect(StatusCode::BAD_REQUEST);
        assert_eq!(r.error_code(), Some("invalid_signature"), "{header}");
    }
    // No header at all.
    let r = post_raw(&s.h, body.clone(), None).await;
    r.expect(StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), Some("invalid_signature"));
    // A body changed after signing.
    let good = sign_webhook(&secret(), Utc::now().timestamp(), &body);
    let mut tampered = body.clone();
    let at = tampered.len() - 3;
    tampered[at] ^= 1;
    deliver(&s.h, tampered, &good)
        .await
        .expect(StatusCode::BAD_REQUEST);

    assert_eq!(
        s.mock.seen().len(),
        requests,
        "an unverified event reached Stripe"
    );
    assert!(ledger(&s.pool).await.is_empty());
    assert_eq!(billing_view(&s).await["cardStatus"], "none");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_oversized_body_is_refused_before_it_is_read(pool: PgPool) {
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let mut body = br#"{"id":"evt_big","type":"x","created":1,"data":{"object":{"pad":""#.to_vec();
    body.resize(otto_billing::stripe::MAX_WEBHOOK_PAYLOAD_BYTES + 1, b'a');
    body.extend_from_slice(br#""}}}"#);
    let sig = sign_webhook(&secret(), Utc::now().timestamp(), &body);
    let r = deliver(&h, body, &sig).await;
    r.expect(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.error_code(), Some("payload_too_large"));
    assert!(ledger(&pool).await.is_empty());

    // Exactly at the limit is read (and, being signed, handled).
    let mut body =
        br#"{"id":"evt_max","type":"x.y","created":1,"data":{"object":{"pad":""#.to_vec();
    let room = otto_billing::stripe::MAX_WEBHOOK_PAYLOAD_BYTES - body.len() - 4;
    body.extend(std::iter::repeat_n(b'a', room));
    body.extend_from_slice(br#""}}}"#);
    assert_eq!(body.len(), otto_billing::stripe::MAX_WEBHOOK_PAYLOAD_BYTES);
    let sig = sign_webhook(&secret(), Utc::now().timestamp(), &body);
    deliver(&h, body, &sig).await.expect(StatusCode::OK);
    assert_eq!(ledger(&pool).await, ["evt_max"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_webhook_needs_no_cookie_or_origin(pool: PgPool) {
    // Stripe sends neither; the cross-site guard only inspects cookie-bearing
    // writes, so a signed delivery with no Origin is accepted ...
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let (body, sig) = signed(
        "evt_unknown",
        "customer.created",
        Utc::now().timestamp(),
        json!({"id": "cus_x"}),
        None,
    );
    let r = deliver(&h, body, &sig).await;
    r.expect(StatusCode::OK);
    // ... and an event type billing does not handle is acknowledged and
    // recorded, with no action.
    assert_eq!(ledger(&pool).await, ["evt_unknown"]);
    assert!(mock.seen().is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn subscription_status_moves_forward_in_event_time_only(pool: PgPool) {
    let s = started(pool).await;
    let t0 = Utc::now().timestamp() - 100;
    complete(&s, "evt_done", t0).await.expect(StatusCode::OK);
    let sub_id = s.mock.subscription_ids()[0].clone();
    let sub = |status: &str| json!({ "id": sub_id, "object": "subscription", "customer": s.customer, "status": status });

    let (b, h) = signed(
        "evt_u2",
        "customer.subscription.updated",
        t0 + 20,
        sub("past_due"),
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["subscriptionStatus"], "past_due");

    // Delivered late, created earlier: ignored.
    let (b, h) = signed(
        "evt_u1",
        "customer.subscription.updated",
        t0 + 10,
        sub("active"),
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["subscriptionStatus"], "past_due");

    let (b, h) = signed(
        "evt_del",
        "customer.subscription.deleted",
        t0 + 30,
        sub("canceled"),
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    let view = billing_view(&s).await;
    assert_eq!(view["subscriptionStatus"], "canceled");
    assert_eq!(view["subscriptionLive"], false);

    // Canceled is final, whatever a later `updated` says.
    let (b, h) = signed(
        "evt_u3",
        "customer.subscription.updated",
        t0 + 40,
        sub("active"),
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["subscriptionStatus"], "canceled");

    // An event about some other subscription changes nothing.
    let other = json!({ "id": "sub_other", "customer": s.customer, "status": "active" });
    let (b, h) = signed(
        "evt_other",
        "customer.subscription.updated",
        t0 + 50,
        other,
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["subscriptionStatus"], "canceled");

    let mut tx = s.h.db.begin(s.org).await.unwrap();
    assert!(billing::live_subscription(&mut tx).await.unwrap().is_none());
    drop(tx);

    let actions = audit_actions(&s.pool, s.org).await;
    assert_eq!(
        actions
            .iter()
            .filter(|a| *a == "billing.subscription.status_changed")
            .count(),
        2,
        "{actions:?}"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn payments_failing_and_recovering_and_a_detached_card_are_recorded(pool: PgPool) {
    let s = started(pool).await;
    let t0 = Utc::now().timestamp() - 100;
    complete(&s, "evt_done", t0).await.expect(StatusCode::OK);
    let sub = current_subscription(&s).await;

    // A failure older than the card going on file: ignored.
    deliver_event(
        &s,
        "evt_old_fail",
        "invoice.payment_failed",
        t0 - 10,
        invoice("in_0", &s.customer, &sub),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");
    // A failure of some other (an old, canceled) subscription's invoice:
    // ignored.
    deliver_event(
        &s,
        "evt_other_fail",
        "invoice.payment_failed",
        t0 + 5,
        invoice("in_x", &s.customer, "sub_old"),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");

    deliver_event(
        &s,
        "evt_fail",
        "invoice.payment_failed",
        t0 + 10,
        invoice("in_1", &s.customer, &sub),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "failed");
    // The retry is paid: the card is good again.
    deliver_event(
        &s,
        "evt_paid",
        "invoice.paid",
        t0 + 15,
        invoice("in_1", &s.customer, &sub),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");
    // A paid invoice of another subscription, or with the card fine, does
    // nothing.
    deliver_event(
        &s,
        "evt_paid_other",
        "invoice.paid",
        t0 + 16,
        invoice("in_y", &s.customer, "sub_old"),
    )
    .await
    .expect(StatusCode::OK);
    deliver_event(
        &s,
        "evt_fail2",
        "invoice.payment_failed",
        t0 + 17,
        invoice("in_2", &s.customer, &sub),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "failed");

    // Some other card detached: not ours to care about.
    let (b, h) = signed(
        "evt_det_other",
        "payment_method.detached",
        t0 + 20,
        json!({ "id": "pm_other", "object": "payment_method", "customer": null }),
        Some(json!({ "customer": s.customer })),
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "failed");

    // The card on file detached: its customer is only in previous_attributes.
    let (b, h) = signed(
        "evt_det",
        "payment_method.detached",
        t0 + 30,
        json!({ "id": "pm_card_1", "object": "payment_method", "customer": null }),
        Some(json!({ "customer": s.customer })),
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "detached");
    // A paid invoice does not bring a detached card back.
    deliver_event(
        &s,
        "evt_paid_late",
        "invoice.paid",
        t0 + 40,
        invoice("in_3", &s.customer, &sub),
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "detached");

    // An event for a customer that is not ours is acknowledged, not acted on.
    deliver_event(
        &s,
        "evt_stranger",
        "invoice.payment_failed",
        t0 + 50,
        invoice("in_4", "cus_not_ours", &sub),
    )
    .await
    .expect(StatusCode::OK);

    assert_eq!(
        audit_actions(&s.pool, s.org).await,
        [
            "billing.setup.started",
            "billing.card.added",
            "billing.subscription.created",
            "billing.payment.failed",
            "billing.payment.recovered",
            "billing.payment.failed",
            "billing.card.detached",
        ]
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_new_card_replaces_and_detaches_the_old_one(pool: PgPool) {
    let s = started(pool).await;
    let t0 = Utc::now().timestamp() - 100;
    complete(&s, "evt_one", t0).await.expect(StatusCode::OK);
    assert!(s.mock.detached().is_empty());
    complete_with(&s, "evt_two", t0 + 10, "seti_2", "pm_card_2")
        .await
        .expect(StatusCode::OK);
    assert_eq!(s.mock.detached(), ["pm_card_1"]);
    let defaults = s
        .mock
        .requests("POST", &format!("/v1/customers/{}", s.customer));
    assert_eq!(
        defaults
            .last()
            .unwrap()
            .field("invoice_settings[default_payment_method]"),
        Some("pm_card_2")
    );
    // Stripe then reports the old card detached: it is not the card on file.
    let (b, h) = signed(
        "evt_det_old",
        "payment_method.detached",
        t0 + 20,
        json!({ "id": "pm_card_1", "object": "payment_method", "customer": null }),
        Some(json!({ "customer": s.customer })),
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");
    // Still one subscription.
    assert_eq!(s.mock.subscription_ids().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_older_checkout_delivered_late_does_not_replace_the_newer_card(pool: PgPool) {
    let s = started(pool).await;
    let t0 = Utc::now().timestamp() - 100;
    // The owner went through Checkout twice; Stripe delivers the second
    // completion first.
    complete_with(&s, "evt_card2", t0 + 10, "seti_2", "pm_card_2")
        .await
        .expect(StatusCode::OK);
    let sets_before = s
        .mock
        .requests("POST", &format!("/v1/customers/{}", s.customer))
        .len();
    complete_with(&s, "evt_card1", t0, "seti_1", "pm_card_1")
        .await
        .expect(StatusCode::OK);

    // No default-payment-method call for the stale event: Stripe's default
    // and ours both stay card 2, and card 1 is detached.
    assert_eq!(
        s.mock
            .requests("POST", &format!("/v1/customers/{}", s.customer))
            .len(),
        sets_before
    );
    assert_eq!(
        s.mock.customer(&s.customer).unwrap()["invoice_settings"]["default_payment_method"],
        "pm_card_2"
    );
    let pm: String =
        sqlx::query_scalar("SELECT stripe_payment_method_id FROM subscriptions WHERE org_id = $1")
            .bind(s.org)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(pm, "pm_card_2");
    assert_eq!(s.mock.detached(), ["pm_card_1"]);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");
    let added = audit_actions(&s.pool, s.org)
        .await
        .into_iter()
        .filter(|a| a == "billing.card.added")
        .count();
    assert_eq!(added, 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_canceled_subscription_stops_billing_until_a_new_card(pool: PgPool) {
    let s = started(pool).await;
    let t0 = Utc::now().timestamp() - 100;
    complete(&s, "evt_done", t0).await.expect(StatusCode::OK);
    let first = current_subscription(&s).await;
    // Canceled in Stripe (the dashboard, or dunning), then reported.
    s.mock.set_subscription_status(&first, "canceled");
    let (b, h) = signed(
        "evt_del",
        "customer.subscription.deleted",
        t0 + 10,
        json!({ "id": first, "object": "subscription", "customer": s.customer, "status": "canceled" }),
        None,
    );
    deliver(&s.h, b, &h).await.expect(StatusCode::OK);
    let view = billing_view(&s).await;
    assert_eq!(view["subscriptionStatus"], "canceled");
    assert_eq!(view["billingStopped"], true);
    assert_eq!(
        view["cardStatus"], "active",
        "the card itself is still fine"
    );

    // Sync does not quietly subscribe the org again.
    let report = billing::sync(&s.h.db, &s.mock.client()).await.unwrap();
    assert!(report.subscriptions_created.is_empty(), "{report:?}");
    assert_eq!(s.mock.subscription_ids(), std::slice::from_ref(&first));

    // The owner puts a card on file again: billing resumes, on a new
    // subscription.
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&s.owner_session)
        .send(&s.h.router)
        .await
        .expect(StatusCode::OK);
    complete_with(&s, "evt_again", t0 + 20, "seti_2", "pm_card_2")
        .await
        .expect(StatusCode::OK);
    let view = billing_view(&s).await;
    assert_eq!(view["billingStopped"], false);
    assert_eq!(view["subscriptionStatus"], "active");
    let second = current_subscription(&s).await;
    assert_ne!(second, first);
    assert_eq!(s.mock.subscription_ids().len(), 2);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn stripe_objects_left_by_an_interrupted_attempt_are_adopted(pool: PgPool) {
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    price_a_meter(&pool).await;
    billing::sync(&h.db, &mock.client()).await.unwrap();
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    let c = mock.client();
    // A customer created for the org whose id was never recorded.
    let orphan = c
        .create_customer(
            &CreateCustomer {
                name: Some("acme".into()),
                metadata: [("org_id".to_owned(), org.to_string())].into(),
                ..Default::default()
            },
            &IdempotencyKey::random(),
        )
        .await
        .unwrap();
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        mock.requests("POST", "/v1/customers").len(),
        1,
        "no second customer"
    );
    assert_eq!(
        mock.requests("POST", "/v1/checkout/sessions")[0].field("customer"),
        Some(orphan.id.as_str())
    );

    // And a subscription for it, likewise never recorded.
    let price: String = sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices")
        .fetch_one(&pool)
        .await
        .unwrap();
    let orphan_sub = c
        .create_subscription(
            &CreateSubscription {
                customer: orphan.id.clone(),
                prices: vec![price],
                billing_cycle_anchor: None,
                backdate_start_date: None,
                metadata: [("org_id".to_owned(), org.to_string())].into(),
            },
            &IdempotencyKey::random(),
        )
        .await
        .unwrap();
    let s = Setup {
        h,
        mock,
        pool,
        org,
        owner_session: owner.session,
        customer: orphan.id,
    };
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    assert_eq!(current_subscription(&s).await, orphan_sub.id);
    assert_eq!(s.mock.requests("POST", "/v1/subscriptions").len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn concurrent_setups_finish_on_a_two_connection_pool(pool: PgPool) {
    // More requests than connections, several for one org: each holds at
    // most one connection at a time and none across a Stripe call, so all
    // finish, and each org gets exactly one customer.
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let mut owners = Vec::new();
    for slug in ["acme", "beta", "gamma"] {
        let owner = onboard(&h, &format!("owner@{slug}.test")).await;
        org_with_owner(&h, slug, &owner).await;
        owners.push((slug, owner.session));
    }
    let small = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let small = harness_on(small, &mock);
    // Settle the tenant-role probe first, as a server does at boot
    // (`verify_tenant_isolation`): `Db::begin` asks it once, lazily.
    small
        .db
        .begin(OrgId::new())
        .await
        .unwrap()
        .rollback()
        .await
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for round in 0..3 {
        for (slug, session) in &owners {
            let router = small.router.clone();
            let (slug, session) = (slug.to_string(), session.clone());
            tasks.spawn(async move {
                let r = Call::post(format!("/api/orgs/{slug}/billing/setup"))
                    .with_session(&session)
                    .send(&router)
                    .await;
                (round, r.status, r.text)
            });
        }
    }
    let results = tokio::time::timeout(std::time::Duration::from_secs(60), tasks.join_all())
        .await
        .expect("concurrent setups deadlocked");
    assert_eq!(results.len(), 9);
    for (round, status, text) in results {
        assert_eq!(status, StatusCode::OK, "round {round}: {text}");
    }
    assert_eq!(mock.requests("POST", "/v1/customers").len(), 3);
    assert_eq!(mock.requests("POST", "/v1/checkout/sessions").len(), 9);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_card_with_nothing_priced_waits_for_sync(pool: PgPool) {
    // No meter is priced in Stripe yet: the card goes on file, no subscription.
    let mock = MockStripe::start().await;
    let h = harness(pool.clone(), Some(&mock)).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    Call::post("/api/orgs/acme/billing/setup")
        .with_session(&owner.session)
        .send(&h.router)
        .await
        .expect(StatusCode::OK);
    let s = Setup {
        h,
        mock,
        pool: pool.clone(),
        org,
        owner_session: owner.session,
        customer: "cus_mock1".into(),
    };
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let view = billing_view(&s).await;
    assert_eq!(view["cardStatus"], "active");
    assert_eq!(view["subscriptionStatus"], Value::Null);
    assert!(s.mock.requests("POST", "/v1/subscriptions").is_empty());

    // Once the price book is synced, sync subscribes the org.
    price_a_meter(&pool).await;
    let report = billing::sync(&s.h.db, &s.mock.client()).await.unwrap();
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(report.subscriptions_created.len(), 1);
    let sub = &s.mock.requests("POST", "/v1/subscriptions")[0];
    assert_eq!(sub.field("proration_behavior"), Some("none"));
    assert_eq!(
        sub.field("billing_cycle_anchor"),
        Some(next_first(&pool).await.to_string().as_str())
    );
    assert_eq!(billing_view(&s).await["subscriptionStatus"], "active");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stripe_failure_while_handling_is_retried(pool: PgPool) {
    let s = started(pool).await;
    s.mock.fail("/v1/setup_intents", 500);
    let now = Utc::now().timestamp();
    let r = complete(&s, "evt_done", now).await;
    r.expect(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!r.text.contains("mock"), "{}", r.text);
    assert!(
        ledger(&s.pool).await.is_empty(),
        "a failed event was recorded"
    );

    // Stripe retries the same event; this time it goes through.
    s.mock.clear_failures();
    complete(&s, "evt_done", now).await.expect(StatusCode::OK);
    assert_eq!(billing_view(&s).await["cardStatus"], "active");
    assert_eq!(ledger(&s.pool).await, ["evt_done"]);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_cycle_invoice_is_held_as_a_draft_through_the_webhook(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let sub = current_subscription(&s).await;
    let invoice = s
        .mock
        .add_invoice("in_cycle", &s.customer, &sub, next_first(&s.pool).await);
    deliver_event(
        &s,
        "evt_inv",
        "invoice.created",
        Utc::now().timestamp(),
        invoice,
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(s.mock.invoice("in_cycle").unwrap()["auto_advance"], false);
    assert_eq!(
        audit_actions(&s.pool, s.org)
            .await
            .last()
            .map(String::as_str),
        Some("billing.invoice.held")
    );
    assert!(billing::HANDLED_EVENT_TYPES.contains(&"invoice.created"));
}

// ------------------------------------------------- meter error reports (#76)

/// A `sent` outbox row of the org, as the shipper leaves one Stripe accepted.
async fn sent_row(s: &Setup, identifier: &str, value: i64) {
    sqlx::query(
        "INSERT INTO stripe_meter_outbox \
           (org_id, identifier, event_name, stripe_customer_id, value, bucket_start, \
            status, attempts, finished_at) \
         VALUES ($1, $2, 'otto_flags__evaluations', $3, $4, \
                 date_trunc('hour', now() - interval '2 hours'), 'sent', 1, now())",
    )
    .bind(s.org)
    .bind(identifier)
    .bind(&s.customer)
    .bind(value)
    .execute(&s.pool)
    .await
    .unwrap();
}

async fn row_state(s: &Setup, identifier: &str) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, last_error FROM stripe_meter_outbox WHERE identifier = $1")
        .bind(identifier)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

/// A meter error report in the shape of Stripe's `billing.meter_error_report`.
fn meter_error_report(samples: &[(&str, &str)], error_count: i64) -> Value {
    let sampled: Vec<Value> = samples
        .iter()
        .map(|(identifier, message)| {
            json!({ "error_message": message, "request": { "identifier": identifier } })
        })
        .collect();
    json!({
        "id": "mtr_err_1", "object": "billing.meter_error_report",
        "reason": { "error_count": error_count, "error_types": [
            { "code": "no_meter", "error_count": error_count, "sample_errors": sampled }
        ] },
    })
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_meter_error_report_marks_the_sent_rows_it_names_lost(pool: PgPool) {
    let s = started(pool).await;
    sent_row(&s, "agg:reported", 40).await;
    sent_row(&s, "agg:fine", 9).await;

    let report = meter_error_report(&[("agg:reported", "No meter found")], 1);
    deliver_event(
        &s,
        "evt_err",
        "billing.meter.error_report_triggered",
        Utc::now().timestamp(),
        report.clone(),
    )
    .await
    .expect(StatusCode::OK);

    let (status, error) = row_state(&s, "agg:reported").await;
    assert_eq!(status, "rejected");
    let error = error.unwrap();
    assert!(
        error.contains("no_meter") && error.contains("No meter found"),
        "{error}"
    );
    assert!(error.contains("mtr_err_1"), "{error}");
    assert_eq!(row_state(&s, "agg:fine").await.0, "sent");

    // It counts as lost revenue in `stripe outbox`.
    let summary = otto_billing::stripe_outbox::outbox_summary(&Db::from_pool(s.pool.clone()))
        .await
        .unwrap();
    assert_eq!(summary.lost(), 1);

    // A redelivery is a duplicate; a fresh report of the same row changes nothing.
    deliver_event(
        &s,
        "evt_err",
        "billing.meter.error_report_triggered",
        Utc::now().timestamp(),
        report.clone(),
    )
    .await
    .expect(StatusCode::OK);
    deliver_event(
        &s,
        "evt_err_2",
        "billing.meter.error_report_triggered",
        Utc::now().timestamp(),
        report,
    )
    .await
    .expect(StatusCode::OK);
    assert_eq!(row_state(&s, "agg:reported").await.0, "rejected");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_meter_error_report_naming_nothing_of_ours_is_acknowledged(pool: PgPool) {
    let s = started(pool).await;
    sent_row(&s, "agg:ours", 5).await;
    // An identifier that is not ours, and a report with no samples at all.
    for (id, report) in [
        ("evt_a", meter_error_report(&[("someone-elses-id", "x")], 1)),
        ("evt_b", meter_error_report(&[], 12)),
    ] {
        deliver_event(
            &s,
            id,
            "billing.meter.error_report_triggered",
            Utc::now().timestamp(),
            report,
        )
        .await
        .expect(StatusCode::OK);
    }
    assert_eq!(row_state(&s, "agg:ours").await.0, "sent");
    assert!(billing::HANDLED_EVENT_TYPES.contains(&"billing.meter.error_report_triggered"));
}

// ------------------------------------- canceling a deleted org's billing (#73)

use otto_core::orgs::OrgsExt;

async fn cancellation_row(s: &Setup) -> (String, i32, Option<String>) {
    sqlx::query_as(
        "SELECT status, attempts, last_error FROM stripe_cancellations WHERE org_id = $1",
    )
    .bind(s.org)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

fn cancel_calls(s: &Setup, sub: &str) -> Vec<otto_billing::billing::mock::Seen> {
    s.mock
        .requests("DELETE", &format!("/v1/subscriptions/{sub}"))
}

async fn make_due(s: &Setup) {
    sqlx::query("UPDATE stripe_cancellations SET next_attempt_at = now()")
        .execute(&s.pool)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn deleting_an_org_cancels_its_subscription_once_with_final_usage_invoiced(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let sub = current_subscription(&s).await;
    s.h.db.delete_org(s.org).await.unwrap();

    // Queued by the deletion itself; nothing has called Stripe yet.
    assert_eq!(cancellation_row(&s).await.0, "pending");
    assert!(cancel_calls(&s, &sub).is_empty());

    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!((report.claimed, report.canceled), (1, 1), "{report:?}");
    let calls = cancel_calls(&s, &sub);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("invoice_now"), Some("true"));
    assert_eq!(calls[0].field("prorate"), Some("false"));
    assert_eq!(s.mock.subscription(&sub).unwrap()["status"], "canceled");
    assert_eq!(s.mock.detached(), ["pm_card_1"]);
    assert_eq!(cancellation_row(&s).await.0, "done");

    // Nothing is left to do, and a second pass cancels nothing again.
    let again = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(again.claimed, 0);
    assert_eq!(cancel_calls(&s, &sub).len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stripe_outage_neither_blocks_the_deletion_nor_loses_the_cancellation(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let sub = current_subscription(&s).await;
    s.mock.fail("/v1/subscriptions", 500);

    // The deletion does not touch Stripe at all.
    s.h.db.delete_org(s.org).await.unwrap();
    assert!(s.h.db.get_active_org(s.org).await.unwrap().is_none());

    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(report.retrying, 1, "{report:?}");
    let (status, attempts, error) = cancellation_row(&s).await;
    assert_eq!((status.as_str(), attempts), ("pending", 1));
    assert!(error.is_some());
    // Backed off: not due again at once.
    assert_eq!(
        billing::cancel::run_pass(&s.h.db, &s.mock.client())
            .await
            .unwrap()
            .claimed,
        0
    );

    s.mock.clear_failures();
    make_due(&s).await;
    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(report.canceled, 1, "{report:?}");
    assert_eq!(s.mock.subscription(&sub).unwrap()["status"], "canceled");
    assert_eq!(cancellation_row(&s).await.0, "done");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_cancellation_waits_for_the_orgs_queued_meter_events_to_ship(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let sub = current_subscription(&s).await;
    sent_row(&s, "agg:waiting", 7).await;
    sqlx::query("UPDATE stripe_meter_outbox SET status = 'pending', finished_at = NULL")
        .execute(&s.pool)
        .await
        .unwrap();
    s.h.db.delete_org(s.org).await.unwrap();

    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(report.claimed, 0, "canceled before the usage shipped");
    assert!(cancel_calls(&s, &sub).is_empty());

    sqlx::query("UPDATE stripe_meter_outbox SET status = 'sent', finished_at = now()")
        .execute(&s.pool)
        .await
        .unwrap();
    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(report.canceled, 1, "{report:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_subscription_already_canceled_in_stripe_is_done_without_a_call(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    let sub = current_subscription(&s).await;
    s.mock.set_subscription_status(&sub, "canceled");
    s.h.db.delete_org(s.org).await.unwrap();

    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!((report.canceled, report.already_gone), (0, 1), "{report:?}");
    assert!(cancel_calls(&s, &sub).is_empty());
    assert_eq!(cancellation_row(&s).await.0, "done");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_org_without_a_subscription_queues_nothing(pool: PgPool) {
    let s = started(pool).await;
    // Setup started (a customer) but no card, so no subscription.
    s.h.db.delete_org(s.org).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM stripe_cancellations")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refusal_that_will_not_change_is_kept_failed_for_an_operator(pool: PgPool) {
    let s = started(pool).await;
    complete(&s, "evt_done", Utc::now().timestamp())
        .await
        .expect(StatusCode::OK);
    s.mock.fail("/v1/subscriptions", 400);
    s.h.db.delete_org(s.org).await.unwrap();
    let report = billing::cancel::run_pass(&s.h.db, &s.mock.client())
        .await
        .unwrap();
    assert_eq!(report.failed, 1, "{report:?}");
    let (status, _, error) = cancellation_row(&s).await;
    assert_eq!(status, "failed");
    assert!(error.is_some());
}
