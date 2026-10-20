//! Client tests against a local mock Stripe (axum on 127.0.0.1:0). No network.
//!
//! The mock records every request and answers from a queue of canned
//! responses, so each test asserts exactly what went over the wire.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use chrono::{TimeZone, Utc};
use serde_json::{json, Value};

use super::*;

const KEY: &str = "sk_test_51SuperSecretKeyValue";

#[derive(Debug, Clone)]
struct Seen {
    method: Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
    body: String,
}

impl Seen {
    fn form(&self) -> Vec<(String, String)> {
        serde_urlencoded::from_str(&self.body).expect("form body")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .map(|v| v.to_str().expect("ascii header"))
    }
}

#[derive(Default)]
struct MockState {
    seen: Mutex<Vec<Seen>>,
    replies: Mutex<VecDeque<(StatusCode, HeaderMap, Vec<u8>)>>,
}

struct Mock {
    base: String,
    state: Arc<MockState>,
}

impl Mock {
    async fn start() -> Self {
        let state = Arc::new(MockState::default());
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base: format!("http://{addr}"),
            state,
        }
    }

    fn reply(&self, status: u16, body: Value) -> &Self {
        self.reply_raw(status, body.to_string().into_bytes())
    }

    fn reply_raw(&self, status: u16, body: Vec<u8>) -> &Self {
        let mut h = HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        self.state.replies.lock().unwrap().push_back((
            StatusCode::from_u16(status).unwrap(),
            h,
            body,
        ));
        self
    }

    fn client(&self) -> Client {
        Client::with_base_url(SecretKey::new(KEY).unwrap(), &self.base).unwrap()
    }

    fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    fn only(&self) -> Seen {
        let seen = self.seen();
        assert_eq!(seen.len(), 1, "expected exactly one request: {seen:?}");
        seen.into_iter().next().unwrap()
    }
}

async fn handle(
    State(state): State<Arc<MockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.seen.lock().unwrap().push(Seen {
        method,
        path: uri.path().to_owned(),
        query: uri.query().map(str::to_owned),
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    state.replies.lock().unwrap().pop_front().unwrap_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        HeaderMap::new(),
        b"no canned reply".to_vec(),
    ))
}

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn idem(k: &str) -> IdempotencyKey {
    IdempotencyKey::new(k).unwrap()
}

/// The headers every request carries.
fn assert_common_headers(s: &Seen) {
    assert_eq!(s.header("authorization"), Some(&*format!("Bearer {KEY}")));
    assert_eq!(s.header("stripe-version"), Some(STRIPE_VERSION));
}

fn assert_post(s: &Seen, path: &str, key: &str) {
    assert_eq!(s.method, Method::POST);
    assert_eq!(s.path, path);
    assert_eq!(s.query, None);
    assert_common_headers(s);
    assert_eq!(s.header("idempotency-key"), Some(key));
    assert_eq!(
        s.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
}

fn price_json(id: &str) -> Value {
    json!({
        "id": id, "object": "price", "currency": "usd", "product": "prod_1",
        "lookup_key": null, "tiers_mode": "graduated",
        "recurring": {"interval": "month", "usage_type": "metered", "meter": "mtr_1"},
        "metadata": {}
    })
}

// ------------------------------------------------------------- requests

#[tokio::test]
async fn create_customer_encoding_and_headers() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "cus_1", "object": "customer", "email": "a@b.c", "name": "Acme",
               "metadata": {"org_id": "o1"}, "invoice_settings": {"default_payment_method": null}}),
    );
    let c = m
        .client()
        .create_customer(
            &CreateCustomer {
                email: Some("a@b.c".into()),
                name: Some("Acme & Co".into()),
                metadata: [("org_id".to_owned(), "o1".to_owned())].into(),
            },
            &idem("cust-o1"),
        )
        .await
        .unwrap();
    assert_eq!(c.id, "cus_1");
    assert_eq!(c.metadata["org_id"], "o1");
    let s = m.only();
    assert_post(&s, "/v1/customers", "cust-o1");
    assert_eq!(
        s.form(),
        pairs(&[
            ("email", "a@b.c"),
            ("name", "Acme & Co"),
            ("metadata[org_id]", "o1")
        ])
    );
    // Brackets are percent-encoded on the wire.
    assert!(s.body.contains("metadata%5Borg_id%5D=o1"), "{}", s.body);
}

#[tokio::test]
async fn setup_checkout_session_with_currency() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "cs_1", "object": "checkout.session", "url": "https://checkout.stripe.com/c/cs_1",
               "mode": "setup", "customer": "cus_1", "setup_intent": null, "status": "open",
               "metadata": {"org_id": "o1"}}),
    );
    let s = m
        .client()
        .create_setup_checkout_session(
            &CreateSetupCheckoutSession {
                customer: "cus_1".into(),
                payment_methods: SetupPaymentMethods::Currency("usd".into()),
                success_url: "https://console.example/billing?ok=1".into(),
                cancel_url: "https://console.example/billing".into(),
                org_id: "o1".into(),
            },
            &idem("k1"),
        )
        .await
        .unwrap();
    assert_eq!(s.url.as_deref(), Some("https://checkout.stripe.com/c/cs_1"));
    let r = m.only();
    assert_post(&r, "/v1/checkout/sessions", "k1");
    assert_eq!(
        r.form(),
        pairs(&[
            ("mode", "setup"),
            ("customer", "cus_1"),
            ("currency", "usd"),
            ("success_url", "https://console.example/billing?ok=1"),
            ("cancel_url", "https://console.example/billing"),
            ("metadata[org_id]", "o1"),
        ])
    );
}

#[tokio::test]
async fn setup_checkout_session_with_payment_method_types() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "cs_2", "url": null, "mode": "setup", "customer": "cus_1",
               "setup_intent": "seti_1", "status": "open"}),
    );
    m.client()
        .create_setup_checkout_session(
            &CreateSetupCheckoutSession {
                customer: "cus_1".into(),
                payment_methods: SetupPaymentMethods::Types(vec![
                    "card".into(),
                    "us_bank_account".into(),
                ]),
                success_url: "https://s".into(),
                cancel_url: "https://c".into(),
                org_id: "o2".into(),
            },
            &idem("k2"),
        )
        .await
        .unwrap();
    assert_eq!(
        m.only().form(),
        pairs(&[
            ("mode", "setup"),
            ("customer", "cus_1"),
            ("payment_method_types[0]", "card"),
            ("payment_method_types[1]", "us_bank_account"),
            ("success_url", "https://s"),
            ("cancel_url", "https://c"),
            ("metadata[org_id]", "o2"),
        ])
    );
}

#[tokio::test]
async fn empty_payment_method_types_is_refused_locally() {
    let m = Mock::start().await;
    let err = m
        .client()
        .create_setup_checkout_session(
            &CreateSetupCheckoutSession {
                customer: "cus_1".into(),
                payment_methods: SetupPaymentMethods::Types(vec![]),
                success_url: "https://s".into(),
                cancel_url: "https://c".into(),
                org_id: "o".into(),
            },
            &idem("k"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StripeError::InvalidRequest(_)));
    assert!(m.seen().is_empty());
}

#[tokio::test]
async fn retrieve_setup_intent_is_a_get_without_idempotency_key() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "seti_1", "object": "setup_intent", "status": "succeeded",
               "customer": "cus_1", "payment_method": "pm_1", "metadata": {}}),
    );
    let si = m.client().retrieve_setup_intent("seti_1").await.unwrap();
    assert_eq!(si.payment_method.as_deref(), Some("pm_1"));
    assert_eq!(si.status, "succeeded");
    let s = m.only();
    assert_eq!(s.method, Method::GET);
    assert_eq!(s.path, "/v1/setup_intents/seti_1");
    assert_common_headers(&s);
    assert_eq!(s.header("idempotency-key"), None);
    assert!(s.body.is_empty());
}

#[tokio::test]
async fn ids_are_checked_before_they_reach_a_path() {
    let m = Mock::start().await;
    let c = m.client();
    for bad in ["../customers", "seti_1?expand[]=x", "seti 1", ""] {
        assert!(matches!(
            c.retrieve_setup_intent(bad).await,
            Err(StripeError::InvalidRequest(_))
        ));
    }
    assert!(c
        .set_default_payment_method("cus_1/../x", "pm_1", &idem("k"))
        .await
        .is_err());
    assert!(m.seen().is_empty());
}

#[tokio::test]
async fn set_default_payment_method_encoding() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "cus_1", "email": null, "name": null,
               "invoice_settings": {"default_payment_method": "pm_9"}}),
    );
    let c = m
        .client()
        .set_default_payment_method("cus_1", "pm_9", &idem("dpm-1"))
        .await
        .unwrap();
    assert_eq!(
        c.invoice_settings
            .unwrap()
            .default_payment_method
            .as_deref(),
        Some("pm_9")
    );
    let s = m.only();
    assert_post(&s, "/v1/customers/cus_1", "dpm-1");
    assert_eq!(
        s.form(),
        pairs(&[("invoice_settings[default_payment_method]", "pm_9")])
    );
}

#[tokio::test]
async fn create_meter_encoding() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "mtr_1", "object": "billing.meter", "event_name": "otto_factory__jobs_completed",
               "display_name": "Jobs completed", "status": "active"}),
    );
    let event_name = meter_event_name("otto-factory", "jobs_completed").unwrap();
    let meter = m
        .client()
        .create_meter(
            &CreateMeter {
                display_name: "Jobs completed".into(),
                event_name: event_name.clone(),
            },
            &idem("meter-otto-factory/jobs_completed"),
        )
        .await
        .unwrap();
    assert_eq!(meter.id, "mtr_1");
    let s = m.only();
    assert_post(
        &s,
        "/v1/billing/meters",
        "meter-otto-factory/jobs_completed",
    );
    assert_eq!(
        s.form(),
        pairs(&[
            ("display_name", "Jobs completed"),
            ("event_name", "otto_factory__jobs_completed"),
            ("default_aggregation[formula]", "sum"),
            ("customer_mapping[type]", "by_id"),
            ("customer_mapping[event_payload_key]", "stripe_customer_id"),
            ("value_settings[event_payload_key]", "value"),
        ])
    );
}

#[tokio::test]
async fn create_metered_price_encodes_nested_tiers() {
    let m = Mock::start().await;
    m.reply(200, price_json("price_1"));
    let price = m
        .client()
        .create_metered_price(
            &CreateMeteredPrice {
                currency: "usd".into(),
                product: PriceProduct::New {
                    name: "otto-factory jobs".into(),
                },
                meter: "mtr_1".into(),
                tiers: vec![
                    PriceTier {
                        up_to: TierUpTo::Units(1000),
                        unit_amount_ucents: 0,
                    },
                    PriceTier {
                        up_to: TierUpTo::Units(100_000),
                        unit_amount_ucents: 1_500_000,
                    },
                    PriceTier {
                        up_to: TierUpTo::Inf,
                        unit_amount_ucents: 1,
                    },
                ],
                lookup_key: Some("otto-factory/jobs_completed@2026-11".into()),
                nickname: None,
                metadata: [(
                    "meter_key".to_owned(),
                    "otto-factory/jobs_completed".to_owned(),
                )]
                .into(),
            },
            &idem("price-1"),
        )
        .await
        .unwrap();
    assert_eq!(price.id, "price_1");
    assert_eq!(price.recurring.unwrap().meter.as_deref(), Some("mtr_1"));
    let s = m.only();
    assert_post(&s, "/v1/prices", "price-1");
    assert_eq!(
        s.form(),
        pairs(&[
            ("currency", "usd"),
            ("product_data[name]", "otto-factory jobs"),
            ("billing_scheme", "tiered"),
            ("tiers_mode", "graduated"),
            ("recurring[interval]", "month"),
            ("recurring[usage_type]", "metered"),
            ("recurring[meter]", "mtr_1"),
            ("tiers[0][up_to]", "1000"),
            ("tiers[0][unit_amount_decimal]", "0"),
            ("tiers[1][up_to]", "100000"),
            ("tiers[1][unit_amount_decimal]", "1.5"),
            ("tiers[2][up_to]", "inf"),
            ("tiers[2][unit_amount_decimal]", "0.000001"),
            ("lookup_key", "otto-factory/jobs_completed@2026-11"),
            ("metadata[meter_key]", "otto-factory/jobs_completed"),
        ])
    );
    assert!(
        s.body.contains("tiers%5B1%5D%5Bunit_amount_decimal%5D=1.5"),
        "{}",
        s.body
    );
}

#[tokio::test]
async fn create_metered_price_with_existing_product() {
    let m = Mock::start().await;
    m.reply(200, price_json("price_2"));
    m.client()
        .create_metered_price(
            &CreateMeteredPrice {
                currency: "usd".into(),
                product: PriceProduct::Id("prod_1".into()),
                meter: "mtr_1".into(),
                tiers: vec![PriceTier {
                    up_to: TierUpTo::Inf,
                    unit_amount_ucents: 250_000_000,
                }],
                lookup_key: None,
                nickname: Some("flat".into()),
                metadata: Default::default(),
            },
            &idem("price-2"),
        )
        .await
        .unwrap();
    let form = m.only().form();
    assert_eq!(form[1], ("product".to_owned(), "prod_1".to_owned()));
    assert!(form.contains(&("tiers[0][unit_amount_decimal]".into(), "250".into())));
    assert!(form.contains(&("nickname".into(), "flat".into())));
}

#[tokio::test]
async fn bad_tiers_are_refused_locally() {
    let m = Mock::start().await;
    let err = m
        .client()
        .create_metered_price(
            &CreateMeteredPrice {
                currency: "usd".into(),
                product: PriceProduct::Id("prod_1".into()),
                meter: "mtr_1".into(),
                tiers: vec![PriceTier {
                    up_to: TierUpTo::Units(10),
                    unit_amount_ucents: 1,
                }],
                lookup_key: None,
                nickname: None,
                metadata: Default::default(),
            },
            &idem("k"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StripeError::InvalidRequest(_)));
    assert!(m.seen().is_empty());
}

#[tokio::test]
async fn subscription_create_add_and_change_price() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"id": "sub_1", "object": "subscription", "customer": "cus_1", "status": "active",
               "items": {"object": "list", "has_more": false,
                         "data": [{"id": "si_1", "price": price_json("price_a"), "subscription": "sub_1"}]},
               "metadata": {"org_id": "o1"}}),
    )
    .reply(
        200,
        json!({"id": "si_2", "price": price_json("price_c"), "subscription": "sub_1"}),
    )
    .reply(
        200,
        json!({"id": "si_1", "price": price_json("price_d"), "subscription": "sub_1"}),
    );
    let c = m.client();
    let anchor = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    let sub = c
        .create_subscription(
            &CreateSubscription {
                customer: "cus_1".into(),
                prices: vec!["price_a".into(), "price_b".into()],
                billing_cycle_anchor: Some(anchor),
                metadata: [("org_id".to_owned(), "o1".to_owned())].into(),
            },
            &idem("sub-o1"),
        )
        .await
        .unwrap();
    assert_eq!(sub.items.data[0].price.id, "price_a");
    let added = c
        .add_subscription_item("sub_1", "price_c", &idem("add-c"))
        .await
        .unwrap();
    assert_eq!(added.id, "si_2");
    let changed = c
        .change_subscription_item_price("si_1", "price_d", &idem("chg-d"))
        .await
        .unwrap();
    assert_eq!(changed.price.id, "price_d");

    let seen = m.seen();
    assert_eq!(seen.len(), 3);
    assert_post(&seen[0], "/v1/subscriptions", "sub-o1");
    assert_eq!(
        seen[0].form(),
        pairs(&[
            ("customer", "cus_1"),
            ("items[0][price]", "price_a"),
            ("items[1][price]", "price_b"),
            ("billing_cycle_anchor", "1793491200"),
            ("proration_behavior", "none"),
            ("metadata[org_id]", "o1"),
        ])
    );
    assert_post(&seen[1], "/v1/subscription_items", "add-c");
    assert_eq!(
        seen[1].form(),
        pairs(&[
            ("subscription", "sub_1"),
            ("price", "price_c"),
            ("proration_behavior", "none"),
        ])
    );
    assert_post(&seen[2], "/v1/subscription_items/si_1", "chg-d");
    assert_eq!(
        seen[2].form(),
        pairs(&[("price", "price_d"), ("proration_behavior", "none")])
    );
}

#[tokio::test]
async fn meter_event_encoding() {
    let m = Mock::start().await;
    m.reply(
        200,
        json!({"object": "billing.meter_event", "event_name": "otto_factory__jobs_completed",
               "identifier": "otto-factory:6f1c0f0e", "timestamp": 1793491200,
               "payload": {"stripe_customer_id": "cus_1", "value": "42"}, "livemode": false}),
    );
    let rec = m
        .client()
        .send_meter_event(
            &MeterEvent {
                event_name: "otto_factory__jobs_completed".into(),
                stripe_customer_id: "cus_1".into(),
                value: 42,
                identifier: "otto-factory:6f1c0f0e".into(),
                timestamp: Utc.timestamp_opt(1_793_491_200, 0).unwrap(),
            },
            &idem("otto-factory:6f1c0f0e"),
        )
        .await
        .unwrap();
    assert_eq!(rec.identifier, "otto-factory:6f1c0f0e");
    let s = m.only();
    assert_post(&s, "/v1/billing/meter_events", "otto-factory:6f1c0f0e");
    assert_eq!(
        s.form(),
        pairs(&[
            ("event_name", "otto_factory__jobs_completed"),
            ("payload[stripe_customer_id]", "cus_1"),
            ("payload[value]", "42"),
            ("identifier", "otto-factory:6f1c0f0e"),
            ("timestamp", "1793491200"),
        ])
    );
}

#[tokio::test]
async fn meter_event_bounds_are_checked_locally() {
    let m = Mock::start().await;
    let ev = MeterEvent {
        event_name: "e".into(),
        stripe_customer_id: "cus_1".into(),
        value: -1,
        identifier: "id".into(),
        timestamp: Utc::now(),
    };
    let c = m.client();
    assert!(c.send_meter_event(&ev, &idem("k")).await.is_err());
    let ev = MeterEvent {
        value: 1,
        identifier: "x".repeat(101),
        ..ev
    };
    assert!(c.send_meter_event(&ev, &idem("k")).await.is_err());
    assert!(m.seen().is_empty());
}

// ------------------------------------------------------------- idempotency

#[tokio::test]
async fn every_post_carries_the_callers_idempotency_key() {
    let m = Mock::start().await;
    let body = json!({"id": "cus_1"});
    m.reply(200, body.clone())
        .reply(200, body.clone())
        .reply(200, body);
    let c = m.client();
    let params = CreateCustomer::default();
    let retry = idem("stable-key");
    c.create_customer(&params, &retry).await.unwrap();
    // A retry reuses the key, so Stripe replays rather than acting twice.
    c.create_customer(&params, &retry).await.unwrap();
    c.create_customer(&params, &IdempotencyKey::random())
        .await
        .unwrap();
    let keys: Vec<String> = m
        .seen()
        .iter()
        .map(|s| s.header("idempotency-key").unwrap().to_owned())
        .collect();
    assert_eq!(keys[0], "stable-key");
    assert_eq!(keys[1], "stable-key");
    assert_ne!(keys[2], "stable-key");
    assert!(uuid::Uuid::parse_str(&keys[2]).is_ok());
}

// ------------------------------------------------------------- errors

#[tokio::test]
async fn api_errors_map_to_typed_error() {
    let m = Mock::start().await;
    m.reply(
        402,
        json!({"error": {"type": "card_error", "code": "card_declined",
                         "message": "Your card was declined.", "param": "payment_method",
                         "decline_code": "generic_decline"}}),
    );
    let err = m
        .client()
        .set_default_payment_method("cus_1", "pm_1", &idem("k"))
        .await
        .unwrap_err();
    let api = err.api().expect("api error");
    assert_eq!(
        api,
        &ApiError {
            status: 402,
            kind: "card_error".into(),
            code: Some("card_declined".into()),
            message: "Your card was declined.".into(),
            param: Some("payment_method".into()),
        }
    );
    assert_eq!(
        err.to_string(),
        "Stripe API error (HTTP 402, card_error, card_declined): Your card was declined."
    );
}

#[tokio::test]
async fn error_without_code() {
    let m = Mock::start().await;
    m.reply(
        404,
        json!({"error": {"type": "invalid_request_error", "message": "No such setupintent: 'seti_x'"}}),
    );
    let err = m
        .client()
        .retrieve_setup_intent("seti_x")
        .await
        .unwrap_err();
    let api = err.api().unwrap();
    assert_eq!(api.status, 404);
    assert_eq!(api.code, None);
    assert_eq!(api.kind, "invalid_request_error");
}

#[tokio::test]
async fn errors_never_contain_the_key() {
    let m = Mock::start().await;
    // A hostile or buggy upstream echoing the key in every field.
    m.reply(
        401,
        json!({"error": {"type": format!("t {KEY}"), "code": KEY, "param": KEY,
                         "message": format!("Invalid API Key provided: {KEY}")}}),
    );
    let err = m
        .client()
        .retrieve_setup_intent("seti_1")
        .await
        .unwrap_err();
    let api = err.api().unwrap();
    assert_eq!(api.status, 401);
    assert_eq!(api.message, "Invalid API Key provided: [redacted]");
    for s in [format!("{err}"), format!("{err:?}"), format!("{err:#?}")] {
        assert!(!s.contains(KEY), "{s}");
        assert!(!s.contains("SuperSecret"), "{s}");
    }
}

#[tokio::test]
async fn unparseable_error_body() {
    let m = Mock::start().await;
    m.reply_raw(502, format!("<html>bad gateway {KEY}</html>").into_bytes());
    let err = m
        .client()
        .retrieve_setup_intent("seti_1")
        .await
        .unwrap_err();
    let api = err.api().unwrap();
    assert_eq!(api.status, 502);
    assert_eq!(api.kind, "invalid_response");
    assert!(!format!("{err:?}").contains(KEY));
}

#[tokio::test]
async fn unexpected_success_shape_is_a_decode_error() {
    let m = Mock::start().await;
    m.reply(200, json!({"object": "customer"}));
    let err = m
        .client()
        .create_customer(&CreateCustomer::default(), &idem("k"))
        .await
        .unwrap_err();
    assert!(matches!(err, StripeError::Decode(_)), "{err:?}");
}

#[tokio::test]
async fn oversized_response_is_refused() {
    let m = Mock::start().await;
    let big = format!(
        r#"{{"id":"cus_1","pad":"{}"}}"#,
        "x".repeat(MAX_RESPONSE_BYTES)
    );
    m.reply_raw(200, big.into_bytes());
    let err = m
        .client()
        .create_customer(&CreateCustomer::default(), &idem("k"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, StripeError::Decode(msg) if msg.contains("exceeds")),
        "{err:?}"
    );
}

#[tokio::test]
async fn transport_error_does_not_contain_the_key() {
    // Bind and drop, so nothing is listening on the port.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let c = Client::with_base_url(SecretKey::new(KEY).unwrap(), &format!("http://{addr}")).unwrap();
    let err = c.retrieve_setup_intent("seti_1").await.unwrap_err();
    assert!(matches!(err, StripeError::Transport(_)), "{err:?}");
    assert!(!format!("{err} {err:?}").contains(KEY));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let m = Mock::start().await;
    let mut h = HeaderMap::new();
    h.insert("location", "http://127.0.0.1:1/elsewhere".parse().unwrap());
    m.state
        .replies
        .lock()
        .unwrap()
        .push_back((StatusCode::FOUND, h, Vec::new()));
    let err = m
        .client()
        .retrieve_setup_intent("seti_1")
        .await
        .unwrap_err();
    assert_eq!(err.api().map(|a| a.status), Some(302));
    assert_eq!(m.seen().len(), 1);
}

#[test]
fn client_debug_does_not_contain_the_key() {
    let c = Client::with_base_url(SecretKey::new(KEY).unwrap(), "http://127.0.0.1:1").unwrap();
    assert!(!format!("{c:?}").contains(KEY));
}

#[tokio::test]
async fn raw_meter_keys_are_refused_as_event_names() {
    let m = Mock::start().await;
    let c = m.client();
    for bad in [
        "otto-factory/jobs_completed",
        "",
        "Jobs",
        &"a".repeat(MAX_EVENT_NAME_LEN + 1),
    ] {
        let err = c
            .create_meter(
                &CreateMeter {
                    display_name: "x".into(),
                    event_name: bad.to_owned(),
                },
                &idem("k"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, StripeError::InvalidRequest(_)),
            "{bad}: {err:?}"
        );
        let err = c
            .send_meter_event(
                &MeterEvent {
                    event_name: bad.to_owned(),
                    stripe_customer_id: "cus_1".into(),
                    value: 1,
                    identifier: "id".into(),
                    timestamp: Utc::now(),
                },
                &idem("k"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, StripeError::InvalidRequest(_)),
            "{bad}: {err:?}"
        );
    }
    assert!(m.seen().is_empty());
}
