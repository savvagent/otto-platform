//! A local, stateful stand-in for the slice of Stripe that [`super`] calls,
//! for tests. Never a network call: it listens on `127.0.0.1:0`.
//!
//! Like the client's own wire tests (`stripe::tests`), it records every request
//! so a test can assert exactly what was sent. Unlike them it keeps state, so a
//! whole flow (customer, checkout, subscription, items) can run against it:
//! customers, meters, prices, subscriptions and their items are created and
//! returned in Stripe's shapes, and setup intents are seeded by the test
//! ([`MockStripe::add_setup_intent`]), standing in for the card a person types
//! into Checkout.
//!
//! It honours `Idempotency-Key` the way Stripe does: a POST repeating a key
//! gets the first response again and changes nothing. It enforces the two
//! subscription rules sync depends on: at most [`super::MAX_SUBSCRIPTION_ITEMS`]
//! items, and no price twice on one subscription.
//!
//! Compiled for this crate's tests and, through the `test-support` feature, for
//! other crates' tests. Never in a production build.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use serde_json::{json, Value};

use super::MAX_SUBSCRIPTION_ITEMS;
use crate::stripe::{Client, SecretKey};

/// The key the mock's client authenticates with.
pub const MOCK_SECRET_KEY: &str = "sk_test_mock_stripe_key";

/// One request the mock received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub idempotency_key: Option<String>,
    pub authorization: Option<String>,
    /// The decoded form body, in order.
    pub form: Vec<(String, String)>,
}

impl Seen {
    /// The first value of a form field.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every value whose field name starts with `prefix`, in order.
    pub fn fields_starting(&self, prefix: &str) -> Vec<&str> {
        self.form
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Default)]
struct Inner {
    seen: Vec<Seen>,
    /// Idempotency key -> the response first given for it.
    replies: HashMap<String, (StatusCode, Value)>,
    next_id: u64,
    customers: BTreeMap<String, Value>,
    setup_intents: BTreeMap<String, Value>,
    meters: BTreeMap<String, Value>,
    prices: BTreeMap<String, Value>,
    /// Subscription id -> the subscription, without its items.
    subscriptions: BTreeMap<String, Value>,
    /// Item id -> (subscription id, price id).
    items: BTreeMap<String, (String, String)>,
    /// Path prefix -> the status every matching request fails with.
    failures: Vec<(String, u16)>,
}

impl Inner {
    fn id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}_mock{}", self.next_id)
    }

    fn item_json(&self, item: &str) -> Value {
        let (sub, price) = &self.items[item];
        json!({
            "id": item,
            "object": "subscription_item",
            "subscription": sub,
            "price": self.prices.get(price).cloned().unwrap_or(Value::Null),
        })
    }

    fn subscription_json(&self, sub: &str) -> Value {
        let mut s = self.subscriptions[sub].clone();
        let data: Vec<Value> = self
            .items
            .iter()
            .filter(|(_, (owner, _))| owner == sub)
            .map(|(id, _)| self.item_json(id))
            .collect();
        s["items"] = json!({ "object": "list", "data": data, "has_more": false });
        s
    }

    fn items_of(&self, sub: &str) -> Vec<String> {
        self.items
            .iter()
            .filter(|(_, (owner, _))| owner == sub)
            .map(|(_, (_, price))| price.clone())
            .collect()
    }
}

/// A running mock. Dropping it leaves the listener running until the test's
/// runtime shuts down, which is when the test ends.
#[derive(Clone)]
pub struct MockStripe {
    base_url: String,
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for MockStripe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockStripe")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Value) {
    (
        status,
        json!({ "error": { "type": "invalid_request_error", "message": message } }),
    )
}

fn metadata(form: &[(String, String)]) -> Value {
    let map: serde_json::Map<String, Value> = form
        .iter()
        .filter_map(|(k, v)| {
            let key = k.strip_prefix("metadata[")?.strip_suffix(']')?;
            Some((key.to_owned(), Value::String(v.clone())))
        })
        .collect();
    Value::Object(map)
}

impl MockStripe {
    /// Start listening on an ephemeral loopback port.
    pub async fn start() -> Self {
        let inner = Arc::new(Mutex::new(Inner::default()));
        let app = Router::new().fallback(handle).with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mock Stripe listener");
        let addr = listener.local_addr().expect("mock Stripe address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            inner,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// A client pointed at this mock.
    pub fn client(&self) -> Client {
        Client::with_base_url(
            SecretKey::new(MOCK_SECRET_KEY).expect("mock key"),
            &self.base_url,
        )
        .expect("mock client")
    }

    /// Every request so far, oldest first.
    pub fn seen(&self) -> Vec<Seen> {
        self.lock().seen.clone()
    }

    /// The requests with this method whose path is exactly `path`.
    pub fn requests(&self, method: &str, path: &str) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.method == method && s.path == path)
            .collect()
    }

    /// The POSTs whose path starts with `prefix`.
    pub fn posts_under(&self, prefix: &str) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.method == "POST" && s.path.starts_with(prefix))
            .collect()
    }

    /// Seed a setup intent, as Checkout would leave one behind.
    pub fn add_setup_intent(&self, id: &str, customer: &str, payment_method: &str, status: &str) {
        self.lock().setup_intents.insert(
            id.to_owned(),
            json!({
                "id": id, "object": "setup_intent", "status": status,
                "customer": customer, "payment_method": payment_method, "metadata": {},
            }),
        );
    }

    /// Every request whose path starts with `prefix` fails with `status`
    /// until [`Self::clear_failures`].
    pub fn fail(&self, prefix: &str, status: u16) {
        self.lock().failures.push((prefix.to_owned(), status));
    }

    pub fn clear_failures(&self) {
        self.lock().failures.clear();
    }

    /// A subscription as Stripe holds it, with its items.
    pub fn subscription(&self, id: &str) -> Option<Value> {
        let inner = self.lock();
        inner
            .subscriptions
            .contains_key(id)
            .then(|| inner.subscription_json(id))
    }

    /// Every subscription id, oldest first.
    pub fn subscription_ids(&self) -> Vec<String> {
        let inner = self.lock();
        let mut ids: Vec<(u64, String)> = inner
            .subscriptions
            .keys()
            .map(|k| {
                (
                    k.trim_start_matches("sub_mock").parse().unwrap_or(0),
                    k.clone(),
                )
            })
            .collect();
        ids.sort();
        ids.into_iter().map(|(_, k)| k).collect()
    }

    /// The price ids on a subscription.
    pub fn subscription_prices(&self, id: &str) -> Vec<String> {
        self.lock().items_of(id)
    }

    /// A customer as Stripe holds it.
    pub fn customer(&self, id: &str) -> Option<Value> {
        self.lock().customers.get(id).cloned()
    }

    /// A price as Stripe holds it.
    pub fn price(&self, id: &str) -> Option<Value> {
        self.lock().prices.get(id).cloned()
    }

    /// How many meters and prices exist.
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.meters.len(), inner.prices.len())
    }
}

async fn handle(
    State(inner): State<Arc<Mutex<Inner>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let form: Vec<(String, String)> = serde_urlencoded::from_bytes(&body).unwrap_or_default();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let seen = Seen {
        method: method.as_str().to_owned(),
        path: uri.path().to_owned(),
        idempotency_key: header("idempotency-key"),
        authorization: header("authorization"),
        form,
    };

    let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
    inner.seen.push(seen.clone());

    if let Some((_, status)) = inner
        .failures
        .iter()
        .find(|(prefix, _)| seen.path.starts_with(prefix.as_str()))
    {
        let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let (s, v) = error(status, "the mock was told to fail this path");
        return (s, axum::Json(v));
    }

    if let Some(key) = seen.idempotency_key.as_ref() {
        if let Some((s, v)) = inner.replies.get(key) {
            return (*s, axum::Json(v.clone()));
        }
    }
    let (status, value) = route(&mut inner, &seen);
    if let Some(key) = seen.idempotency_key {
        inner.replies.insert(key, (status, value.clone()));
    }
    (status, axum::Json(value))
}

fn route(inner: &mut Inner, req: &Seen) -> (StatusCode, Value) {
    let segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
    let f = |name: &str| req.field(name).map(str::to_owned);
    match (req.method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "customers"]) => {
            let id = inner.id("cus");
            let c = json!({
                "id": id, "object": "customer", "email": f("email"), "name": f("name"),
                "metadata": metadata(&req.form),
                "invoice_settings": { "default_payment_method": null },
            });
            inner.customers.insert(id, c.clone());
            (StatusCode::OK, c)
        }
        ("POST", ["v1", "customers", id]) => match inner.customers.get_mut(*id) {
            Some(c) => {
                if let Some(pm) = f("invoice_settings[default_payment_method]") {
                    c["invoice_settings"]["default_payment_method"] = json!(pm);
                }
                (StatusCode::OK, c.clone())
            }
            None => error(StatusCode::NOT_FOUND, "No such customer"),
        },
        ("POST", ["v1", "checkout", "sessions"]) => {
            if !f("customer").is_some_and(|c| inner.customers.contains_key(&c)) {
                return error(StatusCode::BAD_REQUEST, "No such customer");
            }
            let id = inner.id("cs");
            (
                StatusCode::OK,
                json!({
                    "id": id, "object": "checkout.session",
                    "url": format!("https://checkout.stripe.test/c/pay/{id}"),
                    "mode": f("mode"), "customer": f("customer"), "setup_intent": null,
                    "status": "open", "metadata": metadata(&req.form),
                }),
            )
        }
        ("GET", ["v1", "setup_intents", id]) => match inner.setup_intents.get(*id) {
            Some(si) => (StatusCode::OK, si.clone()),
            None => error(StatusCode::NOT_FOUND, "No such setupintent"),
        },
        ("POST", ["v1", "billing", "meters"]) => {
            let event_name = f("event_name").unwrap_or_default();
            if inner
                .meters
                .values()
                .any(|m| m["event_name"] == json!(event_name))
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "An active meter with this event_name already exists",
                );
            }
            let id = inner.id("mtr");
            let m = json!({
                "id": id, "object": "billing.meter", "event_name": event_name,
                "display_name": f("display_name"), "status": "active",
            });
            inner.meters.insert(id, m.clone());
            (StatusCode::OK, m)
        }
        ("POST", ["v1", "prices"]) => {
            let Some(meter) = f("recurring[meter]").filter(|m| inner.meters.contains_key(m)) else {
                return error(StatusCode::BAD_REQUEST, "No such meter");
            };
            let product = match f("product") {
                Some(p) => p,
                None => inner.id("prod"),
            };
            let id = inner.id("price");
            let tiers: Vec<Value> = (0..)
                .map_while(|i| {
                    let up_to = f(&format!("tiers[{i}][up_to]"))?;
                    let amount = f(&format!("tiers[{i}][unit_amount_decimal]"))?;
                    Some(json!({ "up_to": up_to, "unit_amount_decimal": amount }))
                })
                .collect();
            let p = json!({
                "id": id, "object": "price", "currency": f("currency"), "product": product,
                "lookup_key": f("lookup_key"), "nickname": f("nickname"),
                "tiers_mode": f("tiers_mode"), "tiers": tiers,
                "recurring": {
                    "interval": f("recurring[interval]"),
                    "usage_type": f("recurring[usage_type]"),
                    "meter": meter,
                },
                "metadata": metadata(&req.form),
            });
            inner.prices.insert(id, p.clone());
            (StatusCode::OK, p)
        }
        ("POST", ["v1", "subscriptions"]) => {
            let prices: Vec<String> = req
                .fields_starting("items[")
                .into_iter()
                .map(str::to_owned)
                .collect();
            if prices.len() > MAX_SUBSCRIPTION_ITEMS {
                return error(StatusCode::BAD_REQUEST, "too many subscription items");
            }
            let customer = f("customer").unwrap_or_default();
            if !inner.customers.contains_key(&customer) {
                return error(StatusCode::BAD_REQUEST, "No such customer");
            }
            if prices.iter().any(|p| !inner.prices.contains_key(p)) {
                return error(StatusCode::BAD_REQUEST, "No such price");
            }
            let id = inner.id("sub");
            inner.subscriptions.insert(
                id.clone(),
                json!({
                    "id": id, "object": "subscription", "customer": customer,
                    "status": "active", "metadata": metadata(&req.form),
                    "billing_cycle_anchor": f("billing_cycle_anchor"),
                }),
            );
            for price in prices {
                let item = inner.id("si");
                inner.items.insert(item, (id.clone(), price));
            }
            (StatusCode::OK, inner.subscription_json(&id))
        }
        ("POST", ["v1", "subscription_items"]) => {
            let (Some(sub), Some(price)) = (f("subscription"), f("price")) else {
                return error(StatusCode::BAD_REQUEST, "missing subscription or price");
            };
            if !inner.subscriptions.contains_key(&sub) || !inner.prices.contains_key(&price) {
                return error(StatusCode::BAD_REQUEST, "No such subscription or price");
            }
            let existing = inner.items_of(&sub);
            if existing.contains(&price) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Cannot add multiple subscription items with the same price",
                );
            }
            if existing.len() >= MAX_SUBSCRIPTION_ITEMS {
                return error(StatusCode::BAD_REQUEST, "too many subscription items");
            }
            let item = inner.id("si");
            inner.items.insert(item.clone(), (sub, price));
            (StatusCode::OK, inner.item_json(&item))
        }
        ("POST", ["v1", "subscription_items", id]) => {
            let Some(price) = f("price").filter(|p| inner.prices.contains_key(p)) else {
                return error(StatusCode::BAD_REQUEST, "No such price");
            };
            match inner.items.get_mut(*id) {
                Some(entry) => {
                    entry.1 = price;
                    (StatusCode::OK, inner.item_json(id))
                }
                None => error(StatusCode::NOT_FOUND, "No such subscription item"),
            }
        }
        _ => error(StatusCode::NOT_FOUND, "the mock does not serve this route"),
    }
}
