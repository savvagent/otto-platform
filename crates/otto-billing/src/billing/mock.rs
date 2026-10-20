//! A local, stateful stand-in for the slice of Stripe that [`super`] calls,
//! for tests. Never a network call: it listens on `127.0.0.1:0`.
//!
//! Like the client's own wire tests (`stripe::tests`), it records every request
//! so a test can assert exactly what was sent. Unlike them it keeps state, so a
//! whole flow (customer, checkout, subscription, schedule) can run against it:
//! customers, meters, prices, subscriptions, their items and their schedules
//! are created and returned in Stripe's shapes, and setup intents are seeded
//! by the test ([`MockStripe::add_setup_intent`]), standing in for the card a
//! person types into Checkout.
//!
//! What it holds to, as Stripe does:
//!
//! - **Idempotency keys.** A POST repeating a key with the same method, path
//!   and body gets the first response again, failures included (Stripe
//!   replays a cached `500` too), and changes nothing. Repeating a key with
//!   different parameters is `400 idempotency_error`.
//! - At most [`super::MAX_SUBSCRIPTION_ITEMS`] items per subscription, no
//!   price twice on one, one active meter per event name, one open schedule
//!   per subscription, and a schedule update must keep the current phase's
//!   start.
//! - **Meter events** ([`MockStripe::meter_events`]): a timestamp more than
//!   35 days old or more than 5 minutes ahead is `400`, and an `identifier`
//!   already received is not counted again (Stripe dedupes on it for at least
//!   24 hours). It is answered `200` by default, or `400
//!   resource_already_exists` after [`MockStripe::answer_duplicates_with_error`],
//!   so callers can be tested against either. [`MockStripe::delay`] slows a
//!   path down, and [`MockStripe::max_meter_events_in_flight`] reports how
//!   many meter-event calls overlapped.
//!
//! Schedules do not run on their own: [`MockStripe::advance_to`] plays them to
//! a given time, switching each subscription's items as its phases begin.
//!
//! **Invoices** are seeded by the test ([`MockStripe::add_invoice`]), standing
//! in for the draft Stripe makes when a period ends. They can be read, have
//! `auto_advance` set, and be finalized (a draft only); and
//! [`MockStripe::advance_to`] finalizes a draft whose `auto_advance` is still
//! on an hour after it was made, as Stripe does.
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
    pub query: Vec<(String, String)>,
    pub idempotency_key: Option<String>,
    pub authorization: Option<String>,
    /// The decoded form body, in order.
    pub form: Vec<(String, String)>,
    body: String,
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

    /// The first value of a query parameter.
    pub fn query_field(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Cached {
    method: String,
    path: String,
    body: String,
    status: StatusCode,
    value: Value,
}

#[derive(Default)]
struct Inner {
    seen: Vec<Seen>,
    replies: HashMap<String, Cached>,
    next_id: u64,
    customers: BTreeMap<String, Value>,
    setup_intents: BTreeMap<String, Value>,
    meters: BTreeMap<String, Value>,
    prices: BTreeMap<String, Value>,
    /// Subscription id -> the subscription, without its items.
    subscriptions: BTreeMap<String, Value>,
    /// Item id -> (subscription id, price id), in creation order by id.
    items: BTreeMap<u64, (String, String, String)>,
    schedules: BTreeMap<String, Value>,
    invoices: BTreeMap<String, Value>,
    detached: Vec<String>,
    /// Meter events Stripe counted, in arrival order, one per identifier.
    meter_events: Vec<Value>,
    /// Answer a duplicate meter-event identifier with a `400` rather than
    /// a `200`.
    duplicate_is_error: bool,
    /// Path prefix -> how long every matching request waits before it is
    /// handled.
    delays: Vec<(String, std::time::Duration)>,
    /// Meter-event calls in flight now, by customer and in total, and the
    /// most there have ever been.
    in_flight: HashMap<String, usize>,
    in_flight_total: usize,
    max_in_flight_per_customer: usize,
    max_in_flight_total: usize,
    /// Path prefix -> the status every matching request fails with.
    failures: Vec<(String, u16)>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Inner {
    fn id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}_mock{}", self.next_id)
    }

    fn add_item(&mut self, sub: &str, price: &str) -> String {
        self.next_id += 1;
        let id = format!("si_mock{}", self.next_id);
        self.items
            .insert(self.next_id, (id.clone(), sub.to_owned(), price.to_owned()));
        id
    }

    fn item_by_id(&mut self, id: &str) -> Option<&mut (String, String, String)> {
        self.items.values_mut().find(|(i, _, _)| i == id)
    }

    fn item_json(&self, item: &(String, String, String)) -> Value {
        let (id, sub, price) = item;
        json!({
            "id": id,
            "object": "subscription_item",
            "subscription": sub,
            "price": self.prices.get(price).cloned().unwrap_or(Value::Null),
        })
    }

    fn items_json(&self, sub: &str) -> Vec<Value> {
        self.items
            .values()
            .filter(|(_, owner, _)| owner == sub)
            .map(|i| self.item_json(i))
            .collect()
    }

    fn subscription_json(&self, sub: &str) -> Value {
        let mut s = self.subscriptions[sub].clone();
        s["items"] = json!({ "object": "list", "data": self.items_json(sub), "has_more": false });
        s
    }

    fn prices_of(&self, sub: &str) -> Vec<String> {
        self.items
            .values()
            .filter(|(_, owner, _)| owner == sub)
            .map(|(_, _, price)| price.clone())
            .collect()
    }

    /// Make a subscription hold exactly `prices` (as a schedule phase does).
    fn set_items(&mut self, sub: &str, prices: &[String]) {
        self.items
            .retain(|_, (_, owner, price)| owner != sub || prices.contains(price));
        let have = self.prices_of(sub);
        for p in prices {
            if !have.contains(p) {
                self.add_item(sub, p);
            }
        }
    }

    fn schedule_open(&self, id: &str) -> bool {
        self.schedules
            .get(id)
            .is_some_and(|s| matches!(s["status"].as_str(), Some("active" | "not_started")))
    }
}

/// A running mock. The listener runs until the test's runtime shuts down.
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

fn error(status: StatusCode, kind: &str, message: &str) -> (StatusCode, Value) {
    (
        status,
        json!({ "error": { "type": kind, "message": message } }),
    )
}

fn invalid(message: &str) -> (StatusCode, Value) {
    error(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

fn missing(message: &str) -> (StatusCode, Value) {
    error(StatusCode::NOT_FOUND, "invalid_request_error", message)
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

fn list(data: Vec<Value>) -> Value {
    json!({ "object": "list", "data": data, "has_more": false })
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

    /// Every POST so far.
    pub fn posts(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.method == "POST")
            .collect()
    }

    /// The POSTs whose path starts with `prefix`.
    pub fn posts_under(&self, prefix: &str) -> Vec<Seen> {
        self.posts()
            .into_iter()
            .filter(|s| s.path.starts_with(prefix))
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
    /// until [`Self::clear_failures`]. A keyed POST's failure is cached under
    /// its key, as Stripe caches it.
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

    /// Set a subscription's status, as Stripe does when it is canceled.
    pub fn set_subscription_status(&self, id: &str, status: &str) {
        if let Some(s) = self.lock().subscriptions.get_mut(id) {
            s["status"] = json!(status);
        }
    }

    /// The price ids on a subscription, sorted.
    pub fn subscription_prices(&self, id: &str) -> Vec<String> {
        let mut p = self.lock().prices_of(id);
        p.sort();
        p
    }

    /// A subscription schedule as Stripe holds it.
    pub fn schedule(&self, id: &str) -> Option<Value> {
        self.lock().schedules.get(id).cloned()
    }

    /// Payment methods detached so far, in order.
    pub fn detached(&self) -> Vec<String> {
        self.lock().detached.clone()
    }

    /// The meter events counted so far, oldest first: one per identifier,
    /// however many times it was sent.
    pub fn meter_events(&self) -> Vec<Value> {
        self.lock().meter_events.clone()
    }

    /// Answer a meter event whose identifier was already received with `400
    /// resource_already_exists` (`true`) or `200` (`false`, the default).
    pub fn answer_duplicates_with_error(&self, error: bool) {
        self.lock().duplicate_is_error = error;
    }

    /// Every request whose path starts with `prefix` waits `delay` before it
    /// is handled.
    pub fn delay(&self, prefix: &str, delay: std::time::Duration) {
        self.lock().delays.push((prefix.to_owned(), delay));
    }

    /// Stop every [`Self::delay`].
    pub fn clear_delays(&self) {
        self.lock().delays.clear();
    }

    /// The most meter-event calls ever in flight at once for one customer,
    /// and in total.
    pub fn max_meter_events_in_flight(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.max_in_flight_per_customer, inner.max_in_flight_total)
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

    /// Seed a draft subscription-cycle invoice of `subscription`, made at
    /// `period_end` (Unix seconds) for the period that ends then, with
    /// `auto_advance` on, as Stripe makes one. Returns it, in the shape an
    /// `invoice.created` event carries.
    pub fn add_invoice(
        &self,
        id: &str,
        customer: &str,
        subscription: &str,
        period_end: i64,
    ) -> Value {
        let invoice = json!({
            "id": id, "object": "invoice", "customer": customer, "status": "draft",
            "auto_advance": true, "billing_reason": "subscription_cycle",
            "created": period_end, "period_start": period_end - 30 * 86_400,
            "period_end": period_end,
            "parent": { "type": "subscription_details",
                        "subscription_details": { "subscription": subscription } },
        });
        self.lock().invoices.insert(id.to_owned(), invoice.clone());
        invoice
    }

    /// An invoice as Stripe holds it.
    pub fn invoice(&self, id: &str) -> Option<Value> {
        self.lock().invoices.get(id).cloned()
    }

    /// Set an invoice's status, as finalizing or voiding it in the dashboard
    /// does.
    pub fn set_invoice_status(&self, id: &str, status: &str) {
        if let Some(i) = self.lock().invoices.get_mut(id) {
            i["status"] = json!(status);
        }
    }

    /// Play every open schedule forward to `at` (Unix seconds): each
    /// subscription takes the items of the phase in effect at `at`, and a
    /// schedule whose last phase has ended releases its subscription. A draft
    /// invoice whose `auto_advance` is on and that was made at least an hour
    /// before `at` is finalized.
    pub fn advance_to(&self, at: i64) {
        let mut inner = self.lock();
        for invoice in inner.invoices.values_mut() {
            if invoice["status"] == json!("draft")
                && invoice["auto_advance"] == json!(true)
                && invoice["created"].as_i64().is_some_and(|c| c + 3600 <= at)
            {
                invoice["status"] = json!("open");
            }
        }
        let open: Vec<String> = inner
            .schedules
            .keys()
            .filter(|id| inner.schedule_open(id))
            .cloned()
            .collect();
        for id in open {
            let s = inner.schedules[&id].clone();
            let sub = s["subscription"].as_str().unwrap_or_default().to_owned();
            let phases = s["phases"].as_array().cloned().unwrap_or_default();
            let prices = |p: &Value| -> Vec<String> {
                p["items"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|i| i["price"].as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let current = phases.iter().find(|p| {
                p["start_date"].as_i64().unwrap_or(i64::MAX) <= at
                    && at < p["end_date"].as_i64().unwrap_or(i64::MAX)
            });
            if let Some(p) = current {
                let p = p.clone();
                inner.set_items(&sub, &prices(&p));
                let schedule = inner.schedules.get_mut(&id).expect("schedule");
                schedule["current_phase"] =
                    json!({ "start_date": p["start_date"], "end_date": p["end_date"] });
            } else if let Some(last) = phases.last() {
                if last["end_date"].as_i64().is_some_and(|end| at >= end) {
                    let last = last.clone();
                    inner.set_items(&sub, &prices(&last));
                    let schedule = inner.schedules.get_mut(&id).expect("schedule");
                    schedule["status"] = json!("released");
                    schedule["current_phase"] = Value::Null;
                    if let Some(s) = inner.subscriptions.get_mut(&sub) {
                        s["schedule"] = Value::Null;
                    }
                }
            }
        }
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
    let query: Vec<(String, String)> = uri
        .query()
        .and_then(|q| serde_urlencoded::from_str(q).ok())
        .unwrap_or_default();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let seen = Seen {
        method: method.as_str().to_owned(),
        path: uri.path().to_owned(),
        query,
        idempotency_key: header("idempotency-key"),
        authorization: header("authorization"),
        form,
        body: String::from_utf8_lossy(&body).into_owned(),
    };

    // Handled in a task of its own, so a caller that gives up (a client
    // timeout) does not stop the request being processed, as with Stripe.
    let task = tokio::spawn(async move {
        let lock = || inner.lock().unwrap_or_else(PoisonError::into_inner);
        let meter_event = seen.path == "/v1/billing/meter_events";
        let customer = seen
            .field("payload[stripe_customer_id]")
            .unwrap_or_default()
            .to_owned();
        let delay = {
            let mut inner = lock();
            if meter_event {
                let n = inner.in_flight.entry(customer.clone()).or_default();
                *n += 1;
                let n = *n;
                inner.in_flight_total += 1;
                inner.max_in_flight_per_customer = inner.max_in_flight_per_customer.max(n);
                inner.max_in_flight_total = inner.max_in_flight_total.max(inner.in_flight_total);
            }
            inner
                .delays
                .iter()
                .find(|(prefix, _)| seen.path.starts_with(prefix.as_str()))
                .map(|(_, d)| *d)
        };
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let mut inner = lock();
        let (status, axum::Json(value)) = respond(&mut inner, seen);
        if meter_event {
            if let Some(n) = inner.in_flight.get_mut(&customer) {
                *n -= 1;
            }
            inner.in_flight_total -= 1;
        }
        (status, value)
    });
    match task.await {
        Ok((status, value)) => (status, axum::Json(value)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "error": { "type": "api_error", "message": "mock panicked" } })),
        ),
    }
}

fn respond(inner: &mut Inner, seen: Seen) -> (StatusCode, axum::Json<Value>) {
    inner.seen.push(seen.clone());

    if let Some(key) = seen.idempotency_key.as_ref() {
        if let Some(c) = inner.replies.get(key) {
            if c.method != seen.method || c.path != seen.path || c.body != seen.body {
                let (s, v) = error(
                    StatusCode::BAD_REQUEST,
                    "idempotency_error",
                    "Keys for idempotent requests can only be used with the same parameters \
                     they were first used with.",
                );
                return (s, axum::Json(v));
            }
            return (c.status, axum::Json(c.value.clone()));
        }
    }

    let failure = inner
        .failures
        .iter()
        .find(|(prefix, _)| seen.path.starts_with(prefix.as_str()))
        .map(|(_, status)| *status);
    let (status, value) = match failure {
        Some(status) => error(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            "api_error",
            "the mock was told to fail this path",
        ),
        None => route(inner, &seen),
    };
    if let Some(key) = seen.idempotency_key {
        inner.replies.insert(
            key,
            Cached {
                method: seen.method,
                path: seen.path,
                body: seen.body,
                status,
                value: value.clone(),
            },
        );
    }
    (status, axum::Json(value))
}

/// `phases[i][...]` of a schedule update, as JSON phases.
fn parse_phases(
    inner: &Inner,
    req: &Seen,
    current_start: i64,
) -> Result<Vec<Value>, (StatusCode, Value)> {
    let mut phases = Vec::new();
    let mut start = None;
    for i in 0.. {
        let Some(end) = req.field(&format!("phases[{i}][end_date]")) else {
            break;
        };
        let end: i64 = end.parse().map_err(|_| invalid("bad end_date"))?;
        let this_start = match (i, req.field(&format!("phases[{i}][start_date]"))) {
            (0, Some(s)) => {
                let s: i64 = s.parse().map_err(|_| invalid("bad start_date"))?;
                if s != current_start {
                    return Err(invalid(
                        "phases[0][start_date] must be the current phase's start_date",
                    ));
                }
                s
            }
            (0, None) => return Err(invalid("phases[0][start_date] is required")),
            (_, Some(_)) => return Err(invalid("only the first phase may set start_date")),
            (_, None) => start.ok_or_else(|| invalid("phase has no start"))?,
        };
        if end <= this_start {
            return Err(invalid("a phase must end after it starts"));
        }
        let items: Vec<Value> = (0..)
            .map_while(|j| req.field(&format!("phases[{i}][items][{j}][price]")))
            .map(|p| json!({ "price": p }))
            .collect();
        if items.is_empty() || items.len() > MAX_SUBSCRIPTION_ITEMS {
            return Err(invalid("a phase needs 1 to 20 items"));
        }
        if items.iter().any(|i| {
            !inner
                .prices
                .contains_key(i["price"].as_str().unwrap_or_default())
        }) {
            return Err(invalid("No such price"));
        }
        phases.push(json!({
            "start_date": this_start,
            "end_date": end,
            "items": items,
            "proration_behavior": req.field(&format!("phases[{i}][proration_behavior]")),
        }));
        start = Some(end);
    }
    if phases.is_empty() {
        return Err(invalid("phases are required"));
    }
    Ok(phases)
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
        ("GET", ["v1", "customers", "search"]) => {
            let query = req.query_field("query").unwrap_or_default();
            let parsed = query
                .strip_prefix("metadata['")
                .and_then(|r| r.split_once("']:'"))
                .and_then(|(k, v)| Some((k.to_owned(), v.strip_suffix('\'')?.to_owned())));
            let Some((key, value)) = parsed else {
                return invalid("unsupported search query");
            };
            let data = inner
                .customers
                .values()
                .filter(|c| c["metadata"][&key] == json!(value))
                .cloned()
                .collect();
            (StatusCode::OK, list(data))
        }
        ("POST", ["v1", "customers", id]) => match inner.customers.get_mut(*id) {
            Some(c) => {
                if let Some(pm) = f("invoice_settings[default_payment_method]") {
                    c["invoice_settings"]["default_payment_method"] = json!(pm);
                }
                (StatusCode::OK, c.clone())
            }
            None => missing("No such customer"),
        },
        ("POST", ["v1", "payment_methods", id, "detach"]) => {
            inner.detached.push((*id).to_owned());
            (
                StatusCode::OK,
                json!({ "id": id, "object": "payment_method", "customer": null }),
            )
        }
        ("POST", ["v1", "checkout", "sessions"]) => {
            if !f("customer").is_some_and(|c| inner.customers.contains_key(&c)) {
                return invalid("No such customer");
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
            None => missing("No such setupintent"),
        },
        ("GET", ["v1", "billing", "meters"]) => {
            let data = inner.meters.values().cloned().collect();
            (StatusCode::OK, list(data))
        }
        ("POST", ["v1", "billing", "meters"]) => {
            let event_name = f("event_name").unwrap_or_default();
            if inner
                .meters
                .values()
                .any(|m| m["event_name"] == json!(event_name))
            {
                return invalid("An active meter with this event_name already exists");
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
                return invalid("No such meter");
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
        ("GET", ["v1", "subscriptions"]) => {
            let customer = req.query_field("customer").unwrap_or_default().to_owned();
            let ids: Vec<String> = inner
                .subscriptions
                .iter()
                .filter(|(_, s)| s["customer"] == json!(customer))
                .map(|(id, _)| id.clone())
                .collect();
            let data = ids.iter().map(|id| inner.subscription_json(id)).collect();
            (StatusCode::OK, list(data))
        }
        ("GET", ["v1", "subscriptions", id]) => {
            if inner.subscriptions.contains_key(*id) {
                (StatusCode::OK, inner.subscription_json(id))
            } else {
                missing("No such subscription")
            }
        }
        ("POST", ["v1", "subscriptions"]) => {
            let prices: Vec<String> = req
                .fields_starting("items[")
                .into_iter()
                .map(str::to_owned)
                .collect();
            if prices.is_empty() || prices.len() > MAX_SUBSCRIPTION_ITEMS {
                return invalid("a subscription needs 1 to 20 items");
            }
            let customer = f("customer").unwrap_or_default();
            if !inner.customers.contains_key(&customer) {
                return invalid("No such customer");
            }
            if prices.iter().any(|p| !inner.prices.contains_key(p)) {
                return invalid("No such price");
            }
            let id = inner.id("sub");
            let created = now();
            let anchor: Option<i64> = f("billing_cycle_anchor").and_then(|a| a.parse().ok());
            let start: Option<i64> = f("backdate_start_date").and_then(|a| a.parse().ok());
            if start.is_some_and(|s| s > created) {
                return invalid("backdate_start_date must be in the past");
            }
            if let (Some(s), Some(a)) = (start, anchor) {
                if a <= s {
                    return invalid("billing_cycle_anchor must be after backdate_start_date");
                }
            }
            inner.subscriptions.insert(
                id.clone(),
                json!({
                    "id": id, "object": "subscription", "customer": customer,
                    "status": "active", "metadata": metadata(&req.form),
                    "created": created, "billing_cycle_anchor": anchor,
                    "start_date": start.unwrap_or(created),
                    "schedule": null,
                }),
            );
            for price in prices {
                inner.add_item(&id, &price);
            }
            (StatusCode::OK, inner.subscription_json(&id))
        }
        ("GET", ["v1", "subscription_items"]) => {
            let sub = req.query_field("subscription").unwrap_or_default();
            (StatusCode::OK, list(inner.items_json(sub)))
        }
        ("POST", ["v1", "subscription_items"]) => {
            let (Some(sub), Some(price)) = (f("subscription"), f("price")) else {
                return invalid("missing subscription or price");
            };
            if !inner.subscriptions.contains_key(&sub) || !inner.prices.contains_key(&price) {
                return invalid("No such subscription or price");
            }
            let existing = inner.prices_of(&sub);
            if existing.contains(&price) {
                return invalid("Cannot add multiple subscription items with the same price");
            }
            if existing.len() >= MAX_SUBSCRIPTION_ITEMS {
                return invalid("too many subscription items");
            }
            let item = inner.add_item(&sub, &price);
            let json = inner
                .items
                .values()
                .find(|(i, _, _)| *i == item)
                .map(|i| inner.item_json(i))
                .unwrap_or(Value::Null);
            (StatusCode::OK, json)
        }
        ("POST", ["v1", "subscription_items", id]) => {
            let Some(price) = f("price").filter(|p| inner.prices.contains_key(p)) else {
                return invalid("No such price");
            };
            match inner.item_by_id(id) {
                Some(entry) => {
                    entry.2 = price;
                    let entry = entry.clone();
                    (StatusCode::OK, inner.item_json(&entry))
                }
                None => missing("No such subscription item"),
            }
        }
        ("POST", ["v1", "subscription_schedules"]) => {
            let Some(sub) = f("from_subscription") else {
                return invalid("from_subscription is required");
            };
            let Some(s) = inner.subscriptions.get(&sub).cloned() else {
                return invalid("No such subscription");
            };
            if s["schedule"]
                .as_str()
                .is_some_and(|id| inner.schedule_open(id))
            {
                return invalid("The subscription is already attached to a schedule");
            }
            // The current period's start: the backdated start, if any.
            let start = s["start_date"]
                .as_i64()
                .or_else(|| s["created"].as_i64())
                .unwrap_or_else(now);
            let end = s["billing_cycle_anchor"]
                .as_i64()
                .unwrap_or(start + 30 * 86_400);
            let items: Vec<Value> = inner
                .prices_of(&sub)
                .into_iter()
                .map(|p| json!({ "price": p }))
                .collect();
            let id = inner.id("sub_sched");
            let schedule = json!({
                "id": id, "object": "subscription_schedule", "status": "active",
                "subscription": sub, "end_behavior": "release",
                "current_phase": { "start_date": start, "end_date": end },
                "phases": [{
                    "start_date": start, "end_date": end, "items": items,
                    "proration_behavior": "create_prorations",
                }],
            });
            inner.schedules.insert(id.clone(), schedule.clone());
            if let Some(s) = inner.subscriptions.get_mut(&sub) {
                s["schedule"] = json!(id);
            }
            (StatusCode::OK, schedule)
        }
        ("GET", ["v1", "subscription_schedules", id]) => match inner.schedules.get(*id) {
            Some(s) => (StatusCode::OK, s.clone()),
            None => missing("No such subscription schedule"),
        },
        ("POST", ["v1", "subscription_schedules", id]) => {
            if !inner.schedule_open(id) {
                return invalid("You cannot update a schedule that is not active");
            }
            let s = inner.schedules[*id].clone();
            let current_start = s["current_phase"]["start_date"].as_i64().unwrap_or(0);
            let phases = match parse_phases(inner, req, current_start) {
                Ok(p) => p,
                Err(e) => return e,
            };
            // The current phase's items apply now, as in Stripe.
            let sub = s["subscription"].as_str().unwrap_or_default().to_owned();
            let now_prices: Vec<String> = phases[0]["items"]
                .as_array()
                .map(|i| {
                    i.iter()
                        .filter_map(|x| x["price"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            inner.set_items(&sub, &now_prices);
            let schedule = inner.schedules.get_mut(*id).expect("schedule");
            schedule["current_phase"] = json!({
                "start_date": phases[0]["start_date"], "end_date": phases[0]["end_date"],
            });
            schedule["phases"] = json!(phases);
            schedule["end_behavior"] = json!(f("end_behavior"));
            schedule["proration_behavior"] = json!(f("proration_behavior"));
            (StatusCode::OK, schedule.clone())
        }
        ("POST", ["v1", "subscription_schedules", id, "release"]) => {
            if !inner.schedule_open(id) {
                return invalid("You cannot release a schedule that is not active");
            }
            let schedule = inner.schedules.get_mut(*id).expect("schedule");
            schedule["status"] = json!("released");
            let sub = schedule["subscription"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let schedule = schedule.clone();
            if let Some(s) = inner.subscriptions.get_mut(&sub) {
                s["schedule"] = Value::Null;
            }
            (StatusCode::OK, schedule)
        }
        ("GET", ["v1", "invoices", id]) => match inner.invoices.get(*id) {
            Some(i) => (StatusCode::OK, i.clone()),
            None => missing("No such invoice"),
        },
        ("POST", ["v1", "invoices", id]) => match inner.invoices.get_mut(*id) {
            Some(i) => {
                if let Some(a) = f("auto_advance") {
                    i["auto_advance"] = json!(a == "true");
                }
                (StatusCode::OK, i.clone())
            }
            None => missing("No such invoice"),
        },
        ("POST", ["v1", "invoices", id, "finalize"]) => match inner.invoices.get_mut(*id) {
            Some(i) if i["status"] == json!("draft") => {
                i["status"] = json!("open");
                i["auto_advance"] = json!(f("auto_advance").as_deref() != Some("false"));
                (StatusCode::OK, i.clone())
            }
            Some(_) => invalid("This invoice is already finalized."),
            None => missing("No such invoice"),
        },
        ("POST", ["v1", "billing", "meter_events"]) => {
            let (Some(event_name), Some(identifier)) = (f("event_name"), f("identifier")) else {
                return invalid("event_name and identifier are required");
            };
            let Some(timestamp) = f("timestamp").and_then(|t| t.parse::<i64>().ok()) else {
                return invalid("timestamp is required");
            };
            if timestamp < now() - 35 * 86_400 {
                return invalid("Timestamp must be within the past 35 calendar days.");
            }
            if timestamp > now() + 5 * 60 {
                return invalid("Timestamp must not be more than 5 minutes in the future.");
            }
            let record = json!({
                "object": "billing.meter_event", "event_name": event_name,
                "identifier": identifier, "timestamp": timestamp,
                "payload": {
                    "stripe_customer_id": f("payload[stripe_customer_id]"),
                    "value": f("payload[value]"),
                },
            });
            if inner
                .meter_events
                .iter()
                .any(|e| e["identifier"] == json!(identifier))
            {
                if inner.duplicate_is_error {
                    return (
                        StatusCode::BAD_REQUEST,
                        json!({ "error": {
                            "type": "invalid_request_error",
                            "code": "resource_already_exists",
                            "message": format!(
                                "A meter event with identifier {identifier} already exists."
                            ),
                        } }),
                    );
                }
            } else {
                inner.meter_events.push(record.clone());
            }
            (StatusCode::OK, record)
        }
        _ => missing("the mock does not serve this route"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::{CreateCustomer, IdempotencyKey};

    #[tokio::test]
    async fn a_key_reused_with_other_parameters_is_an_idempotency_error() {
        let m = MockStripe::start().await;
        let c = m.client();
        let key = IdempotencyKey::new("k1").unwrap();
        let a = CreateCustomer {
            name: Some("A".into()),
            ..Default::default()
        };
        let first = c.create_customer(&a, &key).await.unwrap();
        assert_eq!(c.create_customer(&a, &key).await.unwrap().id, first.id);
        let b = CreateCustomer {
            name: Some("B".into()),
            ..Default::default()
        };
        let err = c.create_customer(&b, &key).await.unwrap_err();
        assert_eq!(err.api().unwrap().kind, "idempotency_error");
        assert_eq!(m.lock().customers.len(), 1);
    }

    #[tokio::test]
    async fn meter_events_dedupe_on_identifier_and_refuse_old_timestamps() {
        use crate::stripe::MeterEvent;
        let m = MockStripe::start().await;
        let c = m.client();
        let ev = |identifier: &str, age: chrono::Duration| MeterEvent {
            event_name: "svc__calls".into(),
            stripe_customer_id: "cus_1".into(),
            value: 2,
            identifier: identifier.into(),
            timestamp: chrono::Utc::now() - age,
        };
        let fresh = ev("svc:1", chrono::Duration::zero());
        c.send_meter_event(&fresh, &IdempotencyKey::new("a").unwrap())
            .await
            .unwrap();
        // The same identifier under another key is accepted, not counted.
        c.send_meter_event(&fresh, &IdempotencyKey::new("b").unwrap())
            .await
            .unwrap();
        assert_eq!(m.meter_events().len(), 1);
        let old = ev("svc:2", chrono::Duration::days(36));
        let err = c
            .send_meter_event(&old, &IdempotencyKey::new("c").unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.api().unwrap().status, 400);
        assert_eq!(m.meter_events().len(), 1);
    }

    #[tokio::test]
    async fn a_failure_is_cached_under_its_key() {
        let m = MockStripe::start().await;
        let c = m.client();
        let key = IdempotencyKey::new("k2").unwrap();
        m.fail("/v1/customers", 500);
        let params = CreateCustomer::default();
        assert_eq!(
            c.create_customer(&params, &key)
                .await
                .unwrap_err()
                .api()
                .unwrap()
                .status,
            500
        );
        m.clear_failures();
        // Replayed, as Stripe replays it, until the key changes.
        assert_eq!(
            c.create_customer(&params, &key)
                .await
                .unwrap_err()
                .api()
                .unwrap()
                .status,
            500
        );
        let other = IdempotencyKey::new("k3").unwrap();
        assert!(c.create_customer(&params, &other).await.is_ok());
    }
}
