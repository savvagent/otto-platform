//! `Client::call_tool` against a mock MCP resource server. Nothing here is
//! specific to otto-flags: `add` is an unrelated tool, and `issue` stands in
//! for any tool whose result carries a secret.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use savvagent_client::{Client, Error, Opener, Store};
use serde_json::{json, Value};
use url::Url;

const TOKEN: &str = "at-valid";
const SECRET: &str = "srv_THE-SECRET";

/// The grant is seeded, so signing in must never be needed.
struct NoBrowser;
impl Opener for NoBrowser {
    fn open(&self, _: &Url) -> savvagent_client::Result<()> {
        panic!("no browser should open: the grant is cached");
    }
}

#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Vec<Value>>>);

async fn mcp(State(calls): State<Calls>, headers: HeaderMap, Json(req): Json<Value>) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    calls.0.lock().unwrap().push(req.clone());
    assert_eq!(req["method"], "tools/call");
    let args = &req["params"]["arguments"];
    let ok = |structured: Value| {
        json!({"jsonrpc": "2.0", "id": req["id"], "result": {
            // What rmcp sends: the same JSON as text, secrets and all.
            "content": [{"type": "text", "text": structured.to_string()}],
            "structuredContent": structured,
        }})
    };
    let body = match req["params"]["name"].as_str().unwrap() {
        "add" => ok(json!({"sum": args["a"].as_i64().unwrap() + args["b"].as_i64().unwrap()})),
        "issue" => ok(json!({
            "app": {"name": args["name"]},
            "keys": {"serverKey": SECRET, "clientKey": "sdk_public"},
            // A careless server repeating the key elsewhere.
            "note": format!("store {SECRET} now"),
        })),
        "denied" => json!({"jsonrpc": "2.0", "id": req["id"], "error": {
            "code": -32600,
            "message": "this token lacks the keys:issue scope\u{1b}[31m",
            "data": {"code": "insufficient_scope", "retriable": false},
        }}),
        "boom" => json!({"jsonrpc": "2.0", "id": req["id"], "result": {
            "content": [{"type": "text", "text": "the app does not exist"}],
            "isError": true,
        }}),
        "stream" => {
            let event = ok(json!({"sum": 3}));
            return (
                [(header::CONTENT_TYPE, "text/event-stream")],
                format!("event: message\ndata: {event}\n\n"),
            )
                .into_response();
        }
        other => panic!("unexpected tool {other}"),
    };
    Json(body).into_response()
}

/// A mock resource server, and a client whose store holds a fresh grant for it.
async fn setup(scope: &str) -> (Client, String, Calls, tempfile::TempDir) {
    let calls = Calls::default();
    let app = Router::new()
        .route("/mcp", post(mcp))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resource = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let doc = json!({"clients": {}, "grants": {&resource: {
        "issuer": "http://127.0.0.1:1",
        "client_id": "c",
        "access_token": TOKEN,
        "refresh_token": null,
        "expires_at": now + 3600,
        "scope": scope,
    }}});
    std::fs::write(dir.path().join("credentials.json"), doc.to_string()).unwrap();
    let client = Client::new(Store::at(dir.path()), Box::new(NoBrowser)).unwrap();
    (client, resource, calls, dir)
}

#[tokio::test]
async fn calls_any_tool_and_returns_its_structured_result() {
    let (client, resource, calls, _dir) = setup("things:write").await;
    let out = client
        .call_tool(&resource, &[], "add", json!({"a": 2, "b": 5}), &[])
        .await
        .unwrap();
    assert_eq!(out.value(), &json!({"sum": 7}));
    let sent = calls.0.lock().unwrap();
    assert_eq!(
        sent[0]["params"],
        json!({"name": "add", "arguments": {"a": 2, "b": 5}})
    );
}

#[tokio::test]
async fn named_secret_fields_come_back_only_as_secrets() {
    let (client, resource, _calls, _dir) = setup("apps:admin keys:issue").await;
    let scopes = ["apps:admin".to_owned(), "keys:issue".to_owned()];
    let out = client
        .call_tool(
            &resource,
            &scopes,
            "issue",
            json!({"name": "web"}),
            &["/keys/serverKey"],
        )
        .await
        .unwrap();
    assert_eq!(out.secret("/keys/serverKey").unwrap().expose(), SECRET);
    assert_eq!(
        out.value(),
        &json!({
            "app": {"name": "web"},
            "keys": {"clientKey": "sdk_public"},
            "note": "<redacted>",
        })
    );
    let shown = format!("{out:?} {}", out.value());
    assert!(!shown.contains("THE-SECRET"), "{shown}");
}

#[tokio::test]
async fn a_missing_scope_is_its_own_error_with_the_servers_reason() {
    let (client, resource, _calls, _dir) = setup("apps:admin").await;
    let err = client
        .call_tool(&resource, &[], "denied", json!({}), &[])
        .await
        .unwrap_err();
    let Error::InsufficientScope { message, .. } = &err else {
        panic!("{err:?}");
    };
    assert!(message.contains("keys:issue"), "{message}");
    assert!(
        !err.to_string().contains('\u{1b}'),
        "escape sequences are dropped"
    );
}

#[tokio::test]
async fn a_secret_field_must_be_a_json_pointer() {
    let (client, resource, calls, _dir) = setup("").await;
    let err = client
        .call_tool(
            &resource,
            &[],
            "issue",
            json!({"name": "web"}),
            &["keys/serverKey"],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    assert!(calls.0.lock().unwrap().is_empty(), "refused before sending");
}

#[tokio::test]
async fn a_tool_error_names_the_tool() {
    let (client, resource, _calls, _dir) = setup("").await;
    let err = client
        .call_tool(&resource, &[], "boom", json!({}), &[])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tool { .. }), "{err:?}");
    assert_eq!(err.to_string(), "boom failed: the app does not exist");
}

#[tokio::test]
async fn a_rejected_token_means_signing_in_again() {
    let (client, resource, _calls, dir) = setup("").await;
    let path = dir.path().join("credentials.json");
    let doc = std::fs::read_to_string(&path)
        .unwrap()
        .replace(TOKEN, "at-revoked");
    std::fs::write(&path, doc).unwrap();
    let err = client
        .call_tool(&resource, &[], "add", json!({"a": 1, "b": 1}), &[])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::LoginRequired { .. }), "{err:?}");
}

#[tokio::test]
async fn an_event_stream_response_is_read_too() {
    let (client, resource, _calls, _dir) = setup("").await;
    let out = client
        .call_tool(&resource, &[], "stream", json!({}), &[])
        .await
        .unwrap();
    assert_eq!(out.value(), &json!({"sum": 3}));
}
