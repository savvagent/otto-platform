//! `otto-flags` against a mock otto-flags MCP server, with a cached grant so no
//! browser is involved. Every case captures stdout and stderr (this binary has
//! no other log) and checks no server key appears in either: the only place a
//! `srv_` value may go is the sink the user chose.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

const SERVER_KEY: &str = "srv_LEAKCANARY";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Issue keys the way otto-flags does today.
    Issue,
    /// Refuse: the token lacks `keys:issue`.
    NoScope,
    /// Create the app but withhold the server key.
    Withhold,
    /// Act, then answer with something that is not a JSON-RPC response.
    Garbage,
}

#[derive(Clone)]
struct Mock {
    mode: Mode,
    calls: Arc<Mutex<Vec<Value>>>,
}

async fn mcp(State(mock): State<Mock>, headers: HeaderMap, Json(req): Json<Value>) -> Response {
    assert_eq!(
        headers.get(header::AUTHORIZATION).unwrap(),
        "Bearer at",
        "the cached token is sent"
    );
    mock.calls.lock().unwrap().push(req.clone());
    let id = req["id"].clone();
    if mock.mode == Mode::Garbage {
        return "<html>gateway timeout</html>".into_response();
    }
    if mock.mode == Mode::NoScope {
        return Json(json!({"jsonrpc": "2.0", "id": id, "error": {
            "code": -32600,
            "message": "this token lacks the keys:issue scope",
            "data": {"code": "insufficient_scope", "retriable": false},
        }}))
        .into_response();
    }
    let args = &req["params"]["arguments"];
    let name = args["name"].as_str().or(args["app"].as_str()).unwrap();
    let which = args["which"].as_str().unwrap_or("both");
    let mut keys = json!({});
    if which != "server" {
        keys["clientKey"] = json!("sdk_PUBLIC");
    }
    if which != "client" && mock.mode == Mode::Issue {
        keys["serverKey"] = json!(SERVER_KEY);
    }
    let structured = json!({
        "app": {"id": "app-1", "name": name, "environments": ["production"],
                "clientKey": "sdk_PUBLIC"},
        "keys": keys,
        // A careless server repeating the key: it must be redacted.
        "note": format!("Store {SERVER_KEY} now."),
    });
    Json(json!({"jsonrpc": "2.0", "id": id, "result": {
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
    }}))
    .into_response()
}

struct Env {
    resource: String,
    calls: Arc<Mutex<Vec<Value>>>,
    dir: tempfile::TempDir,
    _runtime: tokio::runtime::Runtime,
}

fn env(mode: Mode) -> Env {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mock = Mock {
        mode,
        calls: calls.clone(),
    };
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let resource = format!("http://{}/mcp", listener.local_addr().unwrap());
    let app = Router::new().route("/mcp", post(mcp)).with_state(mock);
    runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let doc = json!({"clients": {}, "grants": {&resource: {
        "issuer": "http://127.0.0.1:1", "client_id": "c", "access_token": "at",
        "refresh_token": null, "expires_at": now + 3600,
        "scope": "apps:admin keys:issue",
    }}});
    std::fs::create_dir(dir.path().join("cfg")).unwrap();
    std::fs::write(dir.path().join("cfg/credentials.json"), doc.to_string()).unwrap();
    Env {
        resource,
        calls,
        dir,
        _runtime: runtime,
    }
}

impl Env {
    /// Run `otto-flags` with stdout and stderr captured: stdout is a pipe.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_otto-flags"))
            .args(args)
            .env("OTTO_CONFIG_DIR", self.dir.path().join("cfg"))
            .env("OTTO_FLAGS_RESOURCE", &self.resource)
            .output()
            .unwrap()
    }

    fn calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }
}

/// The two streams as text, after asserting neither holds the key.
fn no_leak(out: &Output) -> (String, String) {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!stdout.contains("srv_"), "stdout: {stdout}");
    // The usage text and the note mention `srv_…`; no key value may appear.
    assert!(!stderr.contains(SERVER_KEY), "stderr: {stderr}");
    assert!(!stdout.contains("LEAKCANARY") && !stderr.contains("LEAKCANARY"));
    (stdout, stderr)
}

#[test]
fn a_piped_stdout_is_refused_before_anything_is_issued() {
    let e = env(Mode::Issue);
    for args in [
        &["keys", "rotate", "--app", "web"][..],
        &["app", "create", "web"][..],
    ] {
        let out = e.run(args);
        let (_, stderr) = no_leak(&out);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("pipe") && stderr.contains("Nothing was changed"),
            "{stderr}"
        );
    }
    assert_eq!(e.calls(), 0, "nothing was asked of the server");
}

#[test]
fn an_existing_out_file_is_refused_before_anything_is_issued() {
    let e = env(Mode::Issue);
    let key = e.path("key");
    std::fs::write(&key, "old").unwrap();
    let out = e.run(&["keys", "rotate", "--app", "web", "--out", &key]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&key).unwrap(), "old");
    assert_eq!(e.calls(), 0);
}

#[test]
fn the_server_key_goes_only_to_the_named_file() {
    let e = env(Mode::Issue);
    let key = e.path("key");
    let out = e.run(&["app", "create", "web", "--env", "production", "--out", &key]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(&key).unwrap(),
        format!("{SERVER_KEY}\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(
        stderr.contains("sdk_PUBLIC"),
        "the public key is shown: {stderr}"
    );
    assert!(stderr.contains("secret written to"), "{stderr}");

    let sent = &e.calls.lock().unwrap()[0];
    assert_eq!(sent["params"]["name"], "create_app");
    assert_eq!(
        sent["params"]["arguments"],
        json!({"name": "web", "environments": ["production"]})
    );
}

#[test]
fn a_missing_scope_names_it_and_how_to_get_it() {
    let e = env(Mode::NoScope);
    let key = e.path("key");
    let out = e.run(&["keys", "rotate", "--app", "web", "--out", &key]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("keys:issue"), "{stderr}");
    assert!(
        stderr.contains(&format!("ottoctl login --resource {}", e.resource)),
        "{stderr}"
    );
    assert!(!Path::new(&key).exists());
}

#[test]
fn a_withheld_server_key_says_how_to_issue_one() {
    let e = env(Mode::Withhold);
    let key = e.path("key");
    let out = e.run(&["app", "create", "web", "--out", &key]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("ottoctl flags keys rotate --app web"),
        "{stderr}"
    );
    assert!(!Path::new(&key).exists());
}

#[test]
fn rotating_only_the_public_key_needs_no_secret_sink() {
    let e = env(Mode::Issue);
    let out = e.run(&["keys", "rotate", "--app", "web", "--which", "client"]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("sdk_PUBLIC"), "{stderr}");
    assert_eq!(e.calls(), 1);
}

#[test]
fn no_usable_response_says_the_rotation_may_have_happened() {
    let e = env(Mode::Garbage);
    let key = e.path("key");
    let out = e.run(&["keys", "rotate", "--app", "my app", "--out", &key]);
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("may have received the request"), "{stderr}");
    assert!(
        stderr.contains("ottoctl flags keys rotate --app 'my app'"),
        "{stderr}"
    );
    assert!(!Path::new(&key).exists(), "the reservation is released");
}

/// An unwritable directory is found before anything is issued, not after.
#[cfg(unix)]
#[test]
fn an_unwritable_directory_is_refused_before_anything_is_issued() {
    use std::os::unix::fs::PermissionsExt;
    let e = env(Mode::Issue);
    let locked = e.dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(locked.join("probe"), "").is_ok() {
        // Root ignores the mode; there is nothing to test.
        return;
    }
    let key = locked.join("key");
    let out = e.run(&[
        "keys",
        "rotate",
        "--app",
        "web",
        "--out",
        key.to_str().unwrap(),
    ]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_, stderr) = no_leak(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Nothing was changed"), "{stderr}");
    assert_eq!(e.calls(), 0);
    assert!(!key.exists());
}
