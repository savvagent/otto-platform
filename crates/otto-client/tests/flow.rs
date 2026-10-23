//! The login, refresh and revoked-grant paths against a mock authorization
//! server that checks PKCE the way otto-auth does.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_client::{Client, Error, Opener, Result, Secret, Sink, Store};
use sha2::{Digest, Sha256};
use url::Url;

const ACCESS_1: &str = "access-token-one-SECRETVALUE";
const REFRESH_1: &str = "refresh-token-one-SECRETVALUE";

#[derive(Default)]
struct Server {
    base: String,
    registrations: u32,
    authorizes: Vec<HashMap<String, String>>,
    challenge: String,
    refresh_calls: u32,
    /// Make the refresh grant fail as a revoked one does.
    revoke: bool,
    /// An `access_token` the next refresh issues.
    next_access: String,
}

type Shared = Arc<Mutex<Server>>;

async fn resource_meta(State(s): State<Shared>) -> Json<serde_json::Value> {
    let base = s.lock().unwrap().base.clone();
    Json(serde_json::json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
    }))
}

async fn server_meta(State(s): State<Shared>) -> Json<serde_json::Value> {
    let base = s.lock().unwrap().base.clone();
    Json(serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
    }))
}

async fn register(
    State(s): State<Shared>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut s = s.lock().unwrap();
    s.registrations += 1;
    assert_eq!(body["redirect_uris"][0], "http://127.0.0.1/callback");
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "client_id": "otto_client_test" })),
    )
}

async fn authorize(State(s): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Redirect {
    let mut s = s.lock().unwrap();
    s.challenge = q["code_challenge"].clone();
    let redirect = format!("{}?code=the-code&state={}", q["redirect_uri"], q["state"]);
    s.authorizes.push(q);
    Redirect::to(&redirect)
}

async fn token(
    State(s): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut s = s.lock().unwrap();
    match f["grant_type"].as_str() {
        "authorization_code" => {
            assert_eq!(f["code"], "the-code");
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(f["code_verifier"].as_bytes()));
            if computed != s.challenge {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "invalid_grant", "error_description": "PKCE verification failed" }),
                    ),
                );
            }
            assert_eq!(f["resource"], format!("{}/mcp", s.base));
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": ACCESS_1, "token_type": "Bearer",
                    "expires_in": 3600, "refresh_token": REFRESH_1, "scope": "mcp",
                })),
            )
        }
        "refresh_token" => {
            s.refresh_calls += 1;
            if s.revoke {
                // A body that would leak if an error echoed it verbatim.
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "refresh token revoked",
                        "debug_token": ACCESS_1,
                    })),
                );
            }
            assert_eq!(f["refresh_token"], REFRESH_1);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": s.next_access, "token_type": "Bearer", "expires_in": 3600,
                })),
            )
        }
        other => panic!("unexpected grant {other}"),
    }
}

async fn spawn() -> (Shared, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let shared: Shared = Arc::new(Mutex::new(Server {
        base: base.clone(),
        next_access: "access-token-two-SECRETVALUE".into(),
        ..Default::default()
    }));
    let app = Router::new()
        // Only the origin-root form: the client tries the path-inserted one
        // first, gets a 404, and must fall back.
        .route("/.well-known/oauth-protected-resource", get(resource_meta))
        .route("/.well-known/oauth-authorization-server", get(server_meta))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .with_state(shared.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (shared, format!("{base}/mcp"))
}

/// A browser: fetch the authorize URL and follow its redirect to the loopback
/// callback.
struct FakeBrowser;

impl Opener for FakeBrowser {
    fn open(&self, url: &Url) -> Result<()> {
        let url = url.clone();
        tokio::spawn(async move {
            reqwest::Client::new().get(url).send().await.unwrap();
        });
        Ok(())
    }
}

/// A browser that never comes back, for the revoked-grant test where no login
/// may be attempted.
struct NoBrowser;

impl Opener for NoBrowser {
    fn open(&self, _: &Url) -> Result<()> {
        panic!("a browser must not be opened");
    }
}

fn client(dir: &std::path::Path, opener: Box<dyn Opener>) -> Client {
    Client::new(Store::at(dir), opener).unwrap()
}

fn expire(dir: &std::path::Path) {
    let path = dir.join("credentials.json");
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for g in doc["grants"].as_object_mut().unwrap().values_mut() {
        g["expires_at"] = 1.into();
    }
    std::fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
}

#[tokio::test]
async fn login_caches_a_refreshable_token_and_reuses_it() {
    let (server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));

    c.login(&resource, &[]).await.unwrap();
    assert!(c.is_signed_in(&resource).unwrap());
    {
        let s = server.lock().unwrap();
        let q = &s.authorizes[0];
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["resource"], resource);
        assert!(q["redirect_uri"].starts_with("http://127.0.0.1:"));
        assert_eq!(s.registrations, 1);
    }

    // Running again with a cached grant opens no browser and calls no endpoint.
    let again = client(dir.path(), Box::new(NoBrowser));
    let token = again.token(&resource).await.unwrap();
    assert_eq!(token.expose(), ACCESS_1);
    assert_eq!(server.lock().unwrap().authorizes.len(), 1);

    // The refresh token is cached: the grant is refresh-capable.
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(doc["grants"][&resource]["refresh_token"], REFRESH_1);
}

#[tokio::test]
async fn a_second_resource_reuses_the_registered_client() {
    let (server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    c.login(&resource, &[]).await.unwrap();
    c.login(&resource, &[]).await.unwrap();
    assert_eq!(server.lock().unwrap().registrations, 1);
}

#[tokio::test]
async fn token_for_a_resource_with_no_grant_goes_through_login() {
    let (server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    assert_eq!(c.token(&resource).await.unwrap().expose(), ACCESS_1);
    assert_eq!(server.lock().unwrap().authorizes.len(), 1);
}

#[tokio::test]
async fn an_expired_token_is_refreshed_and_the_refresh_token_kept() {
    let (server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[])
        .await
        .unwrap();
    expire(dir.path());

    let token = client(dir.path(), Box::new(NoBrowser))
        .token(&resource)
        .await
        .unwrap();
    assert_eq!(token.expose(), "access-token-two-SECRETVALUE");
    assert_eq!(server.lock().unwrap().refresh_calls, 1);

    // The refresh response named no refresh token; the old one is kept.
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(doc["grants"][&resource]["refresh_token"], REFRESH_1);
}

#[tokio::test]
async fn a_revoked_grant_says_to_log_in_again_and_leaks_nothing() {
    let (server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[])
        .await
        .unwrap();
    expire(dir.path());
    server.lock().unwrap().revoke = true;

    let err = client(dir.path(), Box::new(NoBrowser))
        .token(&resource)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::LoginRequired { .. }), "{err:?}");
    assert!(err.to_string().contains("otto login"), "{err}");
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("SECRETVALUE"), "{text}");
    }
    // The dead grant is dropped, so the next run does not retry it forever.
    assert!(!client(dir.path(), Box::new(NoBrowser))
        .is_signed_in(&resource)
        .unwrap());
}

#[tokio::test]
async fn a_server_that_names_a_different_resource_is_refused() {
    let (_server, resource) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    // Same server, but the caller asks for a different path: its metadata says
    // it is `/mcp`, so a token for `/other` would have the wrong audience.
    let other = resource.replace("/mcp", "/other");
    let err = client(dir.path(), Box::new(NoBrowser))
        .login(&other, &[])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Discovery(_)), "{err:?}");
}

#[tokio::test]
async fn an_http_authorization_server_off_loopback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(NoBrowser))
        .login("http://example.com/mcp", &[])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Discovery(_)), "{err:?}");
}

#[test]
fn credentials_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path().join("cfg"));
    store.put_client("https://auth.example", "id").unwrap();
    let mode = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.path().join("cfg")), 0o700);
    assert_eq!(mode(dir.path().join("cfg/credentials.json")), 0o600);
}

#[test]
fn a_secret_cannot_be_formatted_and_a_file_sink_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let secret = Secret::new("srv_THE-SECRET");
    assert!(!format!("{secret} {secret:?}").contains("THE-SECRET"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    // An existing, world-readable file must be narrowed before it is written.
    std::fs::write(&path, "old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut terminal = Vec::new();
    secret
        .deliver(&Sink::File(path.clone()), &mut terminal)
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "srv_THE-SECRET\n");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The terminal is told where the secret went, not what it is.
    assert!(!String::from_utf8(terminal).unwrap().contains("THE-SECRET"));

    let mut terminal = Vec::new();
    secret.deliver(&Sink::Terminal, &mut terminal).unwrap();
    assert_eq!(String::from_utf8(terminal).unwrap(), "srv_THE-SECRET\n");
}
