//! Login, refresh, and failure paths against a mock authorization server that
//! behaves like savvagent-auth where it matters: PKCE S256 is checked, every refresh
//! rotates the refresh token, and presenting a consumed refresh token revokes
//! the whole family.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use savvagent_client::{Client, Error, LoginOutcome, Opener, Result, Store};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Default)]
struct Server {
    base: String,
    registrations: u32,
    authorizes: Vec<HashMap<String, String>>,
    /// code -> (challenge, resource, scope)
    codes: HashMap<String, (String, String, String)>,
    /// refresh token -> (resource, consumed)
    refresh: HashMap<String, (String, bool)>,
    minted: u32,
    refresh_calls: u32,
    /// Set when a consumed refresh token was presented, as savvagent-auth does.
    family_revoked: bool,
    /// The metadata names a different issuer.
    wrong_issuer: bool,
    /// The code exchange fails with this description.
    token_error: Option<String>,
    /// Token responses leave out `scope`, as RFC 6749 allows when it is the
    /// scope asked for.
    omit_scope: bool,
    /// Grant only this scope, whatever was asked for.
    grant_only: Option<String>,
    /// The authorization server's `scopes_supported`, when it says.
    server_scopes: Option<Vec<String>>,
    /// The first resource's `scopes_supported`, when it says.
    resource_scopes: Option<Vec<String>>,
    /// `savvagent_authorize_resources_max`, when the server says.
    max_resources: Option<usize>,
    /// Resources the person leaves out on a multi-resource consent screen.
    decline: Vec<String>,
    /// Resources kept but granted nothing, named as `refused_resource`.
    refuse: Vec<String>,
    /// The `resource` values of each authorize request, in order.
    resource_lists: Vec<Vec<String>>,
}

type Shared = Arc<Mutex<Server>>;

fn oauth_error(description: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": description,
            // Would leak if an error ever echoed the body.
            "debug_token": "leaked-SECRETVALUE",
        })),
    )
}

async fn resource_meta_root(State(s): State<Shared>) -> Json<serde_json::Value> {
    let (base, scopes) = {
        let s = s.lock().unwrap();
        (s.base.clone(), s.resource_scopes.clone())
    };
    let mut meta =
        serde_json::json!({ "resource": format!("{base}/mcp"), "authorization_servers": [base] });
    if let Some(scopes) = scopes {
        meta["scopes_supported"] = scopes.into();
    }
    Json(meta)
}

/// The RFC 9728 path-inserted form, for a second resource on the same host.
async fn resource_meta_other(State(s): State<Shared>) -> Json<serde_json::Value> {
    let base = s.lock().unwrap().base.clone();
    Json(
        serde_json::json!({ "resource": format!("{base}/other"), "authorization_servers": [base] }),
    )
}

async fn server_meta(State(s): State<Shared>) -> Json<serde_json::Value> {
    let s = s.lock().unwrap();
    let base = s.base.clone();
    let issuer = if s.wrong_issuer {
        "https://evil.example".to_owned()
    } else {
        base.clone()
    };
    let mut meta = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
    });
    if let Some(scopes) = &s.server_scopes {
        meta["scopes_supported"] = scopes.clone().into();
    }
    if let Some(max) = s.max_resources {
        meta["savvagent_authorize_resources_max"] = max.into();
    }
    Json(meta)
}

async fn register(
    State(s): State<Shared>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    s.lock().unwrap().registrations += 1;
    assert_eq!(body["redirect_uris"][0], "http://127.0.0.1/callback");
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "client_id": "sav_client_test" })),
    )
}

/// One code, or for a request naming several resources one `code` and its
/// `resource` per resource not in `decline`, as savvagent-auth answers.
async fn authorize(State(s): State<Shared>, RawQuery(raw): RawQuery) -> Redirect {
    let raw = raw.unwrap_or_default();
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let resources: Vec<String> = pairs
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.clone())
        .collect();
    let q: HashMap<String, String> = pairs.into_iter().collect();
    let mut s = s.lock().unwrap();
    let scope = q.get("scope").cloned().unwrap_or_else(|| "mcp".into());
    let mut redirect = format!("{}?", q["redirect_uri"]);
    if resources.len() == 1 {
        s.minted += 1;
        let code = format!("code-{}", s.minted);
        s.codes.insert(
            code.clone(),
            (q["code_challenge"].clone(), resources[0].clone(), scope),
        );
        redirect.push_str(&format!("code={code}&"));
    } else {
        for resource in &resources {
            if s.decline.contains(resource) {
                continue;
            }
            if s.refuse.contains(resource) {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(resource.as_bytes()).collect();
                redirect.push_str(&format!("refused_resource={encoded}&"));
                continue;
            }
            s.minted += 1;
            let code = format!("code-{}", s.minted);
            s.codes.insert(
                code.clone(),
                (q["code_challenge"].clone(), resource.clone(), scope.clone()),
            );
            let encoded: String =
                url::form_urlencoded::byte_serialize(resource.as_bytes()).collect();
            redirect.push_str(&format!("code={code}&resource={encoded}&"));
        }
    }
    redirect.push_str(&format!("state={}", q["state"]));
    s.resource_lists.push(resources);
    s.authorizes.push(q);
    Redirect::to(&redirect)
}

fn mint(s: &mut Server, resource: &str, scope: &str) -> serde_json::Value {
    s.minted += 1;
    let n = s.minted;
    let refresh = format!("rt-{n}-SECRETVALUE");
    s.refresh
        .insert(refresh.clone(), (resource.to_owned(), false));
    serde_json::json!({
        "access_token": format!("at-{n}-{resource}-SECRETVALUE"),
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "scope": scope,
    })
}

async fn token(
    State(s): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut s = s.lock().unwrap();
    match f["grant_type"].as_str() {
        "authorization_code" => {
            if let Some(desc) = s.token_error.clone() {
                return oauth_error(&desc);
            }
            let (challenge, resource, scope) = s.codes.remove(&f["code"]).expect("known code");
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(f["code_verifier"].as_bytes()));
            if computed != challenge {
                return oauth_error("PKCE verification failed");
            }
            assert_eq!(f["resource"], resource);
            let scope = s.grant_only.clone().unwrap_or(scope);
            let mut body = mint(&mut s, &resource, &scope);
            if s.omit_scope {
                body.as_object_mut().unwrap().remove("scope");
            }
            (StatusCode::OK, Json(body))
        }
        "refresh_token" => {
            s.refresh_calls += 1;
            if s.family_revoked {
                return oauth_error("refresh token was revoked");
            }
            let presented = f["refresh_token"].clone();
            let Some((resource, consumed)) = s.refresh.get(&presented).cloned() else {
                return oauth_error("unknown refresh token");
            };
            if consumed {
                s.family_revoked = true;
                return oauth_error(
                    "refresh token was already used; the token family has been revoked",
                );
            }
            s.refresh.insert(presented, (resource.clone(), true));
            assert_eq!(f["resource"], resource, "refresh must keep the audience");
            (StatusCode::OK, Json(mint(&mut s, &resource, "mcp")))
        }
        other => panic!("unexpected grant {other}"),
    }
}

/// The mock, and its two resources: `/mcp` (metadata at the origin root) and
/// `/other` (metadata at the path-inserted URL).
async fn spawn() -> (Shared, String, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let shared: Shared = Arc::new(Mutex::new(Server {
        base: base.clone(),
        ..Default::default()
    }));
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_meta_root),
        )
        .route(
            "/.well-known/oauth-protected-resource/other",
            get(resource_meta_other),
        )
        .route("/.well-known/oauth-authorization-server", get(server_meta))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .with_state(shared.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (shared, format!("{base}/mcp"), format!("{base}/other"))
}

/// A browser: fetch the authorize URL and follow its redirect to the loopback
/// callback.
struct FakeBrowser;

impl Opener for FakeBrowser {
    fn open(&self, url: &Url) -> Result<()> {
        let url = url.clone();
        tokio::spawn(async move {
            let _ = reqwest::Client::new().get(url).send().await;
        });
        Ok(())
    }
}

/// A local process that opens many connections to the callback port first
/// and sends nothing on any of them, then the real browser.
struct StallThenBrowser;

const STALLED_CONNECTIONS: usize = 64;

impl Opener for StallThenBrowser {
    fn open(&self, url: &Url) -> Result<()> {
        let url = url.clone();
        let redirect = url
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| Url::parse(&v).unwrap())
            .unwrap();
        let port = redirect.port().unwrap();
        tokio::spawn(async move {
            let mut stalled = Vec::new();
            for _ in 0..STALLED_CONNECTIONS {
                stalled.push(
                    tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap(),
                );
            }
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stalled);
            });
            let _ = reqwest::Client::new().get(url).send().await;
        });
        Ok(())
    }
}

/// A browser must not be opened.
struct NoBrowser;

impl Opener for NoBrowser {
    fn open(&self, _: &Url) -> Result<()> {
        panic!("a browser must not be opened");
    }
}

fn client(dir: &std::path::Path, opener: Box<dyn Opener>) -> Client {
    Client::new(Store::at(dir), opener).unwrap()
}

fn credentials(dir: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("credentials.json")).unwrap()).unwrap()
}

fn expire(dir: &std::path::Path) {
    let mut doc = credentials(dir);
    for g in doc["grants"].as_object_mut().unwrap().values_mut() {
        g["expires_at"] = 1.into();
    }
    std::fs::write(
        dir.join("credentials.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn login_caches_a_refreshable_token_and_a_second_login_reuses_it() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();

    let first = client(dir.path(), Box::new(FakeBrowser));
    assert_eq!(
        first.login(&resource, &[], false).await.unwrap(),
        LoginOutcome::SignedIn
    );
    {
        let s = server.lock().unwrap();
        let q = &s.authorizes[0];
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["resource"], resource);
        assert!(q["redirect_uri"].starts_with("http://127.0.0.1:"));
        assert_eq!(s.registrations, 1);
    }
    assert!(
        credentials(dir.path())["grants"][&resource]["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("rt-")
    );

    // `savctl login` again: no browser, no new authorization.
    let again = client(dir.path(), Box::new(NoBrowser));
    assert_eq!(
        again.login(&resource, &[], false).await.unwrap(),
        LoginOutcome::AlreadySignedIn
    );
    assert_eq!(server.lock().unwrap().authorizes.len(), 1);
}

#[tokio::test]
async fn force_and_a_new_scope_each_run_the_browser_again() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    c.login(&resource, &[], false).await.unwrap();

    assert_eq!(
        c.login(&resource, &[], true).await.unwrap(),
        LoginOutcome::SignedIn
    );
    let wanted = vec!["keys:issue".to_owned()];
    assert_eq!(
        c.login(&resource, &wanted, false).await.unwrap(),
        LoginOutcome::SignedIn
    );
    // Now granted: the same request is satisfied from the cache.
    let cached = client(dir.path(), Box::new(NoBrowser));
    assert_eq!(
        cached.login(&resource, &wanted, false).await.unwrap(),
        LoginOutcome::AlreadySignedIn
    );

    let s = server.lock().unwrap();
    assert_eq!(s.authorizes.len(), 3);
    assert_eq!(s.authorizes[2]["scope"], "keys:issue");
    assert_eq!(s.registrations, 1, "the registered client is reused");
}

#[tokio::test]
async fn each_resource_gets_a_token_for_its_own_audience() {
    let (server, mcp, other) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));

    let a = c.token(&mcp).await.unwrap();
    let b = c.token(&other).await.unwrap();
    assert!(a.expose().ends_with(&format!("{mcp}-SECRETVALUE")));
    assert!(b.expose().ends_with(&format!("{other}-SECRETVALUE")));
    {
        let s = server.lock().unwrap();
        let resources: Vec<_> = s.authorizes.iter().map(|q| q["resource"].clone()).collect();
        assert_eq!(resources, [mcp.clone(), other.clone()]);
    }

    // Refreshing keeps each audience (the mock asserts the `resource` sent).
    expire(dir.path());
    let a2 = client(dir.path(), Box::new(NoBrowser))
        .token(&mcp)
        .await
        .unwrap();
    let b2 = client(dir.path(), Box::new(NoBrowser))
        .token(&other)
        .await
        .unwrap();
    assert!(a2.expose().ends_with(&format!("{mcp}-SECRETVALUE")));
    assert!(b2.expose().ends_with(&format!("{other}-SECRETVALUE")));
    assert_eq!(server.lock().unwrap().refresh_calls, 2);
}

#[tokio::test]
async fn refresh_stores_the_rotated_refresh_token() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap();
    let before = credentials(dir.path())["grants"][&resource]["refresh_token"].clone();

    for _ in 0..3 {
        expire(dir.path());
        client(dir.path(), Box::new(NoBrowser))
            .token(&resource)
            .await
            .unwrap();
    }
    let after = credentials(dir.path())["grants"][&resource]["refresh_token"].clone();
    assert_ne!(before, after);
    let s = server.lock().unwrap();
    assert_eq!(s.refresh_calls, 3);
    // Had the old refresh token been kept, the second refresh would have
    // replayed it and revoked the family.
    assert!(!s.family_revoked);
}

#[tokio::test]
async fn concurrent_refreshes_never_replay_a_refresh_token() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap();
    expire(dir.path());

    // Separate clients, separate lock file handles: as two `savctl` processes.
    let clients: Vec<_> = (0..4)
        .map(|_| client(dir.path(), Box::new(NoBrowser)))
        .collect();
    let tokens = futures_join(&clients, &resource).await;
    for t in &tokens {
        assert_eq!(t, &tokens[0], "all callers see the one refreshed token");
    }
    let s = server.lock().unwrap();
    assert_eq!(s.refresh_calls, 1, "only one caller refreshed");
    assert!(!s.family_revoked);
}

async fn futures_join(clients: &[Client], resource: &str) -> Vec<String> {
    let (a, b, c, d) = tokio::join!(
        clients[0].token(resource),
        clients[1].token(resource),
        clients[2].token(resource),
        clients[3].token(resource),
    );
    [a, b, c, d]
        .into_iter()
        .map(|t| t.unwrap().expose().to_owned())
        .collect()
}

#[tokio::test]
async fn a_revoked_grant_says_to_log_in_again_and_leaks_nothing() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap();
    expire(dir.path());
    server.lock().unwrap().family_revoked = true;

    let err = client(dir.path(), Box::new(NoBrowser))
        .token(&resource)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::LoginRequired { .. }), "{err:?}");
    assert!(err.to_string().contains("savctl login"), "{err}");
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("SECRETVALUE"), "{text}");
    }
    // The dead grant is dropped, so the next run does not retry it forever.
    assert!(!client(dir.path(), Box::new(NoBrowser))
        .is_signed_in(&resource)
        .unwrap());
}

#[tokio::test]
async fn a_token_error_is_reported_cleaned_and_without_the_body() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().token_error = Some("bad\u{1b}[2J code\u{7}".into());
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("invalid_grant bad[2J code"), "{text}");
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(!text.contains("SECRETVALUE"), "{text}");
}

#[tokio::test]
async fn a_stalled_local_connection_does_not_hold_up_the_callback() {
    let (_server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(StallThenBrowser));
    tokio::time::timeout(Duration::from_secs(3), c.login(&resource, &[], false))
        .await
        .expect("login must not wait on the stalled connection")
        .unwrap();
}

#[tokio::test]
async fn metadata_naming_another_issuer_is_refused() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().wrong_issuer = true;
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(NoBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Discovery(_)), "{err:?}");
}

#[tokio::test]
async fn a_server_that_names_a_different_resource_is_refused() {
    let (_server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    // The root metadata says it is `/mcp`; a token for `/nope` would have the
    // wrong audience.
    let nope = resource.replace("/mcp", "/nope");
    let err = client(dir.path(), Box::new(NoBrowser))
        .login(&nope, &[], false)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Discovery(_)), "{err:?}");
}

#[tokio::test]
async fn an_http_authorization_server_off_loopback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(NoBrowser))
        .login("http://example.com/mcp", &[], false)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Discovery(_)), "{err:?}");
}

// Windows DACLs are checked by `private_fs`'s own tests.
#[cfg(unix)]
#[tokio::test]
async fn credentials_are_owner_only_and_an_existing_dir_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let (_server, resource, _) = spawn().await;

    let root = tempfile::tempdir().unwrap();
    let created = root.path().join("cfg");
    client(&created, Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap();
    assert_eq!(mode(created.clone()), 0o700);
    assert_eq!(mode(created.join("credentials.json")), 0o600);
    assert_eq!(mode(created.join("credentials.lock")), 0o600);
    // Only the credentials and the lock: no temporary file left behind.
    assert_eq!(std::fs::read_dir(&created).unwrap().count(), 2);

    let existing = root.path().join("home");
    std::fs::create_dir(&existing).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
    client(&existing, Box::new(FakeBrowser))
        .login(&resource, &[], false)
        .await
        .unwrap();
    assert_eq!(mode(existing.clone()), 0o755);
    assert_eq!(mode(existing.join("credentials.json")), 0o600);
}

#[tokio::test]
async fn asking_for_another_scope_keeps_the_ones_granted() {
    let (server, resource, _) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    c.login(&resource, &["flags:read".to_owned()], false)
        .await
        .unwrap();
    c.token_with_scopes(&resource, &["keys:issue".to_owned()])
        .await
        .unwrap();
    assert_eq!(
        server.lock().unwrap().authorizes[1]["scope"],
        "flags:read keys:issue"
    );
    // Covered now: no browser.
    let cached = client(dir.path(), Box::new(NoBrowser));
    cached
        .token_with_scopes(&resource, &["keys:issue".to_owned()])
        .await
        .unwrap();
    assert_eq!(server.lock().unwrap().authorizes.len(), 2);
}

#[tokio::test]
async fn a_token_response_without_scope_grants_what_was_asked() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().omit_scope = true;
    let dir = tempfile::tempdir().unwrap();
    let wanted = vec!["keys:issue".to_owned()];
    client(dir.path(), Box::new(FakeBrowser))
        .login(&resource, &wanted, false)
        .await
        .unwrap();
    // Without the fallback the stored scope is empty and this opens a browser.
    assert_eq!(
        client(dir.path(), Box::new(NoBrowser))
            .login(&resource, &wanted, false)
            .await
            .unwrap(),
        LoginOutcome::AlreadySignedIn
    );
}

#[tokio::test]
async fn a_scope_the_server_did_not_grant_is_reported_before_any_call() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().grant_only = Some("flags:read".into());
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(FakeBrowser))
        .token_with_scopes(&resource, &["keys:issue".to_owned()])
        .await
        .unwrap_err();
    let Error::InsufficientScope { message, .. } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(message, "the sign-in was not granted keys:issue");
}

#[tokio::test]
async fn a_scope_the_server_does_not_offer_is_refused_before_the_browser() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().server_scopes =
        Some(vec!["flags:read".to_owned(), "apps:admin".to_owned()]);
    let dir = tempfile::tempdir().unwrap();
    let wanted = vec!["flags:read".to_owned(), "keys:issue".to_owned()];
    let err = client(dir.path(), Box::new(NoBrowser))
        .login(&resource, &wanted, false)
        .await
        .unwrap_err();
    match &err {
        Error::ScopeNotOffered {
            scopes, offered, ..
        } => {
            assert_eq!(scopes, &["keys:issue"]);
            assert_eq!(offered, &["flags:read", "apps:admin"]);
        }
        other => panic!("{other:?}"),
    }
    let message = err.to_string();
    assert!(message.contains("does not offer keys:issue"), "{message}");
    assert!(message.contains("flags:read, apps:admin"), "{message}");
    assert!(server.lock().unwrap().authorizes.is_empty());
}

#[tokio::test]
async fn a_bare_login_asks_for_the_resources_scopes_but_not_issue_scopes() {
    let (server, resource, _) = spawn().await;
    server.lock().unwrap().resource_scopes = Some(
        ["flags:read", "apps:admin", "keys:issue"]
            .map(String::from)
            .to_vec(),
    );
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    assert_eq!(
        c.requestable_scopes(&resource).await.unwrap(),
        ["flags:read", "apps:admin"]
    );
    assert_eq!(
        c.missing_scopes(&resource, &["flags:read".to_owned()])
            .unwrap(),
        ["flags:read"],
        "nothing is cached yet"
    );
    c.login(&resource, &["flags:read".to_owned()], false)
        .await
        .unwrap();
    assert!(c
        .missing_scopes(&resource, &["flags:read".to_owned()])
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn offered_scopes_from_the_server_are_cleaned_and_capped() {
    let (server, resource, _) = spawn().await;
    let mut offered = vec!["evil\u{1b}[31m\u{7}red".to_owned()];
    offered.extend((0..50).map(|i| format!("scope{i}")));
    server.lock().unwrap().server_scopes = Some(offered);
    let dir = tempfile::tempdir().unwrap();
    let err = client(dir.path(), Box::new(NoBrowser))
        .login(&resource, &["keys:issue".to_owned()], false)
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(!message.chars().any(char::is_control), "{message:?}");
    assert!(message.contains("evil[31mred"), "{message}");
    assert!(message.contains("scope18"), "{message}");
    assert!(!message.contains("scope19"), "{message}");
}

fn requests(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
    pairs
        .iter()
        .map(|(r, scopes)| {
            (
                r.to_string(),
                scopes.iter().map(|s| s.to_string()).collect(),
            )
        })
        .collect()
}

#[tokio::test]
async fn one_browser_flow_signs_in_to_several_resources_when_the_server_offers_it() {
    let (server, mcp, other) = spawn().await;
    server.lock().unwrap().max_resources = Some(10);
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    let results = c
        .login_all(
            &requests(&[(&mcp, &["a:read"]), (&other, &["b:read"])]),
            false,
        )
        .await;
    let outcomes: Vec<_> = results
        .iter()
        .map(|(r, o)| (r.as_str(), *o.as_ref().unwrap()))
        .collect();
    assert_eq!(
        outcomes,
        [
            (mcp.as_str(), LoginOutcome::SignedIn),
            (other.as_str(), LoginOutcome::SignedIn)
        ]
    );
    {
        let s = server.lock().unwrap();
        assert_eq!(s.authorizes.len(), 1, "one consent screen");
        assert_eq!(s.resource_lists[0], [mcp.clone(), other.clone()]);
        assert_eq!(s.authorizes[0]["scope"], "a:read b:read");
    }
    // Each grant is for its own audience.
    let creds = credentials(dir.path());
    for r in [&mcp, &other] {
        let token = creds["grants"][r]["access_token"].as_str().unwrap();
        assert!(token.ends_with(&format!("-{r}-SECRETVALUE")), "{token}");
    }

    // Already covered: no browser at all.
    let again = client(dir.path(), Box::new(NoBrowser));
    let results = again
        .login_all(
            &requests(&[(&mcp, &["a:read"]), (&other, &["b:read"])]),
            false,
        )
        .await;
    assert!(results
        .iter()
        .all(|(_, o)| matches!(o, Ok(LoginOutcome::AlreadySignedIn))));
    assert_eq!(server.lock().unwrap().authorizes.len(), 1);
}

#[tokio::test]
async fn a_resource_left_out_on_the_consent_screen_is_declined_not_failed() {
    let (server, mcp, other) = spawn().await;
    {
        let mut s = server.lock().unwrap();
        s.max_resources = Some(10);
        s.decline = vec![other.clone()];
    }
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    let results = c
        .login_all(&requests(&[(&mcp, &[]), (&other, &[])]), false)
        .await;
    assert!(matches!(results[0].1, Ok(LoginOutcome::SignedIn)));
    assert!(matches!(results[1].1, Ok(LoginOutcome::Declined)));
    assert!(!c.is_signed_in(&other).unwrap());
}

/// A server that does not advertise the extension gets one ordinary request
/// per resource, as before.
#[tokio::test]
async fn without_the_extension_each_resource_gets_its_own_browser_flow() {
    let (server, mcp, other) = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    let results = c
        .login_all(&requests(&[(&mcp, &[]), (&other, &[])]), false)
        .await;
    assert!(results
        .iter()
        .all(|(_, o)| matches!(o, Ok(LoginOutcome::SignedIn))));
    let s = server.lock().unwrap();
    assert_eq!(s.authorizes.len(), 2);
    assert!(s.resource_lists.iter().all(|l| l.len() == 1));
}

/// One resource that cannot be discovered fails alone; the rest sign in.
#[tokio::test]
async fn one_undiscoverable_resource_does_not_stop_the_others() {
    let (server, mcp, other) = spawn().await;
    server.lock().unwrap().max_resources = Some(10);
    let nope = mcp.replace("/mcp", "/nope");
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    let results = c
        .login_all(
            &requests(&[(&mcp, &[]), (&nope, &[]), (&other, &[])]),
            false,
        )
        .await;
    assert!(matches!(results[0].1, Ok(LoginOutcome::SignedIn)));
    assert!(
        matches!(results[1].1, Err(Error::Discovery(_))),
        "{:?}",
        results[1].1
    );
    assert!(matches!(results[2].1, Ok(LoginOutcome::SignedIn)));
    assert_eq!(server.lock().unwrap().authorizes.len(), 1);
}

/// Kept on the consent screen but granted nothing is a failure, not a choice.
#[tokio::test]
async fn a_resource_the_server_refused_is_a_failure_not_declined() {
    let (server, mcp, other) = spawn().await;
    {
        let mut s = server.lock().unwrap();
        s.max_resources = Some(10);
        s.refuse = vec![other.clone()];
    }
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path(), Box::new(FakeBrowser));
    let results = c
        .login_all(&requests(&[(&mcp, &[]), (&other, &[])]), false)
        .await;
    assert!(matches!(results[0].1, Ok(LoginOutcome::SignedIn)));
    match &results[1].1 {
        Err(Error::Authorization(m)) => assert!(m.contains("could be granted"), "{m}"),
        other => panic!("{other:?}"),
    }
}
