//! Test harness: the assembled router, driven the way a browser drives it.
//!
//! Requests go through `tower::ServiceExt::oneshot` against the real router
//! rather than calling handlers directly, so extractors, path matching, method
//! routing, status codes, and `Set-Cookie` are all under test. A handler tested
//! in isolation cannot tell you that its route is mounted, that its extractor
//! resolves, or that its `404` is not a `403`.

#![allow(dead_code)]

use axum::body::Body;
use axum::Router;
use base64::Engine;
use http::{Request, Response, StatusCode};
use otto_core::orgs::OrgsExt;
use otto_core::orgs::Role;
use otto_tenant::crypto::Cipher;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use otto_web::{AppState, Config};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::SoftToken;
use webauthn_authenticator_rs::WebauthnAuthenticator;

/// Two resource servers, because the authorization server serves every one in
/// the registry and a test with a single one cannot tell "the audience came
/// from the request" from "the audience is a constant".
pub const RESOURCE: &str = "https://things.otto.test/mcp";
pub const RESOURCE_NAME: &str = "Things";
pub const RESOURCE_SCOPES: &[&str] = &["things:read", "things:write", "org:admin"];
pub const RESOURCE_DEFAULT_SCOPES: &[&str] = &["things:read"];
pub const OTHER_RESOURCE: &str = "https://widgets.otto.test/mcp";
pub const OTHER_RESOURCE_NAME: &str = "Widgets";
pub const OTHER_RESOURCE_SCOPES: &[&str] = &["widgets:read", "widgets:write"];
pub const OTHER_RESOURCE_DEFAULT_SCOPES: &[&str] = &["widgets:read"];
pub const PUBLIC_URL: &str = "https://otto.test";

/// Register [`RESOURCE`] with the authorization server's registry, as a
/// resource server does at every startup. Without the row every
/// `/oauth/authorize`, token, refresh, and PAT request for it is refused as
/// `invalid_target`.
pub async fn register_resource(db: &Db) {
    otto_auth::resources::register(
        db,
        otto_auth::resources::ResourceServerSpec {
            resource_uri: RESOURCE,
            name: RESOURCE_NAME,
            scopes: RESOURCE_SCOPES,
            default_scopes: RESOURCE_DEFAULT_SCOPES,
        },
    )
    .await
    .expect("register the resource server");
}

/// Register [`OTHER_RESOURCE`] as well, so the registry holds two.
pub async fn register_other_resource(db: &Db) {
    otto_auth::resources::register(
        db,
        otto_auth::resources::ResourceServerSpec {
            resource_uri: OTHER_RESOURCE,
            name: OTHER_RESOURCE_NAME,
            scopes: OTHER_RESOURCE_SCOPES,
            default_scopes: OTHER_RESOURCE_DEFAULT_SCOPES,
        },
    )
    .await
    .expect("register the second resource server");
}

pub struct Harness {
    pub db: Db,
    pub router: Router,
    pub cipher: Cipher,
}

fn assemble(db: Db, config: Config) -> Harness {
    let webauthn = otto_web::relying_party(&config).expect("relying party");
    let state = AppState::new(db.clone(), cipher(), webauthn, config);
    Harness {
        db,
        router: otto_web::router(state),
        cipher: cipher(),
    }
}

pub async fn harness(pool: PgPool) -> Harness {
    let db = Db::from_pool(pool);
    register_resource(&db).await;
    assemble(db, Config::new(PUBLIC_URL))
}

/// A harness with two registered resource servers.
pub async fn harness_with_two_resources(pool: PgPool) -> Harness {
    let h = harness(pool).await;
    register_other_resource(&h.db).await;
    h
}

pub fn cipher() -> Cipher {
    Cipher::from_base64_key(&base64::engine::general_purpose::STANDARD.encode([9u8; 32])).unwrap()
}

/// A response, already read into memory so a test can assert on both the status
/// and the body without threading a body future through every assertion.
pub struct Reply {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Value,
    /// The raw body, for the endpoints that answer with HTML.
    pub text: String,
}

impl Reply {
    /// The session cookie value this response set, if it set one.
    pub fn session_cookie(&self) -> Option<String> {
        self.headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| {
                let value = v.strip_prefix("__Host-otto_session=")?;
                let value = value.split(';').next()?;
                (!value.is_empty()).then(|| value.to_string())
            })
    }

    pub fn error_code(&self) -> Option<&str> {
        self.body.get("error")?.get("code")?.as_str()
    }

    /// Assert a status, printing the body when it does not match — a bare
    /// "expected 200, got 400" from an API test is a test that wastes an hour.
    pub fn expect(&self, status: StatusCode) -> &Self {
        assert_eq!(
            self.status,
            status,
            "unexpected status; body was: {}",
            if self.text.is_empty() {
                "(empty)"
            } else {
                &self.text
            }
        );
        self
    }
}

/// A request under construction.
pub struct Call {
    method: http::Method,
    uri: String,
    session: Option<String>,
    body: Option<Body>,
    content_type: Option<&'static str>,
    headers: Vec<(&'static str, String)>,
}

impl Call {
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(http::Method::GET, uri)
    }
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(http::Method::POST, uri)
    }
    pub fn put(uri: impl Into<String>) -> Self {
        Self::new(http::Method::PUT, uri)
    }
    pub fn patch(uri: impl Into<String>) -> Self {
        Self::new(http::Method::PATCH, uri)
    }
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(http::Method::DELETE, uri)
    }

    fn new(method: http::Method, uri: impl Into<String>) -> Self {
        Self {
            method,
            uri: uri.into(),
            session: None,
            body: None,
            content_type: None,
            headers: Vec::new(),
        }
    }

    /// An arbitrary request header.
    ///
    /// Added for `Accept-Language`, which is the only input the browser-facing
    /// pages take that is neither a cookie, a path, nor a body — and the one
    /// the consent screen's language falls back to.
    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(Body::from(serde_json::to_vec(&body).unwrap()));
        self.content_type = Some("application/json");
        self
    }

    /// A form-encoded body — what the OAuth endpoints take, per RFC 6749.
    pub fn form(mut self, pairs: &[(&str, &str)]) -> Self {
        let encoded = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.body = Some(Body::from(encoded));
        self.content_type = Some("application/x-www-form-urlencoded");
        self
    }

    pub fn with_session(mut self, token: &str) -> Self {
        self.session = Some(token.to_string());
        self
    }

    pub async fn send(self, router: &Router) -> Reply {
        let mut builder = Request::builder().method(self.method).uri(&self.uri);

        if let Some(ct) = self.content_type {
            builder = builder.header(http::header::CONTENT_TYPE, ct);
        }
        if let Some(token) = &self.session {
            builder = builder.header(
                http::header::COOKIE,
                format!("__Host-otto_session={token}; theme=dark"),
            );
        }
        // A browser attaches `Origin` to every non-GET it sends, and the
        // cross-site guard refuses a cookie-bearing write without one. A test
        // that cares about the origin sets its own header; the rest get the
        // honest one.
        if self.session.is_some()
            && !self.headers.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("origin") || name.eq_ignore_ascii_case("sec-fetch-site")
            })
        {
            builder = builder.header(http::header::ORIGIN, PUBLIC_URL);
        }
        for (name, value) in &self.headers {
            builder = builder.header(*name, value.as_str());
        }

        let request = builder.body(self.body.unwrap_or_else(Body::empty)).unwrap();
        let response: Response<Body> = router.clone().oneshot(request).await.unwrap();

        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        Reply {
            status,
            headers,
            body,
            text,
        }
    }
}

fn urlencode(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Account fixtures
// ---------------------------------------------------------------------------

/// An account that has been through the whole front door: signed up, verified,
/// enrolled, signed in.
pub struct Account {
    pub user: UserId,
    pub email: String,
    pub session: String,
    /// The account's authenticator, kept so a test can sign in again.
    pub auth: Authenticator,
    /// base64url, for `allowCredentials`.
    pub credential_id: String,
}

/// A software authenticator, standing in for a browser's.
///
/// `SoftToken` produces real COSE signatures over the challenges this server
/// issued, so these tests exercise the actual verification path. It cannot hold
/// *discoverable* credentials — see `otto-auth`'s `tests/passkeys.rs` for the full
/// note — so [`soften`] and [`offer`] adjust what is handed to it. Only what
/// the fake authenticator sees is adjusted; every server-side step is the
/// production one.
pub type Authenticator = WebauthnAuthenticator<SoftToken>;

pub fn authenticator() -> Authenticator {
    WebauthnAuthenticator::new(SoftToken::new(true).unwrap().0)
}

/// Drop the resident-key requirement before handing a challenge to SoftToken.
fn soften(mut challenge: Value) -> Value {
    if let Some(sel) = challenge
        .get_mut("publicKey")
        .and_then(|pk| pk.get_mut("authenticatorSelection"))
    {
        sel["requireResidentKey"] = Value::Bool(false);
        sel["residentKey"] = Value::Null;
    }
    challenge
}

/// Name a credential in `allowCredentials`, so a token holding no discoverable
/// credentials can find the right key. Production sends this list empty.
fn offer(mut challenge: Value, credential_id: &str) -> Value {
    challenge["publicKey"]["allowCredentials"] = serde_json::json!([
        { "type": "public-key", "id": credential_id }
    ]);
    challenge
}

/// Create an account the way a person does: register a passkey, get a session.
///
/// Deliberately not a shortcut that inserts rows. The point of most of these
/// tests is that the sequence works end to end, and a fixture that skipped it
/// would test a state the product cannot reach.
pub async fn onboard(h: &Harness, email: &str) -> Account {
    let mut auth = authenticator();

    let started = Call::post("/api/auth/signup/start").send(&h.router).await;
    started.expect(StatusCode::OK);
    assert!(
        started.session_cookie().is_none(),
        "a challenge must not open a session"
    );

    let ceremony_id = started.body["ceremonyId"].as_str().unwrap().to_string();
    let challenge: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(soften(started.body["challenge"].clone())).unwrap();

    let credential = auth
        .do_registration(
            webauthn_rs::prelude::Url::parse(PUBLIC_URL).unwrap(),
            challenge,
        )
        .expect("the authenticator refused the registration challenge");

    let finished = Call::post("/api/auth/signup/finish")
        .json(serde_json::json!({
            "ceremonyId": ceremony_id,
            "credential": credential,
            "nickname": "test key",
        }))
        .send(&h.router)
        .await;
    finished.expect(StatusCode::OK);

    let session = finished
        .session_cookie()
        .expect("finishing signup must open the account's first session");

    let user: UserId = finished.body["user"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Every test that predates passkeys assumes an addressable account, and an
    // invitation names an address — so set one here rather than in each test.
    Call::patch("/api/me")
        .with_session(&session)
        .json(serde_json::json!({ "email": email, "name": "Test User" }))
        .send(&h.router)
        .await
        .expect(StatusCode::OK);

    let credential_id = credential_id_of(h, user).await;

    Account {
        user,
        email: email.to_string(),
        session,
        auth,
        credential_id,
    }
}

/// The base64url credential id of an account's first passkey, for `offer`.
async fn credential_id_of(h: &Harness, user: UserId) -> String {
    use base64::Engine;
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT credential_id FROM passkeys WHERE user_id = $1 ORDER BY created_at LIMIT 1",
    )
    .bind(user)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Drive a registration ceremony to a `…/finish` endpoint, merging any extra
/// fields the endpoint needs (a claim code, for instance).
pub async fn finish_registration(
    h: &Harness,
    auth: &mut Authenticator,
    finish_path: &str,
    started: &Value,
    extra: Value,
) -> Reply {
    let ceremony_id = started["ceremonyId"].as_str().unwrap().to_string();
    let challenge: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(soften(started["challenge"].clone())).unwrap();

    let credential = auth
        .do_registration(
            webauthn_rs::prelude::Url::parse(PUBLIC_URL).unwrap(),
            challenge,
        )
        .expect("the authenticator refused the registration challenge");

    let mut body = serde_json::json!({
        "ceremonyId": ceremony_id,
        "credential": credential,
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }

    Call::post(finish_path.to_string())
        .json(body)
        .send(&h.router)
        .await
}

/// Drive a registration ceremony far enough to produce a real credential,
/// without submitting it anywhere.
///
/// For a test that needs to inspect or pre-empt the credential (its raw id,
/// say) before a `…/finish` endpoint ever sees it — [`finish_registration`]
/// above drives the ceremony and posts it in one step, which cannot express
/// that. Returns the ceremony id alongside the credential since callers of
/// this need both to build their own `…/finish` request body.
pub fn register_credential(
    auth: &mut Authenticator,
    started: &Value,
) -> (String, webauthn_rs::prelude::RegisterPublicKeyCredential) {
    let ceremony_id = started["ceremonyId"].as_str().unwrap().to_string();
    let challenge: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(soften(started["challenge"].clone())).unwrap();

    let credential = auth
        .do_registration(
            webauthn_rs::prelude::Url::parse(PUBLIC_URL).unwrap(),
            challenge,
        )
        .expect("the authenticator refused the registration challenge");

    (ceremony_id, credential)
}

/// Sign in again with an account's own authenticator.
pub async fn sign_in(h: &Harness, account: &mut Account) -> Reply {
    let credential_id = account.credential_id.clone();
    present_credential(h, &mut account.auth, &credential_id, None).await
}

/// Drive a whole authentication ceremony and present the result to
/// `login/finish`, as though the request arrived from `from`.
pub async fn present_credential(
    h: &Harness,
    auth: &mut Authenticator,
    credential_id: &str,
    from: Option<&str>,
) -> Reply {
    let started = Call::post("/api/auth/login/start").send(&h.router).await;
    started.expect(StatusCode::OK);

    let ceremony_id = started.body["ceremonyId"].as_str().unwrap().to_string();
    let challenge: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(offer(started.body["challenge"].clone(), credential_id)).unwrap();

    let credential = auth
        .do_authentication(
            webauthn_rs::prelude::Url::parse(PUBLIC_URL).unwrap(),
            challenge,
        )
        .expect("the authenticator refused the sign-in challenge");

    let mut call = Call::post("/api/auth/login/finish")
        .json(serde_json::json!({ "ceremonyId": ceremony_id, "credential": credential }));
    if let Some(ip) = from {
        call = call.header(CLIENT_IP_HEADER, ip);
    }
    call.send(&h.router).await
}

/// A key an authenticator will sign with and this server has no row for.
///
/// Registered against a signup ceremony that is deliberately never finished,
/// so `passkeys` has nothing to resolve it to. That is what a stranger probing
/// `login/finish` looks like — except the signature is genuine, so a refusal
/// can only be the lookup and never the verification.
pub async fn unregistered_credential(h: &Harness) -> (Authenticator, String) {
    use base64::Engine;

    let mut auth = authenticator();

    let started = Call::post("/api/auth/signup/start").send(&h.router).await;
    started.expect(StatusCode::OK);
    let challenge: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(soften(started.body["challenge"].clone())).unwrap();

    let credential = auth
        .do_registration(
            webauthn_rs::prelude::Url::parse(PUBLIC_URL).unwrap(),
            challenge,
        )
        .expect("the authenticator refused the registration challenge");

    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential.raw_id.as_ref());
    (auth, id)
}

/// The client-address header [`harness_behind_proxy`] is configured to trust.
///
/// A real one: on Fly the proxy *overwrites* `fly-client-ip`, which is the
/// only property that makes a throttle keyed on it worth anything.
pub const CLIENT_IP_HEADER: &str = "fly-client-ip";

/// A harness whose database cannot be reached, for outage behavior.
pub async fn harness_with_unreachable_db(_pool: PgPool) -> Harness {
    let unreachable = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .expect("lazy pool");
    assemble(Db::from_pool(unreachable), Config::new(PUBLIC_URL))
}

/// A harness deployed the way production is — behind a proxy that stamps the
/// caller's address onto every request.
///
/// The plain [`harness`] configures no header, and `oneshot` attaches no
/// `ConnectInfo`, so under it every request arrives with **no** client
/// address and every throttle keyed on one is silently a no-op. A test about
/// rate limiting has to be able to say where the request came from.
pub async fn harness_behind_proxy(pool: PgPool) -> Harness {
    let db = Db::from_pool(pool);
    register_resource(&db).await;
    let mut config = Config::new(PUBLIC_URL);
    config.client_ip_header = Some(CLIENT_IP_HEADER.into());
    assemble(db, config)
}

/// An org with `owner` as its owner.
pub async fn org_with_owner(h: &Harness, slug: &str, owner: &Account) -> OrgId {
    let created = Call::post("/api/orgs")
        .with_session(&owner.session)
        .json(serde_json::json!({ "slug": slug, "name": slug }))
        .send(&h.router)
        .await;
    created.expect(StatusCode::CREATED);
    created.body["id"].as_str().unwrap().parse().unwrap()
}

/// Add someone to an org directly, for tests about what a role may do rather
/// than about how someone got it.
pub async fn add_member(h: &Harness, org: OrgId, user: UserId, role: Role) {
    h.db.add_member(org, user, role).await.unwrap();
}
