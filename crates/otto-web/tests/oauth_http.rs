//! The authorization server over HTTP, driven the way a coding agent drives it.
//!
//! `otto-auth`'s own tests cover the protocol logic — PKCE, redirect matching,
//! rotation, audiences. These cover the transport around it, which is where an
//! agent actually fails: whether the discovery document says the right thing,
//! whether the consent form round-trips, whether an error comes back as a page
//! or as a redirect, and whether the token endpoint speaks form-encoded RFC 6749
//! rather than the JSON a modern instinct would reach for.

use otto_core::orgs::OrgsExt;
mod common;

use base64::Engine;
use common::{harness, onboard, org_with_owner, Call, Harness, RESOURCE};
use http::StatusCode;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const REDIRECT: &str = "http://127.0.0.1:1455/callback";

fn pkce() -> (String, String) {
    let verifier = "x".repeat(64);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Register a client the way an agent does, through the open endpoint.
async fn register(h: &Harness, name: &str, redirect: &str) -> String {
    let registered = Call::post("/oauth/register")
        .json(serde_json::json!({
            "client_name": name,
            "redirect_uris": [redirect],
        }))
        .send(&h.router)
        .await;
    registered.expect(StatusCode::CREATED);
    registered.body["client_id"].as_str().unwrap().to_string()
}

fn authorize_url(client_id: &str, challenge: &str, scope: &str, state: &str) -> String {
    authorize_url_to(REDIRECT, client_id, challenge, scope, state)
}

fn authorize_url_to(
    redirect: &str,
    client_id: &str,
    challenge: &str,
    scope: &str,
    state: &str,
) -> String {
    let redirect = redirect.replace(':', "%3A").replace('/', "%2F");
    format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect}\
         &code_challenge={challenge}&code_challenge_method=S256\
         &scope={}&state={state}",
        scope.replace(':', "%3A").replace(' ', "%20")
    )
}

/// Percent-encode a resource URI for a query string.
fn percent_encode(raw: &str) -> String {
    raw.replace(':', "%3A").replace('/', "%2F")
}

fn location(reply: &common::Reply) -> String {
    reply
        .headers
        .get(http::header::LOCATION)
        .unwrap_or_else(|| panic!("no Location header; body was {}", reply.text))
        .to_str()
        .unwrap()
        .to_string()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_decode(value))
    })
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

// ------------------------------------------------------------- discovery

/// The document every OAuth client believes over anything written elsewhere. If
/// it is wrong, onboarding fails in a way that looks like "the server is broken".
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_discovery_documents_describe_this_server(pool: PgPool) {
    let h = harness(pool).await;

    let meta = Call::get("/.well-known/oauth-authorization-server")
        .send(&h.router)
        .await;
    meta.expect(StatusCode::OK);

    assert_eq!(meta.body["issuer"], common::PUBLIC_URL);
    assert_eq!(
        meta.body["authorization_endpoint"],
        format!("{}/oauth/authorize", common::PUBLIC_URL)
    );
    assert_eq!(
        meta.body["token_endpoint"],
        format!("{}/oauth/token", common::PUBLIC_URL)
    );
    assert_eq!(
        meta.body["code_challenge_methods_supported"],
        serde_json::json!(["S256"]),
        "advertising anything but S256 would invite a client to use it"
    );
    assert_eq!(meta.body["resource_indicators_supported"], true);

    // Protected-resource metadata is the resource servers' to publish, not
    // this authorization server's.
    Call::get("/.well-known/oauth-protected-resource")
        .send(&h.router)
        .await
        .expect(StatusCode::NOT_FOUND);
}

/// `scopes_supported` is the union across every enabled resource server in the
/// registry, so it grows when a service registers and shrinks when one is
/// disabled — without a deploy of this server.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn discovery_advertises_the_scopes_of_every_enabled_resource_server(pool: PgPool) {
    let h = common::harness_with_two_resources(pool).await;

    let meta = Call::get("/.well-known/oauth-authorization-server")
        .send(&h.router)
        .await;
    meta.expect(StatusCode::OK);
    let scopes: Vec<&str> = meta.body["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    for expected in common::RESOURCE_SCOPES
        .iter()
        .chain(common::OTHER_RESOURCE_SCOPES)
    {
        assert!(
            scopes.contains(expected),
            "{expected} missing from {scopes:?}"
        );
    }

    otto_auth::resources::set_disabled(&h.db, common::OTHER_RESOURCE, true)
        .await
        .unwrap();
    let after = Call::get("/.well-known/oauth-authorization-server")
        .send(&h.router)
        .await;
    assert!(
        !after.text.contains("widgets:read"),
        "a disabled resource server's scopes must not be advertised: {}",
        after.text
    );
}

// ------------------------------------------------------------ the flow

/// The whole authorization code flow, as a CLI agent runs it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_agent_gets_a_token_it_can_use_against_its_resource_server(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;

    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (verifier, challenge) = pkce();

    // The consent screen.
    let page = Call::get(authorize_url(
        &client_id,
        &challenge,
        "things:read things:write",
        "opaque-state",
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    page.expect(StatusCode::OK);

    assert!(
        page.text.contains("127.0.0.1"),
        "the consent screen must show where the code will be sent"
    );
    assert!(page.text.contains("<code>things:write</code>"));
    assert!(page.text.contains("name=org_id"));

    let org_id = h.db.get_org_by_slug("acme").await.unwrap().unwrap().id;

    // The decision.
    let granted = Call::post("/oauth/authorize")
        .with_session(&rob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "things:read things:write"),
            ("resource", RESOURCE),
            ("state", "opaque-state"),
            ("org_id", &org_id.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    granted.expect(StatusCode::SEE_OTHER);

    let callback = location(&granted);
    assert!(callback.starts_with(REDIRECT), "{callback}");
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("opaque-state"),
        "the client's CSRF value must come back unchanged"
    );
    let code = query_param(&callback, "code").expect("no code in the callback");

    // The exchange. Form-encoded, per RFC 6749 — not JSON.
    let tokens = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
            ("resource", RESOURCE),
        ])
        .send(&h.router)
        .await;
    tokens.expect(StatusCode::OK);

    assert_eq!(tokens.body["token_type"], "Bearer");
    assert_eq!(tokens.body["scope"], "things:read things:write");
    assert_eq!(
        tokens.headers.get(http::header::CACHE_CONTROL).unwrap(),
        "no-store",
        "a token response must not sit in a shared cache"
    );

    let access = tokens.body["access_token"].as_str().unwrap();
    let principal = otto_auth::tokens::introspect(&h.db, access, RESOURCE)
        .await
        .expect("the minted token must work against its resource");
    assert_eq!(principal.org_id, org_id);
    assert_eq!(principal.user_id, rob.user);
    assert!(principal.has_scope("things:write"));

    // And a refresh rotates.
    let refresh = tokens.body["refresh_token"].as_str().unwrap().to_string();
    let refreshed = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
            ("resource", RESOURCE),
        ])
        .send(&h.router)
        .await;
    refreshed.expect(StatusCode::OK);
    assert_ne!(
        refreshed.body["refresh_token"], tokens.body["refresh_token"],
        "the refresh token must rotate"
    );

    // Replaying the consumed refresh token is a theft signal, and takes the
    // whole chain with it.
    let replayed = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
            ("resource", RESOURCE),
        ])
        .send(&h.router)
        .await;
    replayed.expect(StatusCode::BAD_REQUEST);
    assert_eq!(replayed.body["error"], "invalid_grant");
}

/// A registered scope description is the main text of its consent line with
/// the raw name beside it; a scope without one is its bare name; and the
/// description is operator-supplied text, never markup.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_consent_page_shows_scope_descriptions_and_falls_back_to_names(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    otto_auth::resources::set_scope_descriptions(
        &h.db,
        RESOURCE,
        &[
            ("things:read", "See your things"),
            ("things:write", "Change <b>everything</b> & more"),
        ],
    )
    .await
    .unwrap();

    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();
    let page = Call::get(authorize_url(
        &client_id,
        &challenge,
        "things:read things:write org:admin",
        "s",
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    page.expect(StatusCode::OK);

    assert!(
        page.text
            .contains("<li>See your things <code class=scope>things:read</code></li>"),
        "{}",
        page.text
    );
    assert!(page.text.contains(
        "<li>Change &lt;b&gt;everything&lt;/b&gt; &amp; more <code class=scope>things:write</code></li>"
    ));
    assert!(!page.text.contains("<b>everything</b>"));
    // No description registered: just the name, as before.
    assert!(page.text.contains("<li><code>org:admin</code></li>"));
}

/// A client that omits `scope` gets its resource server's default scopes. The consent page shows
/// exactly that list before the human decides — the token issued on "allow"
/// must carry the same scopes, not the empty list a naive read of the
/// original (scope-less) request would produce. Before this was fixed, the
/// hidden `scope` field round-tripped the request's absence rather than the
/// page's normalized default, so the agent came back with a token that
/// failed every tool call after a consent screen had just promised it access.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_scopeless_request_is_granted_the_scopes_the_consent_page_showed(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (verifier, challenge) = pkce();

    let page = Call::get(format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fcallback\
         &code_challenge={challenge}&code_challenge_method=S256&state=s"
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    page.expect(StatusCode::OK);
    assert!(
        page.text.contains("<code>things:read</code>"),
        "the consent page must show the default scopes it is about to grant"
    );

    let org_id = h.db.get_org_by_slug("acme").await.unwrap().unwrap().id;

    // Mirrors what the rendered form actually submits: `scope` present but
    // blank, exactly as `blank_to_none` expects from an unfilled hidden field.
    let granted = Call::post("/oauth/authorize")
        .with_session(&rob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", ""),
            ("state", "s"),
            ("org_id", &org_id.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    granted.expect(StatusCode::SEE_OTHER);

    let code = query_param(&location(&granted), "code").expect("no code in the callback");
    let tokens = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
            ("resource", RESOURCE),
        ])
        .send(&h.router)
        .await;
    tokens.expect(StatusCode::OK);

    assert_eq!(
        tokens.body["scope"],
        common::RESOURCE_DEFAULT_SCOPES.join(" "),
        "the issued token must carry what the consent page displayed, not an \
         empty scope list"
    );

    let access = tokens.body["access_token"].as_str().unwrap();
    let principal = otto_auth::tokens::introspect(&h.db, access, RESOURCE)
        .await
        .expect("the minted token must work against its resource");
    assert!(principal.has_scope("things:read"));
}

/// A signed-out visitor has to end up somewhere they can act, not at a 401.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unauthenticated_visitor_is_sent_to_log_in_and_comes_back(pool: PgPool) {
    let h = harness(pool).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let bounced = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .send(&h.router)
        .await;

    assert_eq!(bounced.status, StatusCode::SEE_OTHER);
    let target = location(&bounced);
    assert!(
        target.starts_with(&format!("{}/login?next=", common::PUBLIC_URL)),
        "{target}"
    );

    let next = query_param(&target, "next").expect("no next parameter");
    assert!(
        next.starts_with("/oauth/authorize?") && next.contains(&client_id),
        "the flow must resume where it left off: {next}"
    );
}

// --------------------------------------------------------- error routing

/// The open-redirector case. An unregistered redirect URI is the one thing that
/// must never be redirected to — it is precisely what could not be verified.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unregistered_redirect_uri_renders_a_page_and_never_redirects(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let attacked = Call::get(format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fevil.test%2Fsteal\
         &code_challenge={challenge}&code_challenge_method=S256&state=s"
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;

    attacked.expect(StatusCode::BAD_REQUEST);
    assert!(
        attacked.headers.get(http::header::LOCATION).is_none(),
        "the server redirected to a URI it could not verify — an open redirector"
    );
    assert!(attacked.text.contains("redirect_uri"), "{}", attacked.text);
    assert!(
        !attacked.text.contains("code="),
        "no code may be issued here"
    );
}

/// Once the destination *is* verified, errors go back to the client so an agent
/// can say something useful instead of hanging on a callback that never comes.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn declining_sends_the_client_an_error_not_a_dead_end(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let org_id = org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let declined = Call::post("/oauth/authorize")
        .with_session(&rob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "things:read"),
            ("state", "opaque-state"),
            ("org_id", &org_id.to_string()),
            ("decision", "deny"),
        ])
        .send(&h.router)
        .await;
    declined.expect(StatusCode::SEE_OTHER);

    let callback = location(&declined);
    assert_eq!(
        query_param(&callback, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("opaque-state")
    );
    assert!(query_param(&callback, "code").is_none());
}

/// The org on a token is decided here and cannot be changed afterwards, so a
/// hand-edited form field is the whole attack surface for a cross-tenant token.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn consent_cannot_name_an_org_the_caller_is_not_in(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let mallory = onboard(&h, "mallory@evil.test").await;
    let acme = org_with_owner(&h, "acme", &rob).await;
    org_with_owner(&h, "evil", &mallory).await;

    let client_id = register(&h, "Mallory's Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let attempted = Call::post("/oauth/authorize")
        .with_session(&mallory.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "things:read"),
            ("org_id", &acme.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    attempted.expect(StatusCode::SEE_OTHER);

    let callback = location(&attempted);
    assert_eq!(
        query_param(&callback, "error").as_deref(),
        Some("access_denied"),
        "a token was issued for an org the caller does not belong to"
    );
    assert!(query_param(&callback, "code").is_none());
}

/// A client cannot be granted authority the human granting it does not hold.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_member_cannot_consent_to_org_admin(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let bob = onboard(&h, "bob@acme.test").await;
    let org = org_with_owner(&h, "acme", &rob).await;
    common::add_member(&h, org, bob.user, otto_core::orgs::Role::Member).await;

    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let refused = Call::post("/oauth/authorize")
        .with_session(&bob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "org:admin"),
            ("org_id", &org.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    refused.expect(StatusCode::SEE_OTHER);

    let callback = location(&refused);
    assert_eq!(
        query_param(&callback, "error").as_deref(),
        Some("invalid_scope")
    );
}

// ------------------------------------------------------- token endpoint

/// PKCE is mandatory, and the refusal has to name what is missing — a client
/// author debugging a bare `invalid_request` has nothing to go on.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_token_endpoint_refuses_a_request_without_pkce(pool: PgPool) {
    let h = harness(pool).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;

    let refused = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "otto_ac_whatever"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
        ])
        .send(&h.router)
        .await;
    refused.expect(StatusCode::BAD_REQUEST);

    // RFC 6749 §5.2 shape: `error` and `error_description` at the top level, not
    // the console's `{"error": {"code", "message"}}` envelope. A client handed
    // the wrong shape reports "unknown error".
    assert_eq!(refused.body["error"], "invalid_request");
    assert!(
        refused.body["error_description"]
            .as_str()
            .unwrap()
            .contains("code_verifier"),
        "{}",
        refused.text
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unsupported_grant_type_says_what_is_supported(pool: PgPool) {
    let h = harness(pool).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;

    let refused = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "password"),
            ("client_id", &client_id),
            ("username", "rob"),
            ("password", "hunter2"),
        ])
        .send(&h.router)
        .await;
    refused.expect(StatusCode::BAD_REQUEST);

    assert_eq!(refused.body["error"], "unsupported_grant_type");
    let description = refused.body["error_description"].as_str().unwrap();
    assert!(description.contains("authorization_code"), "{description}");
}

/// A stolen code is useless without the verifier only the initiating client
/// holds. This is the property PKCE exists for, checked at the HTTP edge.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stolen_code_is_useless_without_the_verifier(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let org_id = org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let granted = Call::post("/oauth/authorize")
        .with_session(&rob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "things:read"),
            ("org_id", &org_id.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    let code = query_param(&location(&granted), "code").unwrap();

    let refused = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &"y".repeat(64)),
        ])
        .send(&h.router)
        .await;
    refused.expect(StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["error"], "invalid_grant");
}

/// RFC 7009: always 200, even for a token that never existed. An endpoint that
/// reported otherwise would be an oracle for testing stolen tokens.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn revocation_is_silent_about_whether_the_token_existed(pool: PgPool) {
    let h = harness(pool).await;
    Call::post("/oauth/revoke")
        .form(&[("token", "otto_at_never-existed")])
        .send(&h.router)
        .await
        .expect(StatusCode::OK);
}

// ------------------------------------------------------------ registration

/// Open registration is not unlimited registration, and the screening is what
/// keeps an authorization code from crossing the network in the clear.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn registration_screens_the_redirect_uris_it_will_accept(pool: PgPool) {
    let h = harness(pool).await;

    for (uri, why) in [
        ("http://app.example.com/cb", "cleartext to a public host"),
        ("https://*.example.com/cb", "a wildcard"),
        ("https://app.example.com/cb#frag", "a fragment"),
        ("not a uri", "not a URI at all"),
    ] {
        let refused = Call::post("/oauth/register")
            .json(serde_json::json!({ "redirect_uris": [uri] }))
            .send(&h.router)
            .await;
        refused.expect(StatusCode::BAD_REQUEST);
        assert_eq!(
            refused.body["error"], "invalid_request",
            "{why} was accepted"
        );
    }

    // Loopback over http is the case that must keep working: it is how every
    // CLI agent completes the flow (RFC 8252 §7.3).
    Call::post("/oauth/register")
        .json(serde_json::json!({ "redirect_uris": ["http://127.0.0.1:1455/cb"] }))
        .send(&h.router)
        .await
        .expect(StatusCode::CREATED);
}

/// A client is inert until a human consents, but registration still costs a
/// row, so the endpoint the plan puts behind a throttle is actually throttled.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_registered_client_is_usable_and_named_on_the_consent_screen(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;

    let registered = Call::post("/oauth/register")
        .json(serde_json::json!({
            "client_name": "<script>alert(1)</script>",
            "redirect_uris": [REDIRECT],
        }))
        .send(&h.router)
        .await;
    registered.expect(StatusCode::CREATED);
    assert_eq!(
        registered.body["token_endpoint_auth_method"], "none",
        "public client: PKCE is the proof of possession, not a secret"
    );

    let client_id = registered.body["client_id"].as_str().unwrap();
    let (_, challenge) = pkce();

    let page = Call::get(authorize_url(client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);

    assert!(
        !page.text.contains("<script>alert(1)</script>"),
        "a self-asserted client name reached the consent page as markup"
    );
    assert!(page.text.contains("&lt;script&gt;"));
}

// ------------------------------------------------------------- language

/// One assertion per locale: the negotiated `lang` attribute, and a string that
/// could only have come from that locale's table.
///
/// **The fixture user must have chosen no locale.** Resolution is stored-choice
/// first and header second, so a user with `locale` already set would satisfy
/// every assertion here without `negotiate()` ever being reached — the headline
/// requirement of #42 would pass while measuring nothing. `onboard` leaves
/// `users.locale` NULL, which is what makes this test about the header.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_consent_page_negotiates_accept_language(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    assert!(
        h.db.get_user(rob.user)
            .await
            .unwrap()
            .unwrap()
            .locale
            .is_none(),
        "this test is about the header, so the account must have chosen nothing"
    );

    // Each pair is (Accept-Language, a phrase only that locale renders).
    let expected = [
        ("en", "en", "Authorize access to Things"),
        ("es", "es", "Autorizar acceso a Things"),
        ("de", "de", "Zugriff auf Things autorisieren"),
        ("fr", "fr", "Autoriser l&#39;accès à Things"),
        ("it", "it", "Autorizza l&#39;accesso a Things"),
        ("hi", "hi", "Things तक पहुँच अधिकृत करें"),
    ];

    for (header, lang, phrase) in expected {
        let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
            .with_session(&rob.session)
            .header("accept-language", header)
            .send(&h.router)
            .await;
        page.expect(StatusCode::OK);

        assert!(
            page.text.contains(&format!("<html lang={lang}>")),
            "Accept-Language: {header} should render lang={lang}; got: {}",
            &page.text[..page.text.len().min(120)]
        );
        assert!(
            page.text.contains(phrase),
            "Accept-Language: {header} should render {phrase:?}"
        );
    }
}

/// Weights and region subtags reach the page, not just bare tags.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_consent_page_honours_weights_and_region_subtags(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    for (header, lang) in [
        ("es-419,es;q=0.9", "es"),
        ("de;q=0.3, it;q=0.9", "it"),
        ("ja,ko;q=0.9,fr;q=0.4", "fr"),
        ("en;q=0, de", "de"),
        ("*", "en"),
    ] {
        let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
            .with_session(&rob.session)
            .header("accept-language", header)
            .send(&h.router)
            .await;
        page.expect(StatusCode::OK);
        assert!(
            page.text.contains(&format!("<html lang={lang}>")),
            "Accept-Language: {header:?} should render lang={lang}"
        );
    }
}

/// The account's own choice outranks the browser's header.
///
/// The mirror of the test above, and the reason the stored locale exists at
/// all: somebody who set Spanish on an English-configured work laptop meant it.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_stored_locale_beats_the_header(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    h.db.set_profile(rob.user, None, None, Some(Some("de")))
        .await
        .unwrap();

    let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .header("accept-language", "en-US,en;q=0.9")
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);
    assert!(page.text.contains("<html lang=de>"));
    assert!(page.text.contains("Zugriff auf Things autorisieren"));

    // And clearing it hands the decision back to the header.
    h.db.set_profile(rob.user, None, None, Some(None))
        .await
        .unwrap();

    let after = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .header("accept-language", "en-US,en;q=0.9")
        .send(&h.router)
        .await;
    after.expect(StatusCode::OK);
    assert!(after.text.contains("<html lang=en>"));
}

/// The error page and the consent page are never in different languages.
///
/// This is the regression the design nearly shipped: an earlier draft had the
/// error page negotiate on `Accept-Language` alone on the reasoning that it
/// could be reached without a session. It cannot — so a user with a stored
/// German locale would have got a German consent page and an English error
/// page in the same flow.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_error_page_speaks_the_same_language_as_the_consent_page(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let (_, challenge) = pkce();

    h.db.set_profile(rob.user, None, None, Some(Some("de")))
        .await
        .unwrap();

    // An unregistered client is refused as a *page*, because the redirect URI
    // is exactly what could not be verified.
    let refused = Call::get(authorize_url(
        "client_does_not_exist",
        &challenge,
        "things:read",
        "s",
    ))
    .with_session(&rob.session)
    .header("accept-language", "en-US")
    .send(&h.router)
    .await;
    refused.expect(StatusCode::BAD_REQUEST);

    assert!(
        refused.text.contains("<html lang=de>"),
        "the error page must follow the same stored locale the consent page does"
    );
    assert!(
        refused
            .text
            .contains("Diese Anfrage konnte nicht autorisiert werden"),
        "the error page title must be translated"
    );
    assert!(
        refused
            .text
            .contains("Es wurde nichts autorisiert. Du kannst dieses Fenster schließen."),
        "the closing note must be translated"
    );
}

/// A signed-in account with no org gets its own page, and it is fully
/// translatable because the text is ours rather than an `AuthError`'s.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_no_organization_page_is_translated(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    // A name with markup in it, because `client_name` is self-asserted through
    // open registration and this page is where it is shown.
    let client_id = register(&h, "<b>Test Agent</b>", REDIRECT).await;
    let (_, challenge) = pkce();

    let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .header("accept-language", "es")
        .send(&h.router)
        .await;
    page.expect(StatusCode::BAD_REQUEST);

    assert!(page.text.contains("<html lang=es>"));
    assert!(page.text.contains("Todavía no hay ninguna organización"));
    assert!(
        page.text.contains("&lt;b&gt;Test Agent&lt;/b&gt;"),
        "the client name has to be named, escaped exactly once: {}",
        page.text
    );
    assert!(
        !page.text.contains("<b>Test Agent</b>"),
        "the client name reached the page as markup"
    );
    assert!(
        !page.text.contains("&amp;lt;"),
        "the client name was double-escaped, so the page misreports who is asking"
    );
}

// ------------------------------------------ one server, many resources

/// Run the consent flow for `resource` and return the code it ends in.
async fn consent_for(
    h: &Harness,
    rob: &common::Account,
    client_id: &str,
    challenge: &str,
    scope: &str,
    resource: &str,
) -> common::Reply {
    let org_id = h.db.get_org_by_slug("acme").await.unwrap().unwrap().id;
    Call::post("/oauth/authorize")
        .with_session(&rob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope),
            ("resource", resource),
            ("state", "s"),
            ("org_id", &org_id.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await
}

/// The authorization server serves every registered resource server. A client
/// that names the second one gets a consent page that names *it*, a code for
/// *it*, and a token audienced for *it* — and that token is worthless at the
/// first.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_client_can_be_authorized_for_any_registered_resource(pool: PgPool) {
    let h = common::harness_with_two_resources(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (verifier, challenge) = pkce();

    let other = percent_encode(common::OTHER_RESOURCE);
    let page = Call::get(format!(
        "{}&resource={other}",
        authorize_url(&client_id, &challenge, "widgets:write", "s")
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    page.expect(StatusCode::OK);
    assert!(
        page.text.contains("Authorize access to Widgets"),
        "the consent page must name the resource server being authorized"
    );
    assert!(page.text.contains("<code>widgets:write</code>"));
    assert!(
        !page.text.contains("things:read"),
        "another resource server's scopes leaked onto this consent page"
    );

    let granted = consent_for(
        &h,
        &rob,
        &client_id,
        &challenge,
        "widgets:write",
        common::OTHER_RESOURCE,
    )
    .await;
    granted.expect(StatusCode::SEE_OTHER);
    let code = query_param(&location(&granted), "code").expect("no code in the callback");

    let tokens = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send(&h.router)
        .await;
    tokens.expect(StatusCode::OK);
    assert_eq!(tokens.body["scope"], "widgets:write");

    let access = tokens.body["access_token"].as_str().unwrap();
    otto_auth::tokens::introspect(&h.db, access, common::OTHER_RESOURCE)
        .await
        .expect("valid at the resource server it was issued for");
    assert!(
        otto_auth::tokens::introspect(&h.db, access, RESOURCE)
            .await
            .is_err(),
        "a token for one resource server must not be replayable against another"
    );
}

/// With several resource servers registered, a request that names none is
/// refused rather than guessed at: the consent screen must say which service
/// the human is authorizing, and the AS cannot know.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_ambiguous_resource_is_refused_not_guessed(pool: PgPool) {
    let h = common::harness_with_two_resources(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::BAD_REQUEST);
    assert!(page.text.contains("resource parameter is required"));

    let decision = consent_for(&h, &rob, &client_id, &challenge, "things:read", "").await;
    decision.expect(StatusCode::BAD_REQUEST);
    assert!(
        decision.headers.get(http::header::LOCATION).is_none(),
        "an ambiguous request must not redirect with a code"
    );
}

/// A scope belongs to the resource server that defines it. Asking one server's
/// audience for another's scope is refused on the page and at the decision.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_scope_from_another_resource_server_is_refused(pool: PgPool) {
    let h = common::harness_with_two_resources(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let page = Call::get(format!(
        "{}&resource={}",
        authorize_url(&client_id, &challenge, "widgets:read", "s"),
        percent_encode(RESOURCE)
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    page.expect(StatusCode::BAD_REQUEST);
    assert!(page.text.contains("unknown scope"));

    let decision = consent_for(&h, &rob, &client_id, &challenge, "widgets:read", RESOURCE).await;
    decision.expect(StatusCode::BAD_REQUEST);
    assert!(decision.headers.get(http::header::LOCATION).is_none());
}

/// A disabled resource server, and one that was never registered, are both
/// refused as `invalid_target` and no code is issued.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_disabled_or_unknown_resource_is_refused(pool: PgPool) {
    let h = common::harness_with_two_resources(pool).await;
    otto_auth::resources::set_disabled(&h.db, common::OTHER_RESOURCE, true)
        .await
        .unwrap();
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    for resource in [common::OTHER_RESOURCE, "https://nope.otto.test/mcp"] {
        let decision = consent_for(&h, &rob, &client_id, &challenge, "", resource).await;
        decision.expect(StatusCode::BAD_REQUEST);
        assert!(
            decision.headers.get(http::header::LOCATION).is_none(),
            "{resource} must not redirect with a code"
        );
    }
}

/// Registered but with every resource server gone, there is nothing to default
/// to and nothing to authorize.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn with_an_empty_registry_nothing_can_be_authorized(pool: PgPool) {
    let h = harness(pool).await;
    sqlx::query("DELETE FROM resource_servers")
        .execute(h.db.pool())
        .await
        .unwrap();
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let page = Call::get(authorize_url(&client_id, &challenge, "", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::BAD_REQUEST);
    assert!(page.text.contains("no resource server is registered"));
}

// ------------------------------------------------- discovery under an outage

/// The open discovery document reads the registry. A database that cannot
/// answer is a "retry" condition (`503`), never a `500`.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn discovery_is_503_when_the_database_is_unreachable(pool: PgPool) {
    let h = common::harness_with_unreachable_db(pool).await;

    let reply = Call::get("/.well-known/oauth-authorization-server")
        .send(&h.router)
        .await;
    reply.expect(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.error_code(), Some("temporarily_unavailable"));
}

// ------------------------------------------------ the form pins the resource

/// A client that names no resource is resolved to the only registered one for
/// the page. The decision form must carry *that*, not the request's empty
/// value: if a second resource server registers between render and submit, an
/// empty field would be ambiguous (or, in an older design, resolve to a
/// different server than the page showed).
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_consent_form_pins_the_resource_the_page_showed(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (verifier, challenge) = pkce();

    let page = Call::get(authorize_url(&client_id, &challenge, "", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);
    let marker = "name=resource value=\"";
    let start = page.text.find(marker).expect("no resource field") + marker.len();
    let pinned = &page.text[start..start + page.text[start..].find('"').unwrap()];
    assert_eq!(
        pinned, RESOURCE,
        "the hidden field echoed the request, not the resolution"
    );

    // A second resource server registers while the human reads the page.
    common::register_other_resource(&h.db).await;

    let granted = consent_for(&h, &rob, &client_id, &challenge, "", pinned).await;
    granted.expect(StatusCode::SEE_OTHER);
    let code = query_param(&location(&granted), "code").expect("no code");
    let tokens = Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send(&h.router)
        .await;
    tokens.expect(StatusCode::OK);
    let access = tokens.body["access_token"].as_str().unwrap();
    otto_auth::tokens::introspect(&h.db, access, RESOURCE)
        .await
        .expect("the token is for the server the page named");

    // And the old behaviour — submitting the empty value — is now refused
    // rather than guessed at.
    let (_, challenge2) = pkce();
    let ambiguous = consent_for(&h, &rob, &client_id, &challenge2, "", "").await;
    ambiguous.expect(StatusCode::BAD_REQUEST);
}

// ------------------------------------------------- cross-site request guard

/// The consent decision is the highest-value forgery target: one form POST
/// from any same-site sibling (an XSS on another `*.savvagent.com` host) would
/// hand an attacker's client a token. `SameSite=Lax` does not stop a sibling.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_consent_decision_from_a_sibling_origin_is_refused(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Attacker", REDIRECT).await;
    let (_, challenge) = pkce();

    for origin in ["https://blog.otto.test", "https://evil.test", "null"] {
        let org_id = h.db.get_org_by_slug("acme").await.unwrap().unwrap().id;
        let decision = Call::post("/oauth/authorize")
            .with_session(&rob.session)
            .header("origin", origin)
            .form(&[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "things:read"),
                ("resource", RESOURCE),
                ("state", "s"),
                ("org_id", &org_id.to_string()),
                ("decision", "allow"),
            ])
            .send(&h.router)
            .await;
        decision.expect(StatusCode::FORBIDDEN);
        assert_eq!(
            decision.error_code(),
            Some("cross_site_request"),
            "{origin}"
        );
        assert!(decision.headers.get(http::header::LOCATION).is_none());
    }
}

/// Agents call the token, registration and revocation endpoints with no cookie
/// and no `Origin`. There is no ambient credential there to forge, so the
/// guard must not touch them.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn agent_endpoints_without_a_cookie_are_not_guarded(pool: PgPool) {
    let h = harness(pool).await;

    // Reaches the handler (which refuses the empty grant) rather than the guard.
    let token = Call::post("/oauth/token")
        .form(&[("grant_type", "authorization_code")])
        .send(&h.router)
        .await;
    assert_ne!(token.status, StatusCode::FORBIDDEN, "{}", token.text);
    assert_eq!(token.body["error"], "invalid_request");

    Call::post("/oauth/revoke")
        .form(&[("token", "otto_at_nothing")])
        .send(&h.router)
        .await
        .expect(StatusCode::OK);

    // Even an agent that happens to send a foreign Origin, cookie-less.
    let registered = Call::post("/oauth/register")
        .header("origin", "https://some-web-agent.test")
        .json(serde_json::json!({ "client_name": "x", "redirect_uris": [REDIRECT] }))
        .send(&h.router)
        .await;
    registered.expect(StatusCode::CREATED);
}

// ------------------------------------------------ first-party clients

/// A first-party client's callback: https, because loopback is never allowed
/// to skip consent (RFC 8252 section 8.6).
const FP_REDIRECT: &str = "https://console.test/auth/callback";

fn fp_url(client_id: &str, challenge: &str, scope: &str, state: &str) -> String {
    authorize_url_to(FP_REDIRECT, client_id, challenge, scope, state)
}

/// A client the operator registered as first-party, the only way to get one.
async fn register_first_party(h: &Harness) -> String {
    otto_auth::oauth::register_operator_client(
        &h.db,
        otto_auth::oauth::RegistrationRequest {
            client_name: Some("Console".into()),
            redirect_uris: vec![FP_REDIRECT.into()],
            software_id: None,
            grant_types: None,
        },
        true,
    )
    .await
    .unwrap()
    .client_id
}

/// `authorize_url` plus an `org_hint`.
fn hinted_url(client_id: &str, challenge: &str, scope: &str, hint: &str) -> String {
    format!(
        "{}&org_hint={hint}",
        fp_url(client_id, challenge, scope, "opaque-state")
    )
}

async fn redeem(h: &Harness, client_id: &str, callback: &str, verifier: &str) -> common::Reply {
    redeem_at(h, client_id, callback, verifier, FP_REDIRECT).await
}

async fn redeem_at(
    h: &Harness,
    client_id: &str,
    callback: &str,
    verifier: &str,
    redirect: &str,
) -> common::Reply {
    let code = query_param(callback, "code").expect("no code in the callback");
    Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", client_id),
            ("redirect_uri", redirect),
            ("code_verifier", verifier),
            ("resource", RESOURCE),
        ])
        .send(&h.router)
        .await
}

/// Registration is open, so nothing a caller sends it may confer first-party
/// status. The flag is not part of the request, and a client that sends it
/// anyway is registered like any other.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn dynamic_registration_cannot_create_a_first_party_client(pool: PgPool) {
    let h = harness(pool).await;

    let registered = Call::post("/oauth/register")
        .json(serde_json::json!({
            "client_name": "Sneaky",
            "redirect_uris": [REDIRECT],
            "first_party": true,
        }))
        .send(&h.router)
        .await;
    registered.expect(StatusCode::CREATED);
    assert!(registered.body.get("first_party").is_none());

    let client_id = registered.body["client_id"].as_str().unwrap();
    let client = otto_auth::oauth::get_client(&h.db, client_id)
        .await
        .unwrap();
    assert!(!client.first_party);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_first_party_client_with_one_org_skips_consent(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let org = org_with_owner(&h, "acme", &rob).await;
    let client_id = register_first_party(&h).await;
    let (verifier, challenge) = pkce();

    let reply = Call::get(fp_url(
        &client_id,
        &challenge,
        "things:read things:write",
        "opaque-state",
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    reply.expect(StatusCode::SEE_OTHER);

    let callback = location(&reply);
    assert!(callback.starts_with(FP_REDIRECT), "{callback}");
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("opaque-state")
    );

    // The same bindings as the consent path: PKCE, redirect URI, resource.
    // A wrong verifier is refused (and burns that code).
    redeem(&h, &client_id, &callback, &"y".repeat(64))
        .await
        .expect(StatusCode::BAD_REQUEST);

    let reply = Call::get(fp_url(
        &client_id,
        &challenge,
        "things:read things:write",
        "opaque-state",
    ))
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    let tokens = redeem(&h, &client_id, &location(&reply), &verifier).await;
    tokens.expect(StatusCode::OK);
    assert_eq!(tokens.body["scope"], "things:read things:write");
    let principal = otto_auth::tokens::introspect(
        &h.db,
        tokens.body["access_token"].as_str().unwrap(),
        RESOURCE,
    )
    .await
    .unwrap();
    assert_eq!(principal.org_id, org);
    assert_eq!(principal.user_id, rob.user);
}

/// The skip is after full validation: a bad redirect URI or missing PKCE is
/// still an error page, never a code.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn skipping_consent_does_not_skip_validation(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register_first_party(&h).await;
    let (_, challenge) = pkce();

    let evil = Call::get(
        fp_url(&client_id, &challenge, "things:read", "s").replace("console.test", "evil.test"),
    )
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    evil.expect(StatusCode::BAD_REQUEST);
    assert!(!evil.headers.contains_key(http::header::LOCATION));

    let no_pkce = Call::get(
        fp_url(&client_id, &challenge, "things:read", "s")
            .replace("code_challenge_method=S256", "code_challenge_method=plain"),
    )
    .with_session(&rob.session)
    .send(&h.router)
    .await;
    no_pkce.expect(StatusCode::BAD_REQUEST);

    let bad_scope = Call::get(fp_url(&client_id, &challenge, "nope:nope", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    bad_scope.expect(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_valid_org_hint_picks_the_org_for_a_first_party_client(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let globex = org_with_owner(&h, "globex", &rob).await;
    let client_id = register_first_party(&h).await;
    let (verifier, challenge) = pkce();

    // Two orgs and no hint: there is a choice, so the screen appears.
    let page = Call::get(fp_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);
    assert!(page.text.contains("name=org_id"));

    // By slug, and by id.
    for hint in ["globex".to_string(), globex.to_string()] {
        let reply = Call::get(hinted_url(&client_id, &challenge, "things:read", &hint))
            .with_session(&rob.session)
            .send(&h.router)
            .await;
        reply.expect(StatusCode::SEE_OTHER);
        let tokens = redeem(&h, &client_id, &location(&reply), &verifier).await;
        tokens.expect(StatusCode::OK);
        let principal = otto_auth::tokens::introspect(
            &h.db,
            tokens.body["access_token"].as_str().unwrap(),
            RESOURCE,
        )
        .await
        .unwrap();
        assert_eq!(principal.org_id, globex, "hint {hint}");
    }
}

/// A hint naming an org the caller is not in is ignored, and the response is
/// the same whether or not that org exists.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_org_hint_the_caller_cannot_use_is_ignored_without_leaking(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let eve = onboard(&h, "eve@initech.test").await;
    org_with_owner(&h, "acme", &rob).await;
    org_with_owner(&h, "globex", &rob).await;
    org_with_owner(&h, "initech", &eve).await;
    let client_id = register_first_party(&h).await;
    let (_, challenge) = pkce();

    let page = |hint: &'static str| {
        let url = hinted_url(&client_id, &challenge, "things:read", hint);
        let h = &h;
        let rob = &rob;
        async move {
            let page = Call::get(url)
                .with_session(&rob.session)
                .send(&h.router)
                .await;
            page.expect(StatusCode::OK);
            page.text
        }
    };
    let someone_elses = page("initech").await;
    let nonexistent = page("nonexistent").await;

    assert!(someone_elses.contains("name=org_id"), "no consent screen");
    assert!(!someone_elses.contains(" selected"));
    assert!(!someone_elses.contains("initech</option>"));
    // Same page, byte for byte, apart from the caller's own echoed input.
    assert_eq!(someone_elses.replace("initech", "nonexistent"), nonexistent);
}

/// With exactly one org there is nothing to pick, so a hint that is useless is
/// just ignored and the client still skips.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_useless_hint_does_not_block_the_single_org_skip(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let org = org_with_owner(&h, "acme", &rob).await;
    let client_id = register_first_party(&h).await;
    let (verifier, challenge) = pkce();

    let reply = Call::get(hinted_url(&client_id, &challenge, "things:read", "initech"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    reply.expect(StatusCode::SEE_OTHER);
    let tokens = redeem(&h, &client_id, &location(&reply), &verifier).await;
    tokens.expect(StatusCode::OK);
    let principal = otto_auth::tokens::introspect(
        &h.db,
        tokens.body["access_token"].as_str().unwrap(),
        RESOURCE,
    )
    .await
    .unwrap();
    assert_eq!(principal.org_id, org);
}

/// Third-party clients always get the screen, hint or no hint, one org or
/// many. The hint only preselects.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_client_that_is_not_first_party_always_gets_the_consent_screen(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let (_, challenge) = pkce();

    let base = authorize_url(&client_id, &challenge, "things:read", "s");
    for url in [base.clone(), format!("{base}&org_hint=acme")] {
        let page = Call::get(url)
            .with_session(&rob.session)
            .send(&h.router)
            .await;
        page.expect(StatusCode::OK);
        assert!(page.text.contains("name=org_id"));
        assert!(!page.headers.contains_key(http::header::LOCATION));
    }

    let globex = org_with_owner(&h, "globex", &rob).await;
    let page = Call::get(format!("{base}&org_hint=globex"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);
    assert!(
        page.text.contains(&format!("value=\"{globex}\" selected")),
        "the hinted org should be preselected: {}",
        page.text
    );
    assert!(
        page.text.contains("name=org_hint value=\"globex\""),
        "the hint must ride through the form"
    );
}

/// A requested admin scope is dropped, not refused, when the human is not an
/// admin; the token says what it actually carries. Covered on both routes.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_member_requesting_org_admin_gets_a_downscoped_token(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    let bob = onboard(&h, "bob@acme.test").await;
    let org = org_with_owner(&h, "acme", &rob).await;
    common::add_member(&h, org, bob.user, otto_core::orgs::Role::Member).await;
    let (verifier, challenge) = pkce();
    let scope = "things:read org:admin";

    // First-party skip.
    let first_party = register_first_party(&h).await;
    for (who, expected) in [(&bob, "things:read"), (&rob, "things:read org:admin")] {
        let reply = Call::get(fp_url(&first_party, &challenge, scope, "s"))
            .with_session(&who.session)
            .send(&h.router)
            .await;
        reply.expect(StatusCode::SEE_OTHER);
        let tokens = redeem(&h, &first_party, &location(&reply), &verifier).await;
        tokens.expect(StatusCode::OK);
        assert_eq!(tokens.body["scope"], expected);
        let principal = otto_auth::tokens::introspect(
            &h.db,
            tokens.body["access_token"].as_str().unwrap(),
            RESOURCE,
        )
        .await
        .unwrap();
        assert_eq!(
            principal.has_scope("org:admin"),
            expected.contains("org:admin")
        );
    }

    // Consent POST.
    let client_id = register(&h, "Test Agent", REDIRECT).await;
    let granted = Call::post("/oauth/authorize")
        .with_session(&bob.session)
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope),
            ("resource", RESOURCE),
            ("org_id", &org.to_string()),
            ("decision", "allow"),
        ])
        .send(&h.router)
        .await;
    granted.expect(StatusCode::SEE_OTHER);
    let tokens = redeem_at(&h, &client_id, &location(&granted), &verifier, REDIRECT).await;
    tokens.expect(StatusCode::OK);
    assert_eq!(tokens.body["scope"], "things:read");

    // Nothing left after the drop: that is still an error, as a redirect.
    let nothing = Call::get(fp_url(&first_party, &challenge, "org:admin", "s"))
        .with_session(&bob.session)
        .send(&h.router)
        .await;
    nothing.expect(StatusCode::SEE_OTHER);
    let callback = location(&nothing);
    assert_eq!(
        query_param(&callback, "error").as_deref(),
        Some("invalid_scope")
    );
    assert!(query_param(&callback, "code").is_none());
}

/// RFC 8252 section 8.6: even if a first-party client somehow has a loopback
/// redirect (here, a hand-edited row), it gets the consent screen.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_first_party_client_on_a_loopback_redirect_still_gets_consent(pool: PgPool) {
    let h = harness(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let client_id = register(&h, "Dev Console", REDIRECT).await;
    sqlx::query("UPDATE oauth_clients SET first_party = true WHERE client_id = $1")
        .bind(&client_id)
        .execute(h.db.pool())
        .await
        .unwrap();
    let (_, challenge) = pkce();

    let page = Call::get(authorize_url(&client_id, &challenge, "things:read", "s"))
        .with_session(&rob.session)
        .send(&h.router)
        .await;
    page.expect(StatusCode::OK);
    assert!(page.text.contains("name=org_id"));
    assert!(!page.headers.contains_key(http::header::LOCATION));
}
