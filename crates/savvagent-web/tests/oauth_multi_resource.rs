//! One authorization request for several resources (RFC 8707 section 2.1):
//! one consent screen, one code per resource the person kept.
//!
//! Every code is an ordinary single-resource code, so these tests check what
//! is new around it: the request is all or nothing, the page offers each
//! resource on its own, the seal binds the list, a forged choice is refused,
//! and each code redeems for its own resource and no other.

use savvagent_core::orgs::OrgsExt;
mod common;

use base64::Engine;
use common::{onboard, org_with_owner, Call, Harness, OTHER_RESOURCE, RESOURCE};
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

async fn register(h: &Harness) -> String {
    let registered = Call::post("/oauth/register")
        .json(serde_json::json!({
            "client_name": "savctl",
            "redirect_uris": [REDIRECT],
        }))
        .send(&h.router)
        .await;
    registered.expect(StatusCode::CREATED);
    registered.body["client_id"].as_str().unwrap().to_string()
}

fn enc(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

/// An authorization request naming each of `resources`.
fn authorize_url(client_id: &str, challenge: &str, scope: &str, resources: &[&str]) -> String {
    let mut url = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}\
         &code_challenge={challenge}&code_challenge_method=S256&scope={}&state=s",
        enc(REDIRECT),
        enc(scope),
    );
    for r in resources {
        url.push_str(&format!("&resource={}", enc(r)));
    }
    url
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

/// Every `(name, value)` of a callback URL's query, decoded, in order.
fn callback_pairs(url: &str) -> Vec<(String, String)> {
    let (_, query) = url.split_once('?').expect("a callback with no query");
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The `(code, resource)` pairs a multi-resource callback carries.
fn codes(url: &str) -> Vec<(String, String)> {
    let pairs = callback_pairs(url);
    let codes: Vec<&String> = pairs
        .iter()
        .filter(|(k, _)| k == "code")
        .map(|(_, v)| v)
        .collect();
    let resources: Vec<&String> = pairs
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(codes.len(), resources.len(), "{url}");
    codes
        .into_iter()
        .cloned()
        .zip(resources.into_iter().cloned())
        .collect()
}

async fn code_count(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM authorization_codes")
        .fetch_one(h.db.pool())
        .await
        .unwrap()
}

async fn redeem(
    h: &Harness,
    client_id: &str,
    verifier: &str,
    code: &str,
    resource: &str,
) -> common::Reply {
    Call::post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", verifier),
            ("resource", resource),
        ])
        .send(&h.router)
        .await
}

struct Setup {
    h: Harness,
    rob: common::Account,
    org: String,
    client_id: String,
    verifier: String,
    challenge: String,
}

async fn setup(pool: PgPool) -> Setup {
    let h = common::harness_with_two_resources(pool).await;
    let rob = onboard(&h, "rob@acme.test").await;
    org_with_owner(&h, "acme", &rob).await;
    let org =
        h.db.get_org_by_slug("acme")
            .await
            .unwrap()
            .unwrap()
            .id
            .to_string();
    let client_id = register(&h).await;
    let (verifier, challenge) = pkce();
    Setup {
        h,
        rob,
        org,
        client_id,
        verifier,
        challenge,
    }
}

const BOTH: &[&str] = &[RESOURCE, OTHER_RESOURCE];
const SCOPE: &str = "things:read things:write widgets:read";

impl Setup {
    async fn page(&self) -> (common::ConsentPage, String) {
        let reply = Call::get(authorize_url(&self.client_id, &self.challenge, SCOPE, BOTH))
            .with_session(&self.rob.session)
            .send(&self.h.router)
            .await;
        reply.expect(StatusCode::OK);
        (common::ConsentPage::parse(&reply.text), reply.text)
    }

    async fn submit(&self, fields: &[(String, String)]) -> common::Reply {
        common::submit_consent(&self.h, &self.rob.session, fields).await
    }
}

/// `fields` plus an `include` for each of `kept`.
fn including(mut fields: Vec<(String, String)>, kept: &[usize]) -> Vec<(String, String)> {
    fields.extend(kept.iter().map(|i| ("include".to_string(), i.to_string())));
    fields
}

#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn discovery_says_how_many_resources_one_request_may_name(pool: PgPool) {
    let h = common::harness(pool).await;
    let meta = Call::get("/.well-known/oauth-authorization-server")
        .send(&h.router)
        .await;
    meta.expect(StatusCode::OK);
    assert_eq!(
        meta.body["savvagent_authorize_resources_max"],
        savvagent_auth::oauth::MAX_RESOURCES_PER_REQUEST
    );
    // Renamed with the Savvagent switch; the old name is not served too.
    assert!(
        meta.body.get("otto_authorize_resources_max").is_none(),
        "{}",
        meta.body
    );
}

/// The whole flow: one page lists both resources with their own scopes, one
/// approval issues a code for each, and each code is good for its own
/// resource only.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn one_consent_screen_issues_a_code_for_each_resource(pool: PgPool) {
    let s = setup(pool).await;
    let (page, html) = s.page().await;
    assert!(html.contains(common::RESOURCE_NAME), "{html}");
    assert!(html.contains(common::OTHER_RESOURCE_NAME), "{html}");
    assert!(
        html.contains("127.0.0.1"),
        "the redirect host must be shown"
    );
    assert_eq!(
        page.checked(),
        ["0 things:read", "0 things:write", "1 widgets:read"],
        "each resource offers only its own scopes, all checked"
    );
    let resources: Vec<&str> = page
        .hidden
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(resources, BOTH);

    let granted = s
        .submit(&including(page.submission(&s.org, "allow"), &[0, 1]))
        .await;
    granted.expect(StatusCode::SEE_OTHER);
    let callback = location(&granted);
    assert!(callback.starts_with(REDIRECT), "{callback}");
    let issued = codes(&callback);
    assert_eq!(
        issued.iter().map(|(_, r)| r.as_str()).collect::<Vec<_>>(),
        BOTH
    );
    assert!(callback_pairs(&callback).contains(&("state".into(), "s".into())));
    assert_eq!(code_count(&s.h).await, 2);

    // A code is bound to its resource: the other one's is refused, and burned.
    let (things_code, _) = &issued[0];
    let (widgets_code, _) = &issued[1];
    let crossed = redeem(&s.h, &s.client_id, &s.verifier, widgets_code, RESOURCE).await;
    crossed.expect(StatusCode::BAD_REQUEST);
    assert_eq!(crossed.body["error"], "invalid_grant");

    let things = redeem(&s.h, &s.client_id, &s.verifier, things_code, RESOURCE).await;
    things.expect(StatusCode::OK);
    assert_eq!(things.body["scope"], "things:read things:write");
    let access = things.body["access_token"].as_str().unwrap();
    savvagent_auth::tokens::introspect(&s.h.db, access, RESOURCE)
        .await
        .expect("a token for its own resource");
    assert!(
        savvagent_auth::tokens::introspect(&s.h.db, access, OTHER_RESOURCE)
            .await
            .is_err(),
        "a token's audience is exactly one resource"
    );
}

/// Unticking a resource leaves it out; the other is granted as chosen.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_resource_left_out_gets_no_code(pool: PgPool) {
    let s = setup(pool).await;
    let (page, _) = s.page().await;
    // Widgets is kept; Things is unticked, so its ticked scopes grant nothing.
    let fields = including(
        page.submission_with(&s.org, "allow", &["0 things:read", "1 widgets:read"]),
        &[1],
    );
    let granted = s.submit(&fields).await;
    granted.expect(StatusCode::SEE_OTHER);
    let issued = codes(&location(&granted));
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].1, OTHER_RESOURCE);
    assert_eq!(code_count(&s.h).await, 1);

    let widgets = redeem(
        &s.h,
        &s.client_id,
        &s.verifier,
        &issued[0].0,
        OTHER_RESOURCE,
    )
    .await;
    widgets.expect(StatusCode::OK);
    assert_eq!(widgets.body["scope"], "widgets:read");
}

/// Leaving out everything is a refusal the client can read, not a dead end.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn leaving_out_every_resource_is_access_denied(pool: PgPool) {
    let s = setup(pool).await;
    let (page, _) = s.page().await;
    for fields in [
        page.submission(&s.org, "allow"),
        including(page.submission_with(&s.org, "allow", &[]), &[0, 1]),
    ] {
        let reply = s.submit(&fields).await;
        reply.expect(StatusCode::SEE_OTHER);
        let callback = location(&reply);
        assert!(
            callback_pairs(&callback).contains(&("error".into(), "access_denied".into())),
            "{callback}"
        );
    }
    assert_eq!(code_count(&s.h).await, 0);
}

/// All or nothing: one bad resource or scope refuses the whole request as a
/// page, before any consent is shown.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn one_bad_resource_or_scope_refuses_the_whole_request(pool: PgPool) {
    let s = setup(pool).await;
    savvagent_auth::resources::register(
        &s.h.db,
        savvagent_auth::resources::ResourceServerSpec {
            resource_uri: "https://off.otto.test/mcp",
            name: "Off",
            scopes: &["off:read"],
            default_scopes: &["off:read"],
        },
    )
    .await
    .unwrap();
    savvagent_auth::resources::set_disabled(&s.h.db, "https://off.otto.test/mcp", true)
        .await
        .unwrap();
    let cases: [(&str, &[&str]); 4] = [
        (SCOPE, &[RESOURCE, "https://nope.otto.test/mcp"]),
        (SCOPE, &[RESOURCE, "https://off.otto.test/mcp"]),
        (SCOPE, &[RESOURCE, RESOURCE]),
        ("things:read nope:read", BOTH),
    ];
    for (scope, resources) in cases {
        let reply = Call::get(authorize_url(&s.client_id, &s.challenge, scope, resources))
            .with_session(&s.rob.session)
            .send(&s.h.router)
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{scope} {resources:?}: {}",
            reply.text
        );
        assert!(reply.headers.get(http::header::LOCATION).is_none());
    }
    assert_eq!(code_count(&s.h).await, 0);
}

/// A resource named with no scope of its own gets its defaults, shown on the
/// page like any other.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_resource_with_none_of_the_requested_scopes_gets_its_defaults(pool: PgPool) {
    let s = setup(pool).await;
    let reply = Call::get(authorize_url(
        &s.client_id,
        &s.challenge,
        "things:write",
        BOTH,
    ))
    .with_session(&s.rob.session)
    .send(&s.h.router)
    .await;
    reply.expect(StatusCode::OK);
    assert_eq!(
        common::ConsentPage::parse(&reply.text).checked(),
        ["0 things:write", "1 widgets:read"]
    );
}

/// A choice the page did not offer is refused, never dropped.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_forged_choice_is_refused(pool: PgPool) {
    let s = setup(pool).await;
    let (page, _) = s.page().await;
    let forgeries: Vec<Vec<(String, String)>> = vec![
        // A resource index that is not on the page.
        including(page.submission(&s.org, "allow"), &[0, 5]),
        // A scope under a resource index that is not on the page.
        including(
            page.submission_with(&s.org, "allow", &["7 things:read"]),
            &[0],
        ),
        // Another resource's scope, moved under this one.
        including(
            page.submission_with(&s.org, "allow", &["0 widgets:read"]),
            &[0],
        ),
        // A scope nobody offered.
        including(
            page.submission_with(&s.org, "allow", &["1 widgets:write"]),
            &[1],
        ),
        // No index at all.
        including(
            page.submission_with(&s.org, "allow", &["things:read"]),
            &[0],
        ),
    ];
    for fields in forgeries {
        let reply = s.submit(&fields).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{fields:?}: {}",
            reply.text
        );
        assert!(reply.headers.get(http::header::LOCATION).is_none());
    }
    assert_eq!(code_count(&s.h).await, 0);
}

/// The seal binds the list of resources: a form that names fewer, more, or
/// others than the page did is refused before any branch.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn the_seal_binds_the_resources_the_page_offered(pool: PgPool) {
    let s = setup(pool).await;
    savvagent_auth::resources::register(
        &s.h.db,
        savvagent_auth::resources::ResourceServerSpec {
            resource_uri: "https://third.otto.test/mcp",
            name: "Third",
            scopes: &["third:read"],
            default_scopes: &["third:read"],
        },
    )
    .await
    .unwrap();
    let (page, _) = s.page().await;
    let allow = including(page.submission(&s.org, "allow"), &[0, 1]);

    let dropped: Vec<_> = {
        let mut seen = false;
        allow
            .iter()
            .filter(|(k, v)| {
                let drop = k == "resource" && v == OTHER_RESOURCE && !seen;
                seen |= drop;
                !drop
            })
            .cloned()
            .collect()
    };
    let mut added = allow.clone();
    added.push(("resource".into(), "https://third.otto.test/mcp".into()));
    let swapped: Vec<_> = allow
        .iter()
        .map(|(k, v)| {
            let v = if k == "resource" && v == OTHER_RESOURCE {
                "https://third.otto.test/mcp".to_string()
            } else {
                v.clone()
            };
            (k.clone(), v)
        })
        .collect();
    for (why, fields) in [("dropped", dropped), ("added", added), ("swapped", swapped)] {
        let reply = s.submit(&fields).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{why}: {}",
            reply.text
        );
        assert!(reply.headers.get(http::header::LOCATION).is_none(), "{why}");
    }
    assert_eq!(code_count(&s.h).await, 0);

    // The untouched form still works.
    s.submit(&allow).await.expect(StatusCode::SEE_OTHER);
}

/// A member who is not an admin loses org:admin on each resource, as on a
/// single grant; a resource left with only that gets nothing.
#[sqlx::test(migrator = "savvagent_tenant::db::MIGRATOR")]
async fn a_member_loses_org_admin_on_each_resource(pool: PgPool) {
    let s = setup(pool).await;
    let ann = onboard(&s.h, "ann@acme.test").await;
    let org: savvagent_tenant::ids::OrgId = s.org.parse().unwrap();
    s.h.db
        .add_member(org, ann.user, savvagent_core::orgs::Role::Member)
        .await
        .unwrap();
    let reply = Call::get(authorize_url(
        &s.client_id,
        &s.challenge,
        "org:admin widgets:read",
        BOTH,
    ))
    .with_session(&ann.session)
    .send(&s.h.router)
    .await;
    reply.expect(StatusCode::OK);
    let page = common::ConsentPage::parse(&reply.text);
    let granted = common::submit_consent(
        &s.h,
        &ann.session,
        &including(page.submission(&s.org, "allow"), &[0, 1]),
    )
    .await;
    granted.expect(StatusCode::SEE_OTHER);
    let issued = codes(&location(&granted));
    assert_eq!(
        issued.iter().map(|(_, r)| r.as_str()).collect::<Vec<_>>(),
        [OTHER_RESOURCE],
        "Things asked only for org:admin, which a member cannot grant"
    );
    assert!(
        callback_pairs(&location(&granted)).contains(&("refused_resource".into(), RESOURCE.into())),
        "a resource kept but granted nothing is named, so it is not taken for one left out"
    );
}
