//! Enterprise OIDC federation — route-level tests against a real Postgres and
//! a fixture IdP (`support::FixtureIdp`), no live network. See
//! `docs/specs/2026-09-16-oidc-federation-design.md` §5 and
//! `docs/plans/2026-09-16-oidc-federation.md`'s Task 3 checklist for what
//! every case below is guarding.
//!
//! **DNS verification is not exercised through the HTTP `verify` endpoint.**
//! `otto_auth::dns::verify_txt_record` does a real DNS lookup, and Task 2's own
//! tests already cover its TXT-record parsing in isolation with no live
//! network. Driving a real DNS record from an integration test would be
//! flaky and network-dependent — the opposite of this suite's "no live
//! network" rule — so fixtures here mark a domain verified directly through
//! `otto_core::domains::mark_verified` (the same function the verify endpoint
//! itself calls once DNS succeeds), and exercise the HTTP claim/list/delete
//! surface and its lockout guards, which do not depend on DNS at all.

use otto_core::orgs::OrgsExt;
mod common;
mod support;

use std::collections::HashMap;

use common::{harness, onboard, org_with_owner, sign_in, Account, Call, Harness, Reply};
use http::StatusCode;
use otto_tenant::ids::OrgId;
use serde_json::Value;
use sqlx::PgPool;
use support::{FixtureIdp, MockResponse, TestServer};

const ADMIN_EMAIL: &str = "admin@acme.test";

// --------------------------------------------------------------- fixtures

/// `PUT /api/orgs/{org}/sso/connection` against a fixture IdP.
async fn bind_connection(h: &Harness, org: &str, admin: &Account, idp: &FixtureIdp) -> Value {
    let reply = Call::put(format!("/api/orgs/{org}/sso/connection"))
        .with_session(&admin.session)
        .json(serde_json::json!({
            "issuer": idp.server.base_url,
            "clientId": "client-1",
            "clientSecret": "shh-its-a-secret",
        }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::OK);
    reply.body
}

/// Claim `domain` for `org`, then mark it verified directly — see the module
/// docs on why this bypasses the live-DNS `verify` endpoint.
async fn claim_and_verify_domain(
    h: &Harness,
    org_id: OrgId,
    org: &str,
    admin: &Account,
    domain: &str,
) {
    let claimed = Call::post(format!("/api/orgs/{org}/sso/domains"))
        .with_session(&admin.session)
        .json(serde_json::json!({ "domain": domain }))
        .send(&h.router)
        .await;
    claimed.expect(StatusCode::CREATED);

    let mut tx = h.db.begin(org_id).await.expect("begin tx");
    otto_core::domains::mark_verified(&mut tx, domain)
        .await
        .expect("mark_verified");
    tx.commit().await.expect("commit");
}

fn query_pairs(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .expect("redirectUrl parses")
        .query_pairs()
        .into_owned()
        .collect()
}

/// The `__Host-otto_sso_binding` cookie value a response set, if it set one —
/// the binding-cookie counterpart to `common::Reply::session_cookie`.
fn binding_cookie(reply: &Reply) -> Option<String> {
    reply
        .headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            let value = v.strip_prefix("__Host-otto_sso_binding=")?;
            let value = value.split(';').next()?;
            (!value.is_empty()).then(|| value.to_string())
        })
}

/// Start an anonymous `sso/start` ceremony; returns (state, nonce, binding cookie).
async fn start_anonymous(h: &Harness, email: &str) -> (String, String, String) {
    let reply = Call::post("/api/auth/sso/start")
        .json(serde_json::json!({ "email": email }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::OK);
    let redirect = reply.body["redirectUrl"]
        .as_str()
        .expect("redirectUrl")
        .to_string();
    let pairs = query_pairs(&redirect);
    let binding = binding_cookie(&reply).expect("sso/start must set the binding cookie");
    (pairs["state"].clone(), pairs["nonce"].clone(), binding)
}

/// Start an authenticated `me/sso/link/start` ceremony for `caller`.
async fn start_link(h: &Harness, caller: &Account) -> (String, String, String) {
    let reply = Call::post("/api/me/sso/link/start")
        .with_session(&caller.session)
        .send(&h.router)
        .await;
    reply.expect(StatusCode::OK);
    let redirect = reply.body["redirectUrl"]
        .as_str()
        .expect("redirectUrl")
        .to_string();
    let pairs = query_pairs(&redirect);
    let binding = binding_cookie(&reply).expect("sso/link/start must set the binding cookie");
    (pairs["state"].clone(), pairs["nonce"].clone(), binding)
}

fn id_token_claims(
    issuer: &str,
    sub: &str,
    email: &str,
    email_verified: bool,
    nonce: &str,
) -> Value {
    let now = chrono::Utc::now().timestamp();
    serde_json::json!({
        "iss": issuer,
        "aud": "client-1",
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    })
}

/// Queue the fixture IdP's token-exchange response and drive `GET
/// /sso/callback` with the given `state`/binding cookie/`id_token`.
async fn complete_callback(
    h: &Harness,
    idp: &FixtureIdp,
    state: &str,
    binding: Option<&str>,
    id_token: &str,
) -> Reply {
    idp.push_token_response(id_token);
    let mut call = Call::get(format!("/sso/callback?code=auth-code-1&state={state}"));
    if let Some(binding) = binding {
        call = call.header("cookie", format!("__Host-otto_sso_binding={binding}"));
    }
    call.send(&h.router).await
}

/// Set up an org with a bound fixture IdP and one verified domain. Returns
/// (org_id, admin, idp).
async fn org_with_sso(
    pool: PgPool,
    org: &str,
    domain: &str,
) -> (Harness, OrgId, Account, FixtureIdp) {
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    let org_id = org_with_owner(&h, org, &admin).await;
    let idp = FixtureIdp::start().await;
    bind_connection(&h, org, &admin, &idp).await;
    claim_and_verify_domain(&h, org_id, org, &admin, domain).await;
    (h, org_id, admin, idp)
}

/// Completes the authenticated "link my SSO identity" ceremony for `admin`,
/// against their own `ADMIN_EMAIL`. `set_enforce_sso`'s enable-path guard
/// (spec: closing the admin's-own-lockout case) requires the caller to
/// already have a linked identity before `PUT .../sso/enforce` with
/// `enforceSso: true` succeeds — every test that flips enforcement on calls
/// this first, the same way a real admin would from account settings before
/// locking their own passkey out.
async fn link_admin_identity(h: &Harness, admin: &Account, idp: &FixtureIdp) {
    let (state, nonce, binding) = start_link(h, admin).await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "admin-sub",
        ADMIN_EMAIL,
        true,
        &nonce,
    ));
    let reply = complete_callback(h, idp, &state, Some(&binding), &id_token).await;
    reply.expect(StatusCode::SEE_OTHER);
}

// ------------------------------------------------------------- the flows

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_full_anonymous_sso_sign_in_flow_opens_a_session_and_joins_the_org(pool: PgPool) {
    let (h, org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "alice@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "alice-sub",
        "alice@acme.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::SEE_OTHER);
    let session = reply
        .session_cookie()
        .expect("callback must open a session");

    let me = Call::get("/api/me")
        .with_session(&session)
        .send(&h.router)
        .await;
    me.expect(StatusCode::OK);
    assert_eq!(me.body["user"]["email"], "alice@acme.test");
    let orgs = me.body["orgs"].as_array().unwrap();
    assert!(
        orgs.iter()
            .any(|m| m["orgSlug"] == "acme" && m["role"] == "member"),
        "a brand-new federated signup must be provisioned into the org as a member: {orgs:?}"
    );

    // Directly against the table too — the plan's own warning that this step
    // is the one most likely to be silently dropped.
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE email = 'alice@acme.test'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    let role: String =
        sqlx::query_scalar("SELECT role::text FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(role, "member");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_returning_federated_user_with_no_membership_row_is_reprovisioned(pool: PgPool) {
    // `identities::link`'s write and the org_members write are two separate
    // statements against two different connections — a first sign-in that
    // linked the identity but failed partway through provisioning
    // membership must not leave that user permanently authenticatable but
    // never a member of the org on every subsequent login.
    let (h, org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "carol@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "carol-sub",
        "carol@acme.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    reply.expect(StatusCode::SEE_OTHER);

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE email = 'carol@acme.test'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();

    // Simulate the membership half of that first sign-in never landing.
    h.db.remove_member(org_id, otto_tenant::ids::UserId::from(user_id))
        .await
        .unwrap();
    let gone: i64 =
        sqlx::query_scalar("SELECT count(*) FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(gone, 0);

    // A second sign-in resolves via Step 4 (`identities::resolve_user`
    // already finds the link), skipping `link_anonymous` entirely.
    let (state2, nonce2, binding2) = start_anonymous(&h, "carol@acme.test").await;
    let id_token2 = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "carol-sub",
        "carol@acme.test",
        true,
        &nonce2,
    ));
    let reply2 = complete_callback(&h, &idp, &state2, Some(&binding2), &id_token2).await;
    reply2.expect(StatusCode::SEE_OTHER);

    let role: String =
        sqlx::query_scalar("SELECT role::text FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(
        role, "member",
        "a returning federated user must be reprovisioned as a member, not left permanently orphaned"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn callback_refuses_a_disabled_account(pool: PgPool) {
    // login::with_passkey refuses a disabled account before minting a
    // session; this callback previously skipped that check entirely for a
    // *returning* federated user (a brand-new user can't already be
    // disabled) — sessions::resolve would still refuse the resulting
    // session on its very next use, so this was never a way in, but the
    // audit trail recorded a false LOGIN_SUCCEEDED instead of a
    // LOGIN_FAILED for an attempt that should be refused outright.
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    // First sign-in links alice's federated identity.
    let (state, nonce, binding) = start_anonymous(&h, "alice@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "alice-sub",
        "alice@acme.test",
        true,
        &nonce,
    ));
    let first = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    first.expect(StatusCode::SEE_OTHER);

    sqlx::query("UPDATE users SET disabled_at = now() WHERE email = 'alice@acme.test'")
        .execute(h.db.pool())
        .await
        .unwrap();

    // A second sign-in attempt, now that the account is disabled.
    let (state, nonce, binding) = start_anonymous(&h, "alice@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "alice-sub",
        "alice@acme.test",
        true,
        &nonce,
    ));
    let second = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    second.expect(StatusCode::BAD_REQUEST);
    assert!(
        second.session_cookie().is_none(),
        "a disabled account must never get a session, even briefly"
    );

    let failed_reason: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT detail FROM audit_events WHERE action = 'auth.login.failed' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        failed_reason.as_ref().and_then(|d| d.get("reason")),
        Some(&serde_json::json!("account disabled"))
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn sso_start_refuses_an_unclaimed_domain(pool: PgPool) {
    let h = harness(pool).await;
    let reply = Call::post("/api/auth/sso/start")
        .json(serde_json::json!({ "email": "nobody@unclaimed.test" }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), Some("sso_not_configured"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn binding_a_connection_refuses_a_discovery_document_missing_issuer(pool: PgPool) {
    // require_discovery_fields originally checked only the three *endpoint*
    // fields, missing `issuer` — which every one of authorization_url,
    // exchange_code, and verify_id_token also needs. Without this check, a
    // connection with no issuer in its cached discovery document binds
    // successfully and then fails every subsequent sign-in attempt.
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    org_with_owner(&h, "acme", &admin).await;

    let server = TestServer::start().await;
    server.push(MockResponse::json(
        200,
        serde_json::json!({
            "authorization_endpoint": format!("{}/authorize", server.base_url),
            "token_endpoint": format!("{}/token", server.base_url),
            "jwks_uri": format!("{}/jwks", server.base_url),
            // no "issuer"
        }),
    ));

    let reply = Call::put("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .json(serde_json::json!({
            "issuer": server.base_url,
            "clientId": "client-1",
            "clientSecret": "shh-its-a-secret",
        }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    let message = reply.body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("issuer"),
        "the refusal should name the missing field: {message:?}"
    );

    let after = Call::get("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .send(&h.router)
        .await;
    after.expect(StatusCode::NO_CONTENT);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn binding_a_connection_refuses_an_unparseable_endpoint_url(pool: PgPool) {
    // Present-and-a-string is not the same as "a URL" — a connection with
    // an empty or malformed authorization_endpoint would otherwise bind
    // successfully and only fail on the first sign-in attempt.
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    org_with_owner(&h, "acme", &admin).await;

    let server = TestServer::start().await;
    server.push(MockResponse::json(
        200,
        serde_json::json!({
            "issuer": server.base_url,
            "authorization_endpoint": "not a url",
            "token_endpoint": format!("{}/token", server.base_url),
            "jwks_uri": format!("{}/jwks", server.base_url),
        }),
    ));

    let reply = Call::put("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .json(serde_json::json!({
            "issuer": server.base_url,
            "clientId": "client-1",
            "clientSecret": "shh-its-a-secret",
        }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    let message = reply.body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("authorization_endpoint"),
        "the refusal should name the invalid field: {message:?}"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn binding_a_connection_refuses_a_discovery_document_with_a_mismatched_issuer(pool: PgPool) {
    // OIDC Discovery §4.3: the document's own `issuer` must equal the
    // issuer it was fetched from — otherwise `verify_id_token` pins `iss`
    // to a value with no relationship to what the admin configured.
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    org_with_owner(&h, "acme", &admin).await;

    let server = TestServer::start().await;
    server.push(MockResponse::json(
        200,
        serde_json::json!({
            "issuer": "https://a-completely-different-issuer.test",
            "authorization_endpoint": format!("{}/authorize", server.base_url),
            "token_endpoint": format!("{}/token", server.base_url),
            "jwks_uri": format!("{}/jwks", server.base_url),
        }),
    ));

    let reply = Call::put("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .json(serde_json::json!({
            "issuer": server.base_url,
            "clientId": "client-1",
            "clientSecret": "shh-its-a-secret",
        }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    let message = reply.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("does not match"), "got: {message:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_full_authenticated_link_flow_links_an_existing_account(pool: PgPool) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    // An existing passkey account whose email happens to match the domain —
    // it links explicitly rather than "just working" on first SSO attempt.
    let bob = onboard(&h, "bob@acme.test").await;

    let (state, nonce, binding) = start_link(&h, &bob).await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "bob-sub",
        "bob@acme.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::SEE_OTHER);
    let session = reply
        .session_cookie()
        .expect("callback must open a session");
    let me = Call::get("/api/me")
        .with_session(&session)
        .send(&h.router)
        .await;
    me.expect(StatusCode::OK);
    assert_eq!(me.body["user"]["id"], bob.user.to_string());

    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM user_identities WHERE user_id = $1")
        .bind(bob.user)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(linked, 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authenticated_link_refuses_when_the_verified_email_does_not_match_the_caller(
    pool: PgPool,
) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let carol = onboard(&h, "carol@acme.test").await;
    let (state, nonce, binding) = start_link(&h, &carol).await;
    // A domain-matching but different email than carol's own.
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "dave-sub",
        "dave@acme.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::BAD_REQUEST);
    assert!(reply.session_cookie().is_none());

    let identities: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_identities WHERE user_id = $1")
            .bind(carol.user)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(identities, 0, "no identity may be created for carol");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn authenticated_link_refuses_to_steal_an_identity_already_linked_to_someone_else(
    pool: PgPool,
) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    // Victim: a brand-new anonymous federated sign-in links
    // (idp_connection_id, "shared-sub") to a fresh account.
    let (state1, nonce1, binding1) = start_anonymous(&h, "victim@acme.test").await;
    let id_token1 = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "shared-sub",
        "victim@acme.test",
        true,
        &nonce1,
    ));
    let victim_reply = complete_callback(&h, &idp, &state1, Some(&binding1), &id_token1).await;
    victim_reply.expect(StatusCode::SEE_OTHER);
    let victim_session = victim_reply.session_cookie().unwrap();
    let victim_me = Call::get("/api/me")
        .with_session(&victim_session)
        .send(&h.router)
        .await;
    let victim_user_id = victim_me.body["user"]["id"].as_str().unwrap().to_string();

    // Attacker: a different, already-authenticated account (also under the
    // claimed domain, so it can even start a link ceremony) tries to link
    // the SAME (idp_connection_id, subject) pair onto itself.
    let attacker = onboard(&h, "attacker@acme.test").await;
    let (state2, nonce2, binding2) = start_link(&h, &attacker).await;
    let id_token2 = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "shared-sub",
        "victim@acme.test",
        true,
        &nonce2,
    ));
    let attacker_reply = complete_callback(&h, &idp, &state2, Some(&binding2), &id_token2).await;

    attacker_reply.expect(StatusCode::BAD_REQUEST);
    assert!(
        attacker_reply.session_cookie().is_none(),
        "no session may open for the attacker's ceremony"
    );

    let linked_user: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM user_identities WHERE subject = 'shared-sub'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(
        linked_user.to_string(),
        victim_user_id,
        "the identity must still belong to the victim"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn anonymous_sso_refuses_when_the_verified_email_already_has_an_unlinked_account(
    pool: PgPool,
) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    // A pre-existing passkey account under the same address, never linked.
    // This is exactly the account-takeover shape the design's Assumptions
    // close: no session, no silent link.
    let _existing = onboard(&h, "collide@acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "collide@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "collider-sub",
        "collide@acme.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::BAD_REQUEST);
    assert!(reply.session_cookie().is_none());

    let identities: i64 = sqlx::query_scalar("SELECT count(*) FROM user_identities")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(identities, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn callback_refuses_an_unverified_email_claim(pool: PgPool) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "eve@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "eve-sub",
        "eve@acme.test",
        false,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::BAD_REQUEST);
    assert!(reply.session_cookie().is_none());

    // A refusal must clear the binding cookie exactly like a success or an
    // internal-error outcome does — its ceremony is already consumed
    // (single-use), so a stale copy left past a refusal is the same hygiene
    // gap those other two outcomes already close.
    let cleared = reply
        .headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with("__Host-otto_sso_binding=") && v.contains("Max-Age=0"));
    assert!(cleared, "refusal must clear the binding cookie");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_replayed_state_is_refused_and_does_not_reopen_a_session(pool: PgPool) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "frank@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "frank-sub",
        "frank@acme.test",
        true,
        &nonce,
    ));
    let first = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    first.expect(StatusCode::SEE_OTHER);
    assert!(first.session_cookie().is_some());

    let second = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    second.expect(StatusCode::BAD_REQUEST);
    assert!(second.session_cookie().is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_missing_binding_cookie_is_refused_and_burns_the_ceremony(pool: PgPool) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "grace@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "grace-sub",
        "grace@acme.test",
        true,
        &nonce,
    ));

    let missing = complete_callback(&h, &idp, &state, None, &id_token).await;
    missing.expect(StatusCode::BAD_REQUEST);
    assert!(missing.session_cookie().is_none());

    // Even with the correct binding cookie now, the ceremony was already
    // burned by the first attempt — it cannot be retried against.
    let retry = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    retry.expect(StatusCode::BAD_REQUEST);
    assert!(retry.session_cookie().is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_mismatched_binding_cookie_is_refused_and_burns_the_ceremony(pool: PgPool) {
    let (h, _org_id, _admin, idp) = org_with_sso(pool, "acme", "acme.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "heidi@acme.test").await;
    let id_token = support::sign_id_token(&id_token_claims(
        &idp.server.base_url,
        "heidi-sub",
        "heidi@acme.test",
        true,
        &nonce,
    ));

    let wrong = complete_callback(
        &h,
        &idp,
        &state,
        Some("otto_ssb_not-the-right-one"),
        &id_token,
    )
    .await;
    wrong.expect(StatusCode::BAD_REQUEST);
    assert!(wrong.session_cookie().is_none());

    let retry = complete_callback(&h, &idp, &state, Some(&binding), &id_token).await;
    retry.expect(StatusCode::BAD_REQUEST);
    assert!(retry.session_cookie().is_none());
}

/// A domain unclaimed and reclaimed by a different org after a ceremony
/// starts must refuse the in-flight ceremony rather than silently completing
/// it under either org — the ceremony's stored `org_id` is the anchor
/// (spec §5's fresh `resolve_for_domain` check), and once the domain no
/// longer resolves *to that org*, the callback fails closed rather than
/// falling back to whichever org the domain now belongs to.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_domain_reassigned_after_the_ceremony_starts_is_refused_not_retargeted(pool: PgPool) {
    let (h, _org_a, admin_a, idp_a) = org_with_sso(pool, "acme", "shared.test").await;

    let (state, nonce, binding) = start_anonymous(&h, "grace@shared.test").await;

    // Org A releases the domain, and org B claims and verifies it — before
    // the ceremony above completes.
    let release = Call::delete("/api/orgs/acme/sso/domains/shared.test")
        .with_session(&admin_a.session)
        .send(&h.router)
        .await;
    release.expect(StatusCode::NO_CONTENT);

    let admin_b = onboard(&h, "admin-b@other.test").await;
    let org_b = org_with_owner(&h, "other", &admin_b).await;
    let idp_b = FixtureIdp::start().await;
    bind_connection(&h, "other", &admin_b, &idp_b).await;
    claim_and_verify_domain(&h, org_b, "other", &admin_b, "shared.test").await;

    let id_token = support::sign_id_token(&id_token_claims(
        &idp_a.server.base_url,
        "grace-sub",
        "grace@shared.test",
        true,
        &nonce,
    ));
    let reply = complete_callback(&h, &idp_a, &state, Some(&binding), &id_token).await;

    reply.expect(StatusCode::BAD_REQUEST);
    assert!(reply.session_cookie().is_none());

    let identities: i64 = sqlx::query_scalar("SELECT count(*) FROM user_identities")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(
        identities, 0,
        "org B must never be silently provisioned either"
    );
}

// --------------------------------------------------------- lockout guards

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn enforce_sso_cannot_be_turned_on_with_no_working_sso_path(pool: PgPool) {
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    org_with_owner(&h, "acme", &admin).await;

    let reply = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), Some("sso_lockout"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn enforce_sso_cannot_be_turned_on_by_an_admin_who_has_not_linked_their_own_identity(
    pool: PgPool,
) {
    // Infrastructure (a bound connection, a verified domain) is fully in
    // place — org_with_sso does exactly that — but nobody has completed the
    // authenticated link ceremony yet. This is the lockout a third review
    // round found: without this guard, flipping enforceSso here would
    // refuse passkey login for every member, including the admin issuing
    // this exact call, with literally no path back into the org for anyone.
    let (h, _org_id, admin, _idp) = org_with_sso(pool, "acme", "acme.test").await;

    let reply = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    reply.expect(StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), Some("sso_lockout"));
    let message = reply.body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("you have not linked"),
        "the refusal should name the actual missing piece: {message:?}"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn deleting_the_only_connection_is_refused_while_enforce_sso_is_on(pool: PgPool) {
    let (h, _org_id, admin, idp) = org_with_sso(pool, "acme", "acme.test").await;
    link_admin_identity(&h, &admin, &idp).await;

    let enable = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    enable.expect(StatusCode::OK);

    let delete = Call::delete("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .send(&h.router)
        .await;
    delete.expect(StatusCode::BAD_REQUEST);
    assert_eq!(delete.error_code(), Some("sso_lockout"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn deleting_the_last_verified_domain_is_refused_while_enforce_sso_is_on(pool: PgPool) {
    let (h, _org_id, admin, idp) = org_with_sso(pool, "acme", "acme.test").await;
    link_admin_identity(&h, &admin, &idp).await;

    let enable = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    enable.expect(StatusCode::OK);

    let delete = Call::delete("/api/orgs/acme/sso/domains/acme.test")
        .with_session(&admin.session)
        .send(&h.router)
        .await;
    delete.expect(StatusCode::BAD_REQUEST);
    assert_eq!(delete.error_code(), Some("sso_lockout"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn passkey_login_is_refused_for_a_member_of_an_enforce_sso_org(pool: PgPool) {
    let (h, _org_id, mut admin, idp) = org_with_sso(pool, "acme", "acme.test").await;
    // set_enforce_sso's enable guard requires the caller to already be
    // linked (closing the admin's-own-lockout case) — the admin's *passkey*
    // still stops working the moment enforcement is on, same as any other
    // member; only their now-linked SSO identity keeps working. That
    // distinction is exactly what this test asserts.
    link_admin_identity(&h, &admin, &idp).await;

    let enable = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    enable.expect(StatusCode::OK);

    // The admin is themselves a member of the now-enforce_sso org — their
    // passkey stops working too, with no carve-out for the person who just
    // flipped the flag. They are not locked out of the org itself (they
    // linked their SSO identity first, per the guard above), only out of
    // this specific credential.
    let reply = sign_in(&h, &mut admin).await;
    reply.expect(StatusCode::FORBIDDEN);
    assert_eq!(reply.error_code(), Some("sso_required"));
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn passkey_login_is_not_refused_for_a_member_of_a_different_unenforced_org(pool: PgPool) {
    // `is_member_of_sso_enforced_org` joins org_members to orgs filtered on
    // enforce_sso — the false-positive shape this guards against is that
    // join accidentally matching an unrelated org's flag. A bystander who
    // never touches the enforce_sso org at all must keep signing in
    // normally.
    let (h, _acme_id, _admin, idp) = org_with_sso(pool.clone(), "acme", "acme.test").await;
    link_admin_identity(&h, &_admin, &idp).await;

    let enable = Call::put("/api/orgs/acme/sso/enforce")
        .with_session(&_admin.session)
        .json(serde_json::json!({ "enforceSso": true }))
        .send(&h.router)
        .await;
    enable.expect(StatusCode::OK);

    let owner = onboard(&h, "owner@other.test").await;
    let other_id = org_with_owner(&h, "other", &owner).await;
    let mut bystander = onboard(&h, "bystander@other.test").await;
    common::add_member(&h, other_id, bystander.user, otto_core::orgs::Role::Member).await;

    let reply = sign_in(&h, &mut bystander).await;
    reply.expect(StatusCode::OK);
    assert!(
        reply.session_cookie().is_some(),
        "a member of an unrelated, non-enforce_sso org must still sign in with a passkey"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn get_connection_returns_no_content_until_one_is_bound_then_never_the_secret(pool: PgPool) {
    let h = harness(pool).await;
    let admin = onboard(&h, ADMIN_EMAIL).await;
    org_with_owner(&h, "acme", &admin).await;

    let before = Call::get("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .send(&h.router)
        .await;
    before.expect(StatusCode::NO_CONTENT);

    let idp = FixtureIdp::start().await;
    bind_connection(&h, "acme", &admin, &idp).await;

    let after = Call::get("/api/orgs/acme/sso/connection")
        .with_session(&admin.session)
        .send(&h.router)
        .await;
    after.expect(StatusCode::OK);
    assert_eq!(after.body["issuer"], idp.server.base_url);
    assert_eq!(after.body["clientId"], "client-1");
    assert!(
        after.body.get("clientSecret").is_none()
            && after.body.get("client_secret_ct").is_none()
            && after.body.get("clientSecretCt").is_none(),
        "the connection's secret must never be readable through this endpoint"
    );
}
