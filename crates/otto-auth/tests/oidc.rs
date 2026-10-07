//! Recorded-fixture tests for `otto_auth::oidc` — discovery fetch, authorization
//! URL construction, code exchange, and `id_token` verification. No live
//! network: every HTTP call in here goes to `support::TestServer`, a local
//! mock server started fresh per test. See otto-factory's `docs/specs/2026-09-16-oidc-federation-design.md`
//! §4 for the shapes under test.

mod support;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_auth::error::AuthError;
use otto_auth::oidc;
use serde_json::json;
use support::{MockResponse, TestServer};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_secs() as i64
}

// ---- fetch_discovery ------------------------------------------------------

#[tokio::test]
async fn fetch_discovery_returns_the_document_verbatim() {
    let server = TestServer::start().await;
    let doc = support::discovery_document(&server.base_url);
    server.push(MockResponse::json(200, doc.clone()));

    let fetched = oidc::fetch_discovery(&server.base_url)
        .await
        .expect("discovery fetch succeeds");
    assert_eq!(fetched, doc);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/.well-known/openid-configuration");
}

#[tokio::test]
async fn fetch_discovery_surfaces_a_non_2xx_status_as_oidc_api() {
    let server = TestServer::start().await;
    server.push(MockResponse::text(503, "issuer is down for maintenance"));

    let err = oidc::fetch_discovery(&server.base_url)
        .await
        .expect_err("a 503 must not be treated as a document");
    match err {
        AuthError::OidcApi { status, body, .. } => {
            assert_eq!(status, 503);
            assert!(body.contains("maintenance"));
        }
        other => panic!("expected AuthError::OidcApi, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_discovery_refuses_a_response_over_the_byte_cap() {
    // An admin- or IdP-controlled URL must not be able to push an unbounded
    // body into this process's memory — every one of fetch_discovery,
    // exchange_code, and fetch_jwks shares the same capped reader, so this
    // one case stands in for all three.
    let server = TestServer::start().await;
    let oversized = "x".repeat(2 * 1024 * 1024); // 2 MiB, over the 1 MiB cap
    server.push(MockResponse::json(200, serde_json::json!(oversized)));

    let err = oidc::fetch_discovery(&server.base_url)
        .await
        .expect_err("an oversized response must be refused, not buffered in full");
    match err {
        AuthError::OidcApi { body, .. } => {
            assert!(body.contains("exceeded"), "got: {body:?}");
        }
        other => panic!("expected AuthError::OidcApi, got {other:?}"),
    }
}

// ---- authorization_url -----------------------------------------------------

#[test]
fn authorization_url_has_the_exact_query_shape_from_spec_4() {
    let discovery = support::discovery_document("https://idp.example.test");

    let url = oidc::authorization_url(
        &discovery,
        "client-123",
        "https://otto.example/sso/callback",
        "state-abc",
        "nonce-xyz",
    )
    .expect("discovery has an authorization_endpoint");

    assert_eq!(
        format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap(),
            url.path()
        ),
        "https://idp.example.test/authorize"
    );

    let pairs: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        pairs.get("scope").map(String::as_str),
        Some("openid email profile")
    );
    assert_eq!(
        pairs.get("client_id").map(String::as_str),
        Some("client-123")
    );
    assert_eq!(
        pairs.get("redirect_uri").map(String::as_str),
        Some("https://otto.example/sso/callback")
    );
    assert_eq!(pairs.get("state").map(String::as_str), Some("state-abc"));
    assert_eq!(pairs.get("nonce").map(String::as_str), Some("nonce-xyz"));
}

#[test]
fn authorization_url_refuses_a_discovery_document_missing_the_endpoint() {
    let discovery = json!({});

    let err = oidc::authorization_url(
        &discovery,
        "client-123",
        "https://otto.example/sso/callback",
        "state-abc",
        "nonce-xyz",
    )
    .expect_err("no authorization_endpoint to build a URL from");

    assert!(matches!(
        err,
        AuthError::OidcDiscoveryField("authorization_endpoint")
    ));
}

// ---- exchange_code ----------------------------------------------------------

#[tokio::test]
async fn exchange_code_happy_path() {
    let server = TestServer::start().await;
    let discovery = support::discovery_document(&server.base_url);
    server.push(MockResponse::json(
        200,
        json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "header.payload.signature",
        }),
    ));

    let token = oidc::exchange_code(
        &discovery,
        "client-1",
        "shh-its-a-secret",
        "auth-code-1",
        "https://otto.example/sso/callback",
    )
    .await
    .expect("token exchange succeeds");

    assert_eq!(token.access_token, "at-1");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.id_token, "header.payload.signature");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/token");
    let body = String::from_utf8(requests[0].body.clone()).expect("form body is utf8");
    assert!(body.contains("grant_type=authorization_code"));
    assert!(body.contains("code=auth-code-1"));
    assert!(body.contains("client_id=client-1"));
    assert!(body.contains("client_secret=shh-its-a-secret"));
    assert!(body.contains("redirect_uri="));
}

#[tokio::test]
async fn exchange_code_surfaces_a_rejected_authorization_code() {
    let server = TestServer::start().await;
    let discovery = support::discovery_document(&server.base_url);
    server.push(MockResponse::json(
        400,
        json!({"error": "invalid_grant", "error_description": "code already redeemed"}),
    ));

    let err = oidc::exchange_code(
        &discovery,
        "client-1",
        "shh",
        "spent-code",
        "https://otto.example/sso/callback",
    )
    .await
    .expect_err("a spent code must not produce a token");

    match err {
        AuthError::OidcApi { status, body, .. } => {
            assert_eq!(status, 400);
            assert!(body.contains("invalid_grant"));
        }
        other => panic!("expected AuthError::OidcApi, got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_code_redacts_the_client_secret_from_a_non_conformant_error_body() {
    // A non-conformant token endpoint might echo the submitted form back in
    // its error body — this must never let the plaintext secret reach
    // whatever logs this error's Display text ends up in.
    let server = TestServer::start().await;
    let discovery = support::discovery_document(&server.base_url);
    server.push(MockResponse::text(
        400,
        "invalid_request: client_secret=super-secret-value was rejected",
    ));

    let err = oidc::exchange_code(
        &discovery,
        "client-1",
        "super-secret-value",
        "spent-code",
        "https://otto.example/sso/callback",
    )
    .await
    .expect_err("a rejected exchange must still error");

    match err {
        AuthError::OidcApi { body, .. } => {
            assert!(
                !body.contains("super-secret-value"),
                "the secret must be redacted from the logged body: {body:?}"
            );
            assert!(body.contains("[redacted]"));
        }
        other => panic!("expected AuthError::OidcApi, got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_code_redacts_the_authorization_code_from_a_non_conformant_error_body() {
    // A compromised or non-conformant token endpoint echoing the submitted
    // `code` back is just as much a leak as echoing the client secret — the
    // code is single-use, but still a bearer-shaped credential.
    let server = TestServer::start().await;
    let discovery = support::discovery_document(&server.base_url);
    server.push(MockResponse::text(
        400,
        "invalid_grant: code=the-spent-authorization-code was already redeemed",
    ));

    let err = oidc::exchange_code(
        &discovery,
        "client-1",
        "irrelevant-secret",
        "the-spent-authorization-code",
        "https://otto.example/sso/callback",
    )
    .await
    .expect_err("a rejected exchange must still error");

    match err {
        AuthError::OidcApi { body, .. } => {
            assert!(
                !body.contains("the-spent-authorization-code"),
                "the code must be redacted from the logged body: {body:?}"
            );
            assert!(body.contains("[redacted]"));
        }
        other => panic!("expected AuthError::OidcApi, got {other:?}"),
    }
}

// ---- verify_id_token ---------------------------------------------------------

/// Every id_token test below starts a fresh `TestServer` (a fresh, unique
/// `jwks_uri`) specifically so `oidc`'s process-wide JWKS cache never lets
/// one test's fixture answer another's lookup.
async fn jwks_server() -> TestServer {
    let server = TestServer::start().await;
    server.push(MockResponse::json(200, support::jwks_document()));
    server
}

#[tokio::test]
async fn verify_id_token_accepts_a_valid_token() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": "client-1",
        "sub": "user-42",
        "email": "alice@acme.test",
        "email_verified": true,
        "nonce": "nonce-1",
        "iat": now(),
        "exp": now() + 300,
    });
    let id_token = support::sign_id_token(&claims);

    let verified = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect("a correctly signed, correctly claimed token verifies");

    assert_eq!(verified.sub, "user-42");
    assert_eq!(verified.email.as_deref(), Some("alice@acme.test"));
    assert_eq!(verified.email_verified, Some(true));
}

#[tokio::test]
async fn verify_id_token_reuses_a_cached_jwks_document() {
    // Deliberately deviates from `jwks_server()`'s helper: only ONE response
    // is queued, so a second live fetch would fail the request outright
    // (the mock server answers an unqueued request with 500). Two
    // successful verifications against this server is only possible if the
    // second call served the JWKS document from `oidc`'s cache instead of
    // fetching it again — proving the cache is actually consulted, not just
    // present and unused (a regression that quietly deleted the caching
    // would still compile and would still pass every other test here, since
    // none of them call `verify_id_token` twice against one server).
    let server = TestServer::start().await;
    server.push(MockResponse::json(200, support::jwks_document()));
    let discovery = support::discovery_document(&server.base_url);

    for nonce in ["nonce-1", "nonce-2"] {
        let claims = json!({
            "iss": server.base_url,
            "aud": "client-1",
            "sub": "user-42",
            "nonce": nonce,
            "exp": now() + 300,
        });
        let id_token = support::sign_id_token(&claims);

        oidc::verify_id_token(&discovery, "client-1", &id_token, nonce)
            .await
            .expect("cached JWKS still verifies a second, freshly signed token");
    }

    let jwks_requests = server
        .requests()
        .into_iter()
        .filter(|r| r.path == "/jwks")
        .count();
    assert_eq!(
        jwks_requests, 1,
        "the second verify_id_token call should have hit the cache, not refetched the JWKS document"
    );
}

#[tokio::test]
async fn verify_id_token_rejects_wrong_issuer() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": "https://not-the-real-idp.test",
        "aud": "client-1",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a token from a different issuer must be refused");
    assert_id_token_invalid(&err, "issuer");
}

#[tokio::test]
async fn verify_id_token_rejects_wrong_audience() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": "some-other-client",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a token issued for a different client_id must be refused");
    assert_id_token_invalid(&err, "audience");
}

#[tokio::test]
async fn verify_id_token_rejects_a_token_with_no_aud_claim() {
    // jsonwebtoken's set_audience()/set_issuer() only compare a claim
    // against the expected value when the claim is present at all — a token
    // that omits `aud` entirely has nothing to compare and would otherwise
    // verify. This is the missing-claim case set_required_spec_claims
    // exists to close; a wrong-value `aud` is covered separately above.
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
        // no "aud" at all
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a token with no aud claim at all must be refused, not silently accepted");
    assert!(matches!(err, AuthError::IdTokenInvalid(_)), "got {err:?}");
}

#[tokio::test]
async fn verify_id_token_rejects_a_multi_audience_token_with_no_matching_azp() {
    // OIDC Core §3.1.3.7 steps 3-5: `set_audience` above only confirms
    // `client_id` is *one of* possibly several audiences. A token minted
    // for several relying parties at once needs `azp` to say which one it
    // was actually issued for.
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": ["client-1", "some-other-client"],
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
        // no "azp"
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a multi-audience token with no azp must be refused");
    assert_id_token_invalid(&err, "azp");
}

#[tokio::test]
async fn verify_id_token_accepts_a_multi_audience_token_with_a_matching_azp() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": ["client-1", "some-other-client"],
        "azp": "client-1",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
    });
    let id_token = support::sign_id_token(&claims);

    oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect("a multi-audience token naming client-1 as azp must verify");
}

#[tokio::test]
async fn verify_id_token_rejects_a_token_with_no_iss_claim() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "aud": "client-1",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
        // no "iss" at all
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a token with no iss claim at all must be refused, not silently accepted");
    assert!(matches!(err, AuthError::IdTokenInvalid(_)), "got {err:?}");
}

#[tokio::test]
async fn verify_id_token_rejects_wrong_nonce() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": "client-1",
        "sub": "user-42",
        "nonce": "a-different-nonce",
        "exp": now() + 300,
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a replayed/mismatched nonce must be refused");
    assert_id_token_invalid(&err, "nonce");
}

#[tokio::test]
async fn verify_id_token_rejects_an_expired_token() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": "client-1",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() - 300,
    });
    let id_token = support::sign_id_token(&claims);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("an expired token must be refused");
    assert_id_token_invalid(&err, "expired");
}

#[tokio::test]
async fn verify_id_token_rejects_a_bad_signature() {
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let claims = json!({
        "iss": server.base_url,
        "aud": "client-1",
        "sub": "user-42",
        "nonce": "nonce-1",
        "exp": now() + 300,
    });
    let mut id_token = support::sign_id_token(&claims);
    // Flip the last character of the signature segment.
    let flipped = match id_token.pop() {
        Some('a') => 'b',
        Some(_) => 'a',
        None => panic!("token unexpectedly empty"),
    };
    id_token.push(flipped);

    let err = oidc::verify_id_token(&discovery, "client-1", &id_token, "nonce-1")
        .await
        .expect_err("a tampered signature must be refused");
    assert!(matches!(err, AuthError::IdTokenInvalid(_)));
}

#[tokio::test]
async fn verify_id_token_rejects_the_classic_rs256_to_hs256_alg_confusion_attack() {
    // The fixture JWKS advertises an RSA public key under TEST_KID, meant to
    // *verify* RS256 signatures. The classic "alg confusion" attack forges a
    // token by switching the header to HS256 and (ab)using that same public
    // key's bytes as the HMAC secret — a naive verifier that picks its
    // algorithm from the attacker-controlled header, then blindly looks up
    // "the key for this kid" and treats it as generic key material, accepts
    // it. This only fails safely because `jsonwebtoken` cross-checks the
    // matched JWK's own key *family* (RSA here) against the header's claimed
    // algorithm's family (HS256 is HMAC) and refuses the mismatch outright —
    // `verify_id_token`'s own doc comment asserts this happens, but nothing
    // in this crate had verified it against an actual forged token until
    // now.
    let server = jwks_server().await;
    let discovery = support::discovery_document(&server.base_url);

    let forged_secret = URL_SAFE_NO_PAD
        .decode(support::TEST_RSA_N)
        .expect("fixture RSA modulus is valid base64url");

    let claims = json!({
        "iss": server.base_url,
        "aud": "client-1",
        "sub": "attacker-controlled",
        "nonce": "nonce-1",
        "exp": now() + 300,
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(support::TEST_KID.to_string());
    let forged_token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(&forged_secret),
    )
    .expect("encoding the forged HS256 token");

    let err = oidc::verify_id_token(&discovery, "client-1", &forged_token, "nonce-1")
        .await
        .expect_err("an HS256 token signed with the RSA key's own public bytes must be refused");
    assert!(
        matches!(err, AuthError::IdTokenInvalid(_)),
        "expected IdTokenInvalid, got {err:?}"
    );
}

fn assert_id_token_invalid(err: &AuthError, expected_substring: &str) {
    match err {
        AuthError::IdTokenInvalid(message) => assert!(
            message.to_lowercase().contains(expected_substring),
            "expected {expected_substring:?} in the failure message, got {message:?}"
        ),
        other => panic!("expected AuthError::IdTokenInvalid, got {other:?}"),
    }
}
