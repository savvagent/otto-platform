//! The OIDC authorization-code client for enterprise SSO federation.
//!
//! Pure client logic, no SQL — see otto-factory's `docs/specs/2026-09-16-oidc-federation-design.md`
//! §4. `otto_core::idp` owns `idp_connections.discovery`'s storage; this module only
//! fetches it, builds the authorization URL from it, exchanges a code for tokens
//! against it, and verifies a returned `id_token` against the IdP's JWKS.
//!
//! Four steps, one function each: [`fetch_discovery`], [`authorization_url`],
//! [`exchange_code`], [`verify_id_token`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

use crate::error::{AuthError, Result};
use crate::ssrf::{is_publicly_routable, PinnedResolver, ResolveError};

/// The outbound calls here happen inline in a browser-facing request (the
/// admin binding a connection, or the callback exchanging a code) — a
/// stalled IdP must not hang that request forever. reqwest sets no timeout
/// by default.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// An operator-facing error body is diagnostic text, not something to echo
/// back whole — bounded the same way otto-factory's tracker clients' `MAX_ERROR_BODY_BYTES`
/// bounds a GitHub/JIRA error body (a byte bound, not a `char` count — see
/// [`truncate`]).
const MAX_ERROR_BODY_BYTES: usize = 256;

/// How long a fetched JWKS document is trusted before this module fetches it
/// again. Short-lived, per spec §4 — long enough that a login doesn't refetch
/// the JWKS on every callback, short enough that a key rotation on the IdP's
/// side propagates without the service needing a restart.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// `reqwest::Client` owns a connection pool and TLS context and is meant to
/// be built once and reused — matching otto-factory's GitHub/JIRA tracker clients,
/// which store their client on the client struct rather than rebuilding it
/// per call. This module has no long-lived client struct of its own (every
/// function here is a free function taking a discovery document), so the
/// client lives in a `OnceLock` instead — same lifetime, same reuse, no
/// per-call rebuild of the pool.
///
/// Fails closed: if the builder errors, this panics (via `expect`) instead
/// of falling back to a default `reqwest::Client`. A default client would have
/// neither the [`PinnedResolver`] nor the no-redirect policy, silently
/// reopening the SSRF this module exists to prevent. `build()` only fails on
/// an invalid TLS backend configuration, which is fixed at compile time by
/// this workspace's `reqwest` feature flags, so a failure here is a
/// startup/config bug that must be loud, not a runtime condition to degrade
/// through. No other `reqwest::Client` is constructed in this crate.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            // Every URL this client fetches — the issuer, and the
            // token_endpoint/jwks_uri read back out of a stored discovery
            // document — is validated by require_safe_url() immediately
            // before the request that uses it (see that function's doc
            // comment for why bind-time-only validation isn't enough).
            // Redirects would let a validated, safe first hop 30x to an
            // unvalidated second one, so following them is refused
            // outright rather than re-validated per hop.
            .redirect(reqwest::redirect::Policy::none())
            // Resolve once, vet every address, and pin the connection to the
            // vetted set — closes DNS rebinding (see `ssrf::PinnedResolver`).
            .dns_resolver(Arc::new(PinnedResolver::system()))
            .build()
            .expect("OIDC HTTP client must build; refusing to fall back to an unpinned client")
    })
}

/// Maps a failed `send()` to an [`AuthError`]. A refusal by the
/// [`PinnedResolver`] (host resolves to a non-public address, to nothing, or
/// not at all) happens inside the connector, so reqwest reports it as a
/// generic connect error with the resolver's error buried in the source
/// chain. Find it by downcasting along `Error::source()` (not by matching on
/// message text) and surface it as [`AuthError::OidcUnsafeUrl`] for `field`.
fn send_error(action: &'static str, field: &'static str, source: reqwest::Error) -> AuthError {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&source);
    while let Some(err) = cause {
        if let Some(refused) = err.downcast_ref::<ResolveError>() {
            return AuthError::OidcUnsafeUrl {
                field,
                reason: refused.to_string(),
            };
        }
        cause = err.source();
    }
    AuthError::OidcHttp { action, source }
}

/// Rejects a URL this server is about to fetch (`fetch_discovery`'s
/// `issuer`, or `exchange_code`/`fetch_jwks`'s `token_endpoint`/`jwks_uri`
/// read out of a stored discovery document) unless it is `https` and its
/// host cannot be an internal address.
///
/// **Why every call site, not just bind time.** `issuer` is admin-typed,
/// but `token_endpoint` and `jwks_uri` are not admin input at all — they
/// are read straight out of whatever JSON the issuer's own
/// `/.well-known/openid-configuration` returned, and that document is
/// fetched fresh (or served from cache, itself only ever populated from a
/// fetch) on every sign-in. An admin who is honest at bind time but whose
/// `issuer` is later compromised, or an issuer that simply publishes a
/// `jwks_uri` pointing at `http://169.254.169.254/...`, would otherwise
/// turn this server into a general-purpose internal-network prober from an
/// unauthenticated endpoint (`/sso/callback`) on every login attempt. Any
/// admin can create their own org (`org creation` needs only a confirmed
/// passkey, not a platform-level trust decision), so `require_admin()`
/// guarding `PUT .../sso/connection` is not itself a meaningful barrier —
/// the check has to hold regardless of who is making the request.
///
/// **Division of labour.** A *domain* host is not resolved here: the shared
/// client's [`PinnedResolver`] resolves it once at connect time, classifies
/// every address, and the connection is pinned to exactly those addresses, so
/// there is no check-then-use window for DNS rebinding. reqwest never
/// consults a resolver for an IP-*literal* host, so this function classifies
/// literals itself. Redirects are refused outright (`http_client()`'s
/// `Policy::none()`), so no second, unvalidated hop exists either.
fn require_safe_url(raw: &str, field: &'static str) -> Result<Url> {
    let unsafe_url = |reason: &str| AuthError::OidcUnsafeUrl {
        field,
        reason: reason.to_string(),
    };

    let url = Url::parse(raw).map_err(|_| unsafe_url("not a valid URL"))?;
    let literal_ip = match url.host() {
        None => return Err(unsafe_url("no host")),
        Some(Host::Domain(_)) => None,
        Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
    };

    if let Some(ip) = literal_ip {
        if !is_publicly_routable(&ip) {
            return Err(unsafe_url(&format!(
                "resolves to a non-public address ({ip})"
            )));
        }
    }

    // `http` is allowed only under `test-support`, and only for a loopback IP
    // literal (the crate's own mock server) — never for a named host, so a
    // Cargo feature cannot widen what a real build refuses to fetch.
    let loopback_literal = literal_ip.is_some_and(|ip| ip.is_loopback());
    let scheme_ok = url.scheme() == "https" || (cfg!(feature = "test-support") && loopback_literal);
    if !scheme_ok {
        return Err(unsafe_url("scheme must be https"));
    }

    Ok(url)
}

/// The largest response body this client will buffer into memory from a
/// discovery document, a token-endpoint response, or a JWKS document. Every
/// one of these three URLs is admin- or IdP-controlled (§4/Assumptions in
/// the design spec makes the same point about *where* they're dialed from);
/// without a cap, a hostile or compromised IdP could push an unbounded body
/// at this process on every sign-in attempt through the unauthenticated
/// `/sso/callback` path. 1 MiB is generously larger than any real discovery
/// document, token response, or JWKS this design ever needs to parse.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Reads `response`'s body up to `max_bytes`, refusing (not silently
/// truncating) if the server sends more. Streamed rather than
/// `response.bytes()`/`response.text()`'s "buffer it all, then look" shape
/// — a `Content-Length` header is untrusted input from the same server this
/// cap exists to bound, so the limit has to be enforced as bytes actually
/// arrive, not checked against a header the server is free to omit or lie
/// about.
async fn read_capped(
    action: &'static str,
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| AuthError::OidcHttp { action, source })?;
        if body.len() + chunk.len() > max_bytes {
            // Not a real HTTP status — reused to mean "the response body
            // itself was the problem, not the transport or the IdP's own
            // status code."
            return Err(AuthError::OidcApi {
                action,
                status: 0,
                body: format!("response exceeded {max_bytes} bytes"),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_json_capped<T: DeserializeOwned>(
    action: &'static str,
    response: reqwest::Response,
) -> Result<T> {
    let bytes = read_capped(action, response, MAX_RESPONSE_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|source| AuthError::OidcApi {
        action,
        status: 0,
        body: format!("could not parse the response as JSON: {source}"),
    })
}

async fn response_body_snippet(action: &'static str, response: reqwest::Response) -> String {
    match read_capped(action, response, MAX_ERROR_BODY_BYTES.max(4096)).await {
        Ok(bytes) => truncate(&String::from_utf8_lossy(&bytes), MAX_ERROR_BODY_BYTES),
        Err(_) => String::new(),
    }
}

/// Truncates `input` to at most `max_bytes` bytes, backing off to the
/// nearest preceding UTF-8 character boundary so a multi-byte character is
/// never split — mirrors otto-factory's tracker clients' identical helper (`github.rs`/
/// `jira.rs`) used for the same purpose (bounding an echoed third-party
/// error body).
fn truncate(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &input[..end])
}

/// Reads a required string field out of a cached discovery document.
/// Every one of `authorization_url`/`exchange_code`/`verify_id_token` calls
/// this for the one field it needs, which is what makes a discovery document
/// missing `authorization_endpoint`/`token_endpoint`/`jwks_uri` fail at the
/// exact point it's used — the HTTP layer's `PUT .../sso/connection` handler (Phase 4)
/// is expected to exercise all three at bind time so a connection is
/// never saved half-configured, per the design spec's Error Handling section.
fn discovery_str<'a>(discovery: &'a Value, field: &'static str) -> Result<&'a str> {
    discovery
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AuthError::OidcDiscoveryField(field))
}

/// Fetches `{issuer}/.well-known/openid-configuration` and returns the raw
/// JSON body verbatim — `otto_core::idp::upsert_connection`'s caller stores
/// this directly into `idp_connections.discovery`. No field validation here;
/// see [`discovery_str`] for where a missing field actually surfaces.
pub async fn fetch_discovery(issuer: &str) -> Result<Value> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let url = require_safe_url(&url, "issuer")?;
    let client = http_client();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|source| send_error("fetching the discovery document", "issuer", source))?;

    let status = response.status();
    if !status.is_success() {
        let body = response_body_snippet("fetching the discovery document", response).await;
        return Err(AuthError::OidcApi {
            action: "fetching the discovery document",
            status: status.as_u16(),
            body,
        });
    }

    read_json_capped("parsing the discovery document", response).await
}

/// Builds the authorization-code redirect URL from a cached discovery
/// document. `scope=openid email profile` — an OIDC login only ever needs the
/// caller's email for the account it's pinning, and `profile` for a display
/// name; nothing wider is requested.
pub fn authorization_url(
    discovery: &Value,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
) -> Result<Url> {
    let endpoint = discovery_str(discovery, "authorization_endpoint")?;
    let mut url = Url::parse(endpoint)
        .map_err(|_| AuthError::OidcDiscoveryField("authorization_endpoint"))?;
    // Every other discovery URL is fetched server-side and goes through
    // require_safe_url. This one never is — it's handed straight to the
    // browser as `window.location.assign(...)` (see settings/+page.svelte
    // and login/+page.svelte) — so an admin-supplied `javascript:` or
    // `data:` URI here is a DOM XSS in the console origin, not an SSRF.
    // require_discovery_fields rejects a non-https scheme at bind time too;
    // this check is what protects every sign-in against a connection that
    // predates that check, or a discovery document that changed since.
    //
    // No DNS resolution here (this function is sync, unlike require_safe_url) —
    // the test-support relaxation below matches on the host already being a
    // loopback IP *literal*, which is what the crate's own mock server binds
    // to, rather than repeating require_safe_url's async lookup.
    if url.scheme() != "https" {
        let is_test_loopback = cfg!(feature = "test-support")
            && url
                .host_str()
                .and_then(|h| h.parse::<IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
        if !is_test_loopback {
            return Err(AuthError::OidcUnsafeUrl {
                field: "authorization_endpoint",
                reason: "scheme must be https — this URL is navigated to directly by the browser"
                    .to_string(),
            });
        }
    }
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("nonce", nonce);
    Ok(url)
}

/// The token endpoint's response. Only the fields this design ever reads are
/// named explicitly; `serde` ignores anything else the IdP sends.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub id_token: String,
}

/// Exchanges an authorization code for tokens. `client_secret` is the
/// **opened** plaintext — the caller (the HTTP layer's callback handler) holds it
/// only for the duration of this call, having just opened it via
/// `otto_core::crypto::Cipher::open` from `idp::get_connection_secret`'s sealed
/// pair; it is never logged and never returned by this function.
pub async fn exchange_code(
    discovery: &Value,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<TokenResponse> {
    let token_endpoint = discovery_str(discovery, "token_endpoint")?;
    let token_endpoint = require_safe_url(token_endpoint, "token_endpoint")?;
    let client = http_client();
    let response = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|source| {
            send_error(
                "exchanging the authorization code",
                "token_endpoint",
                source,
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        // Redaction happens *before* truncation, and against both the raw
        // and the form-urlencoded forms of every credential-bearing value
        // submitted in the request — not just the client secret: a
        // non-conformant or compromised token endpoint that echoes the
        // submitted form back in its error body would otherwise put the
        // plaintext client secret, or the (single-use, but still
        // bearer-shaped) authorization code, into whatever logs this
        // error's Display text reaches (the HTTP layer's callback handler logs the
        // full AuthError on this exact failure). response_body_snippet
        // truncates to MAX_ERROR_BODY_BYTES first, which would leave a
        // secret straddling that boundary as an unmatched partial substring
        // — read the same bound directly instead, redact, then truncate.
        let bytes = read_capped(
            "exchanging the authorization code",
            response,
            MAX_ERROR_BODY_BYTES.max(4096),
        )
        .await
        .unwrap_or_default();
        let mut body = String::from_utf8_lossy(&bytes).into_owned();
        for secret in [client_secret, code] {
            if secret.is_empty() {
                continue;
            }
            body = body.replace(secret, "[redacted]");
            let percent_encoded: String =
                url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
            if percent_encoded != secret {
                body = body.replace(&percent_encoded, "[redacted]");
            }
        }
        let body = truncate(&body, MAX_ERROR_BODY_BYTES);
        return Err(AuthError::OidcApi {
            action: "exchanging the authorization code",
            status: status.as_u16(),
            body,
        });
    }

    read_json_capped("parsing the token response", response).await
}

/// Claims extracted from a verified `id_token` — exactly the fields this
/// design consumes, nothing else deserialized.
///
/// **This struct's fields are never enforced by [`verify_id_token`] itself,
/// and `email_verified` is the one that matters: do not add a check here
/// that refuses on `email_verified != Some(true)`.** Whether an unverified
/// email is trustworthy is a question about *this feature's* trust
/// requirement, not about whether the token is genuinely, freshly, and
/// correctly-audienced from the issuer it claims to be from — those are two
/// separate, equally-required questions, and `verify_id_token`'s job is only
/// the second one. The caller — the HTTP layer's `/sso/callback` handler — is the
/// one place that knows the first check is required before anything reads
/// `claims.email`; folding it in here would make it easy for a future
/// change to "clean up" by moving a callback-only requirement into a shared
/// library function, silently applying (or, worse, failing to apply) it to
/// every future caller of this module. See
/// `docs/specs/2026-09-16-oidc-federation-design.md` §4/§5 for the full
/// reasoning and the account-takeover shape this closes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

/// Superset of [`Claims`] used only inside [`verify_id_token`], to read the
/// anti-replay `nonce` claim — `nonce` is not part of the public `Claims`
/// shape this design hands its callers, since nothing past this function
/// needs it once the check below has run.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    nonce: Option<String>,
    // `aud` and `azp` are read only for the OIDC Core §3.1.3.7 steps 3-5
    // check below — `jsonwebtoken`'s own `set_audience` only checks that
    // `client_id` is *one of* possibly several audiences, which is not the
    // same requirement. `aud` is untyped because the claim is legally either
    // a bare string or an array of strings.
    #[serde(default)]
    aud: Option<Value>,
    #[serde(default)]
    azp: Option<String>,
}

struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

fn jwks_cache() -> &'static RwLock<HashMap<String, CachedJwks>> {
    static CACHE: OnceLock<RwLock<HashMap<String, CachedJwks>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn fetch_jwks(jwks_uri: &str) -> Result<JwkSet> {
    // The lock is only ever held across a plain HashMap read/insert, never
    // across the network call below or anything else that can panic — so a
    // poisoned guard cannot mean this map is actually inconsistent, only
    // that some *other*, unrelated panic happened while a guard was held.
    // Recovering it (rather than propagating an error) is what keeps a
    // one-off panic elsewhere in the process from permanently degrading SSO
    // sign-in for every org sharing this process-wide cache until restart.
    if let Some(cached) = jwks_cache()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(jwks_uri)
    {
        if cached.fetched_at.elapsed() < JWKS_CACHE_TTL {
            return Ok(cached.jwks.clone());
        }
    }

    let jwks_url = require_safe_url(jwks_uri, "jwks_uri")?;
    let client = http_client();
    let response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|source| send_error("fetching the JWKS document", "jwks_uri", source))?;

    let status = response.status();
    if !status.is_success() {
        let body = response_body_snippet("fetching the JWKS document", response).await;
        return Err(AuthError::OidcApi {
            action: "fetching the JWKS document",
            status: status.as_u16(),
            body,
        });
    }

    let jwks: JwkSet = read_json_capped("parsing the JWKS document", response).await?;

    jwks_cache()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            jwks_uri.to_string(),
            CachedJwks {
                jwks: jwks.clone(),
                fetched_at: Instant::now(),
            },
        );

    Ok(jwks)
}

/// Verifies an `id_token`'s signature against the IdP's JWKS (matched by the
/// token header's `kid`), then checks `iss == discovery.issuer`, `aud`
/// contains `client_id`, `exp` has not passed, and `nonce == expected_nonce`.
///
/// The signing key's algorithm family (RSA/EC/HMAC, read from the matched
/// JWK) is cross-checked against the token header's claimed algorithm by
/// `jsonwebtoken` itself before the signature is even checked — an attacker
/// cannot present an HMAC-signed token keyed off the IdP's RSA public key and
/// have it accepted (the classic "alg confusion" attack), because the key
/// family and the claimed algorithm's family must agree.
///
/// Does **not** enforce `email_verified` — see [`Claims`]'s doc comment.
pub async fn verify_id_token(
    discovery: &Value,
    client_id: &str,
    id_token: &str,
    expected_nonce: &str,
) -> Result<Claims> {
    let issuer = discovery_str(discovery, "issuer")?;
    let jwks_uri = discovery_str(discovery, "jwks_uri")?;
    let jwks = fetch_jwks(jwks_uri).await?;

    let header = jsonwebtoken::decode_header(id_token).map_err(|source| {
        AuthError::IdTokenInvalid(format!("could not read the token header: {source}"))
    })?;
    let kid = header
        .kid
        .ok_or_else(|| AuthError::IdTokenInvalid("token header has no kid".into()))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| AuthError::IdTokenInvalid(format!("no signing key matches kid {kid:?}")))?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|source| {
        AuthError::IdTokenInvalid(format!("signing key is unusable: {source}"))
    })?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer]);
    validation.validate_exp = true;
    // `set_audience`/`set_issuer` only compare a claim against the expected
    // value *when the claim is present* — jsonwebtoken's default
    // `required_spec_claims` is just `{"exp"}`, so an id_token that omits
    // `aud` or `iss` entirely satisfies both checks by having nothing to
    // compare. Without this, a token minted for a *different* relying party
    // under the same IdP signing key — carrying no `aud` at all — would
    // verify here. Require all three explicitly present.
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|source| {
            AuthError::IdTokenInvalid(format!("token failed verification: {source}"))
        })?;

    if token_data.claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(AuthError::IdTokenInvalid(
            "nonce did not match this sign-in attempt".into(),
        ));
    }

    // OIDC Core §3.1.3.7 steps 3-5: a multi-valued `aud` is only acceptable
    // when `azp` is present and equals `client_id` — `set_audience` above
    // already confirmed `client_id` is *among* the audiences, but a token
    // minted for several relying parties at once, one of which is us, is
    // not proof this token was issued *for* this sign-in unless `azp` says
    // so explicitly.
    let aud_is_multi_valued =
        matches!(&token_data.claims.aud, Some(Value::Array(values)) if values.len() > 1);
    if aud_is_multi_valued && token_data.claims.azp.as_deref() != Some(client_id) {
        return Err(AuthError::IdTokenInvalid(
            "aud names more than one audience and azp does not identify this client".into(),
        ));
    }

    Ok(Claims {
        sub: token_data.claims.sub,
        email: token_data.claims.email,
        email_verified: token_data.claims.email_verified,
    })
}

#[cfg(test)]
mod ssrf_guard_tests {
    use super::*;

    // The address classifier and resolver have their own tests in `ssrf.rs`;
    // these cover the URL-level checks that stay here.

    #[test]
    fn rejects_a_non_https_scheme_outside_test_support() {
        // Must fail even under `test-support`, since the http exception there
        // only covers loopback IP literals.
        for url in ["http://example.com/foo", "http://localhost:8080/foo"] {
            let err = require_safe_url(url, "issuer")
                .expect_err("a non-https, non-loopback-literal URL must be refused");
            assert!(matches!(err, AuthError::OidcUnsafeUrl { .. }), "{err:?}");
        }
    }

    #[test]
    fn rejects_ip_literal_hosts_the_resolver_never_sees() {
        for url in [
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/",
            "https://[fdaa::1]/",
            "https://[64:ff9b::a9fe:a9fe]/",
            "https://[::ffff:169.254.169.254]/",
            // url normalises these numeric forms to a dotted quad.
            "https://2852039166/",
            "https://0xa9fea9fe/",
        ] {
            let err = require_safe_url(url, "jwks_uri").expect_err(url);
            assert!(
                matches!(err, AuthError::OidcUnsafeUrl { .. }),
                "{url}: {err:?}"
            );
        }
    }

    #[test]
    fn accepts_https_domains_and_public_literals() {
        assert!(require_safe_url("https://idp.example.com/x", "issuer").is_ok());
        assert!(require_safe_url("https://8.8.8.8/x", "issuer").is_ok());
    }

    struct FixedLookup(&'static str);
    impl crate::ssrf::Lookup for FixedLookup {
        fn lookup<'a>(
            &'a self,
            _host: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'a>,
        > {
            let ip: IpAddr = self.0.parse().unwrap();
            Box::pin(async move { Ok(vec![ip]) })
        }
    }

    #[tokio::test]
    async fn a_resolver_refusal_surfaces_as_oidc_unsafe_url_for_the_field() {
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PinnedResolver::new(FixedLookup("10.255.255.1"))))
            .build()
            .unwrap();
        let source = client
            .get("https://private.test/")
            .send()
            .await
            .expect_err("private answer must be refused");
        match send_error("fetching the JWKS document", "jwks_uri", source) {
            AuthError::OidcUnsafeUrl { field, reason } => {
                assert_eq!(field, "jwks_uri");
                assert!(reason.contains("10.255.255.1"), "{reason}");
            }
            other => panic!("expected OidcUnsafeUrl, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_ordinary_connect_failure_stays_oidc_http() {
        // Port 1 on an IP literal: refused connection, no resolver involved.
        let source = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .expect_err("nothing listens on port 1");
        assert!(matches!(
            send_error("fetching the discovery document", "issuer", source),
            AuthError::OidcHttp { .. }
        ));
    }

    #[test]
    fn the_shared_client_builds() {
        let _ = http_client();
    }
}
