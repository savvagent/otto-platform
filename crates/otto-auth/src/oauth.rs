//! The OAuth 2.1 authorization server.
//!
//! Scope is deliberately narrow: one grant (`authorization_code`) plus
//! `refresh_token`, PKCE S256 mandatory, one audience per token. Audiences
//! and their scopes come from the [`crate::resources`] registry. No
//! implicit grant, no password grant, no `plain` challenge method. Most of
//! OAuth's historical footguns are absent because the corresponding features
//! are.
//!
//! Standards implemented here: OAuth 2.1, RFC 8414 (AS metadata), RFC 9728
//! (protected-resource metadata), RFC 7591 (dynamic client registration),
//! RFC 8707 (resource indicators), RFC 7009 (revocation).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{self, prefix};
use crate::error::{AuthError, Result};
use crate::resources::{self, ResourceServer};
use crate::tokens::{self, IssueParams, IssuedTokens, AUTH_CODE_TTL_SECONDS};

// ---------------------------------------------------------------------------
// Redirect URI matching — the highest-consequence function in this file
// ---------------------------------------------------------------------------

/// Does `requested` match a `registered` redirect URI?
///
/// The base rule is **exact string equality**. No prefix matching, no wildcards,
/// no "same origin is close enough": a redirect URI comparison that is looser
/// than exact is an open redirector, and an open redirector on an authorization
/// server hands an attacker authorization codes.
///
/// The one carve-out is RFC 8252 §7.3, and it is not optional — it is what makes
/// CLI agents work at all. A native client listens on a loopback port it cannot
/// know at registration time, so for `http://127.0.0.1`, `http://[::1]` and
/// `http://localhost` the **port is ignored** while scheme, host, path and query
/// must still match exactly.
pub fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }

    let (Ok(reg), Ok(req)) = (url::Url::parse(registered), url::Url::parse(requested)) else {
        return false;
    };

    if !is_loopback_redirect(&reg) || !is_loopback_redirect(&req) {
        return false;
    }

    // Neither a fragment nor userinfo may be smuggled through this branch. The
    // exact-equality test above catches both on any other URI, but the
    // comparison below comes down to scheme, host, path and query, so without
    // this `http://localhost:1/cb#x` and `http://evil.com@localhost:1/cb` would
    // each match a plain registration. Neither changes where the browser
    // actually delivers the code — it dispatches on host — but a fragment does
    // silently break delivery, because `?code=…` appended after a `#` is never
    // sent to the server at all, and the agent waits forever for a code that was
    // issued. Refusing the match turns that into an error the caller can read.
    let clean =
        |u: &url::Url| u.fragment().is_none() && u.username().is_empty() && u.password().is_none();
    if !clean(&reg) || !clean(&req) {
        return false;
    }

    reg.scheme() == req.scheme()
        && reg.host_str() == req.host_str()
        && reg.path() == req.path()
        && reg.query() == req.query()
}

/// A loopback callback over http — the only shape in which cleartext is allowed,
/// and the only shape whose port is ignored when matching.
fn is_loopback_redirect(u: &url::Url) -> bool {
    u.scheme() == "http"
        && matches!(
            u.host_str(),
            Some("127.0.0.1") | Some("[::1]") | Some("::1") | Some("localhost")
        )
}

/// Reject a redirect URI that cannot safely be registered at all.
fn validate_registerable_redirect(uri: &str) -> Result<()> {
    let parsed = url::Url::parse(uri)
        .map_err(|_| AuthError::InvalidRequest(format!("redirect_uri {uri:?} is not a URI")))?;

    // A fragment is never sent to the server and would be silently dropped, so
    // a client registering one has misunderstood something.
    if parsed.fragment().is_some() {
        return Err(AuthError::InvalidRequest(
            "redirect_uri must not contain a fragment".into(),
        ));
    }

    // Plain http is allowed only for literal loopback (native apps). Anything
    // else must be https, or the authorization code crosses the network in the
    // clear.
    if parsed.scheme() == "http" && !is_loopback_redirect(&parsed) {
        return Err(AuthError::InvalidRequest(
            "redirect_uri must use https, except for http on 127.0.0.1, [::1] or localhost".into(),
        ));
    }

    // Credentials in a redirect URI are never part of where the code lands, and
    // a client registering them has either misunderstood the field or is trying
    // to make two different-looking URIs compare equal. Refused for the same
    // reason as the fragment above: say so now rather than at match time.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AuthError::InvalidRequest(
            "redirect_uri must not contain a username or password".into(),
        ));
    }

    // Wildcards are not a thing here, and a client trying one should be told
    // rather than left wondering why matching fails later.
    if uri.contains('*') {
        return Err(AuthError::InvalidRequest(
            "redirect_uri must not contain wildcards; register each URI exactly".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// Verify a PKCE code verifier against the stored challenge. **S256 only.**
///
/// `plain` is refused even though RFC 7636 permits it: it offers no protection
/// against an attacker who can see the authorization request, which is the
/// entire threat model. OAuth 2.1 removes it, and so do we.
pub fn verify_pkce(challenge: &str, method: &str, verifier: &str) -> Result<()> {
    if method != "S256" {
        return Err(AuthError::InvalidGrant(
            "only the S256 code challenge method is supported".into(),
        ));
    }

    // RFC 7636 §4.1: 43–128 characters from an unreserved alphabet. A short
    // verifier is guessable, so the lower bound is a security check.
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(AuthError::InvalidGrant(
            "code_verifier must be 43 to 128 characters".into(),
        ));
    }
    if !verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(AuthError::InvalidGrant(
            "code_verifier contains characters outside the unreserved set".into(),
        ));
    }

    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if crypto::verify(computed.as_bytes(), challenge.as_bytes()) {
        Ok(())
    } else {
        Err(AuthError::InvalidGrant("PKCE verification failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub software_id: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
    pub client_id_issued_at: i64,
}

/// Register a client.
///
/// **This endpoint is open by design** — MCP clients self-register, and
/// requiring an admin to pre-create one would defeat the zero-install premise.
/// That makes it an abuse surface in two distinct ways, and both are handled
/// here rather than assumed away:
///
/// 1. *Spam.* Rate-limited at the HTTP layer by whatever web front end sits in
///    front of this, and registration alone grants nothing — a client is
///    inert until a user consents.
/// 2. *Phishing.* An attacker can register a client called "Claude Code" with
///    their own redirect URI. Nothing here can prevent that, so the defense
///    lives on the consent screen, which **must display the redirect host**
///    rather than the self-asserted name. See [`ConsentDisplay`].
pub async fn register_client(db: &Db, req: RegistrationRequest) -> Result<RegistrationResponse> {
    if req.redirect_uris.is_empty() {
        return Err(AuthError::InvalidRequest(
            "at least one redirect_uri is required".into(),
        ));
    }
    if req.redirect_uris.len() > 10 {
        return Err(AuthError::InvalidRequest(
            "at most 10 redirect_uris may be registered".into(),
        ));
    }
    for uri in &req.redirect_uris {
        validate_registerable_redirect(uri)?;
    }

    // Only the two grants this server implements. A client asking for
    // `password` or `implicit` is told no rather than quietly registered with
    // grants that will fail at the token endpoint.
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    for g in &grant_types {
        if g != "authorization_code" && g != "refresh_token" {
            return Err(AuthError::InvalidRequest(format!(
                "unsupported grant_type {g:?}; this server issues authorization_code and refresh_token only"
            )));
        }
    }

    let client_id = crypto::generate("otto_client_").into_plaintext();

    sqlx::query(
        "INSERT INTO oauth_clients \
           (client_id, client_name, redirect_uris, grant_types, software_id, registered_via_dcr) \
         VALUES ($1,$2,$3,$4,$5,true)",
    )
    .bind(&client_id)
    .bind(req.client_name.as_deref())
    .bind(serde_json::to_value(&req.redirect_uris).unwrap_or_default())
    .bind(serde_json::to_value(&grant_types).unwrap_or_default())
    .bind(req.software_id.as_deref())
    .execute(db.pool())
    .await?;

    Ok(RegistrationResponse {
        client_id,
        client_name: req.client_name,
        redirect_uris: req.redirect_uris,
        grant_types,
        // Public client: no secret. PKCE is the proof of possession, and a
        // secret embedded in a distributed CLI would not be one.
        token_endpoint_auth_method: "none",
        client_id_issued_at: Utc::now().timestamp(),
    })
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub disabled: bool,
}

/// A row from `oauth_clients`. `redirect_uris` is jsonb in the database and a
/// `Vec<String>` in [`Client`], so this intermediate carries the raw value.
#[derive(sqlx::FromRow)]
struct ClientRow {
    client_id: String,
    client_name: Option<String>,
    redirect_uris: serde_json::Value,
    disabled_at: Option<chrono::DateTime<Utc>>,
}

pub async fn get_client(db: &Db, client_id: &str) -> Result<Client> {
    let row: Option<ClientRow> = sqlx::query_as(
        "SELECT client_id, client_name, redirect_uris, disabled_at \
         FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(db.pool())
    .await?;

    let row = row.ok_or_else(|| AuthError::InvalidClient("unknown client".into()))?;

    Ok(Client {
        client_id: row.client_id,
        client_name: row.client_name,
        // A malformed stored value yields an empty list, which fails closed:
        // no redirect URI matches, so no code is ever issued.
        redirect_uris: serde_json::from_value(row.redirect_uris).unwrap_or_default(),
        disabled: row.disabled_at.is_some(),
    })
}

/// What the consent screen must render.
///
/// `client_name` is attacker-controlled through open registration; `redirect_host`
/// is not, because it is where the code will actually be sent. Showing the name
/// alone turns dynamic client registration into a phishing kit, so the host is
/// carried alongside it and the template is expected to show both — with the
/// host given the visual weight.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentDisplay {
    pub client_id: String,
    /// Self-asserted. Render as untrusted.
    pub client_name: Option<String>,
    /// Where the authorization code will be delivered. This is the fact a user
    /// can actually judge.
    pub redirect_host: String,
    /// The resource server the token will be for, from the registry.
    pub resource_name: String,
    pub scopes: Vec<String>,
    pub org_name: String,
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub scopes: Vec<String>,
    pub resource: String,
    pub state: Option<String>,
}

/// A validated authorization request: who is asking, for which resource
/// server, and the scopes the user will be asked to grant.
#[derive(Debug, Clone)]
pub struct Authorization {
    pub client: Client,
    pub resource: ResourceServer,
    /// What the user consents to: the resource server's defaults when the
    /// client asked for nothing, otherwise exactly what it asked for.
    pub scopes: Vec<String>,
}

/// Validate an authorization request before showing a consent screen.
///
/// Order is a security property: the redirect URI is validated **first**,
/// because every later error is reported by redirecting to it. Validating
/// anything else first would mean bouncing an error — with `state` — to an
/// unvalidated destination.
pub async fn validate_authorize(db: &Db, req: &AuthorizeRequest) -> Result<Authorization> {
    let client = get_client(db, &req.client_id).await?;
    if client.disabled {
        return Err(AuthError::InvalidClient("client is disabled".into()));
    }

    if !client
        .redirect_uris
        .iter()
        .any(|r| redirect_uri_matches(r, &req.redirect_uri))
    {
        // Never redirect on this failure — the destination is exactly what we
        // could not verify. Render an error page instead.
        return Err(AuthError::InvalidRequest(
            "redirect_uri does not match a registered URI for this client".into(),
        ));
    }

    if req.code_challenge_method != "S256" {
        return Err(AuthError::InvalidRequest(
            "code_challenge_method must be S256".into(),
        ));
    }
    if req.code_challenge.len() < 43 {
        return Err(AuthError::InvalidRequest(
            "code_challenge is missing or too short".into(),
        ));
    }

    // RFC 8707: the client must say which resource the token is for, and it
    // must be one we issue tokens for. Without this the AS would happily mint
    // tokens audienced for somewhere else.
    let resource = resources::get_active(db, &req.resource).await?;
    let scopes = resource.grant_scopes(&req.scopes)?;
    Ok(Authorization {
        client,
        resource,
        scopes,
    })
}

/// Issue an authorization code after the user consents.
///
/// The code is bound to client, redirect URI, PKCE challenge, user, org, and
/// resource. Every one of those is re-checked at redemption, so a code stolen
/// in transit is useless without the verifier that only the initiating client
/// holds.
///
/// The resource and scopes are resolved again here rather than trusted from
/// the consent screen, so a resource disabled (or a scope removed) between
/// consent and issuance is caught, and the code carries the scopes actually
/// granted — the resource server's defaults when the client asked for none.
pub async fn issue_authorization_code(
    db: &Db,
    req: &AuthorizeRequest,
    user: UserId,
    org: OrgId,
) -> Result<String> {
    let resource = resources::get_active(db, &req.resource).await?;
    let scopes = resource.grant_scopes(&req.scopes)?;
    let code = crypto::generate(prefix::AUTH_CODE);

    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, \
            code_challenge_method, scopes, resource, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $10))",
    )
    .bind(&code.hash)
    .bind(&req.client_id)
    .bind(user)
    .bind(org)
    .bind(&req.redirect_uri)
    .bind(&req.code_challenge)
    .bind(&req.code_challenge_method)
    .bind(&scopes)
    .bind(&resource.resource_uri)
    .bind(AUTH_CODE_TTL_SECONDS as f64)
    .execute(db.pool())
    .await?;

    Ok(code.into_plaintext())
}

/// A claimed row from `authorization_codes`.
#[derive(sqlx::FromRow)]
struct CodeRow {
    client_id: String,
    user_id: UserId,
    org_id: OrgId,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    scopes: Vec<String>,
    resource: String,
    expires_at: chrono::DateTime<Utc>,
}

/// Exchange an authorization code for tokens.
///
/// `requested_resource` is the token request's optional `resource` parameter.
///
/// Single-use, enforced by a conditional UPDATE rather than a read-then-write:
/// two concurrent redemptions of the same stolen code must not both succeed,
/// and only the database can arbitrate that.
pub async fn redeem_code(
    db: &Db,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    code_verifier: &str,
    requested_resource: Option<&str>,
) -> Result<(IssuedTokens, UserId, OrgId)> {
    let hash = crypto::hash(code.trim());

    // Claim the code atomically. `consumed_at IS NULL` in the predicate means
    // the loser of a race gets zero rows and a clean invalid_grant.
    let row: Option<CodeRow> = sqlx::query_as(
        "UPDATE authorization_codes SET consumed_at = now() \
         WHERE code_hash = $1 AND consumed_at IS NULL \
           AND EXISTS (SELECT 1 FROM orgs o \
                        WHERE o.id = authorization_codes.org_id AND o.deleted_at IS NULL) \
         RETURNING client_id, user_id, org_id, redirect_uri, code_challenge, \
                   code_challenge_method, scopes, resource, expires_at",
    )
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;

    let Some(c) = row else {
        // Either unknown or already consumed. A replayed code is a strong theft
        // signal, so revoke anything already issued from it where we can tell.
        if let Some((user, org, client)) = consumed_code_owner(db, &hash).await? {
            tokens::revoke_family(db, user, org, &client).await?;
            return Err(AuthError::InvalidGrant(
                "authorization code was already used; issued tokens have been revoked".into(),
            ));
        }
        return Err(AuthError::InvalidGrant("unknown authorization code".into()));
    };

    if c.expires_at <= Utc::now() {
        return Err(AuthError::InvalidGrant("authorization code expired".into()));
    }
    if c.client_id != client_id {
        return Err(AuthError::InvalidGrant(
            "authorization code was issued to a different client".into(),
        ));
    }
    // Re-check the redirect URI at redemption. RFC 6749 §4.1.3 requires it, and
    // it closes a code-injection path where an attacker redeems a code obtained
    // through a different registered URI.
    if c.redirect_uri != redirect_uri {
        return Err(AuthError::InvalidGrant(
            "redirect_uri does not match the one used to obtain the code".into(),
        ));
    }
    // RFC 8707 §2.2: a token request may repeat `resource`, and if it does it
    // must name the resource the code was issued for.
    if requested_resource.is_some_and(|r| r != c.resource) {
        return Err(AuthError::InvalidGrant(
            "authorization code was issued for a different resource".into(),
        ));
    }
    // Still registered and enabled: disabling a resource server stops new
    // tokens for it, including from codes issued before it was disabled.
    resources::get_active(db, &c.resource).await?;

    verify_pkce(&c.code_challenge, &c.code_challenge_method, code_verifier)?;

    let issued = tokens::issue(
        db,
        IssueParams {
            user_id: c.user_id,
            org_id: c.org_id,
            client_id: Some(client_id),
            scopes: &c.scopes,
            resource: &c.resource,
            with_refresh: true,
        },
    )
    .await?;

    Ok((issued, c.user_id, c.org_id))
}

async fn consumed_code_owner(db: &Db, hash: &[u8]) -> Result<Option<(UserId, OrgId, String)>> {
    let row: Option<(UserId, OrgId, String)> = sqlx::query_as(
        "SELECT user_id, org_id, client_id FROM authorization_codes \
         WHERE code_hash = $1 AND consumed_at IS NOT NULL",
    )
    .bind(hash)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// Delete codes that can no longer be redeemed.
pub async fn sweep_codes(db: &Db) -> Result<u64> {
    let n =
        sqlx::query("DELETE FROM authorization_codes WHERE expires_at < now() - interval '1 hour'")
            .execute(db.pool())
            .await?
            .rows_affected();
    Ok(n)
}

// ---------------------------------------------------------------------------
// Discovery documents
// ---------------------------------------------------------------------------

/// RFC 8414 authorization server metadata, served at
/// `/.well-known/oauth-authorization-server`.
///
/// This document is how every MCP client learns where to register and what to
/// call. Its accuracy is a functional requirement, not documentation — a client
/// will believe it over anything written elsewhere.
///
/// `scopes_supported` is the union across enabled resource servers; see
/// [`resources::all_scopes`].
pub fn as_metadata(public_url: &str, scopes_supported: &[String]) -> serde_json::Value {
    let base = public_url.trim_end_matches('/');
    serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "scopes_supported": scopes_supported,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        // RFC 8707. Advertised so clients know to send `resource`.
        "resource_indicators_supported": true,
    })
}

/// RFC 9728 protected-resource metadata, served at
/// `/.well-known/oauth-protected-resource`.
///
/// A resource server also names this document in a `WWW-Authenticate` header
/// on a 401, which is how an unauthenticated client discovers where to
/// authenticate without being configured with anything but the server URL.
pub fn protected_resource_metadata(
    resource: &ResourceServer,
    public_url: &str,
) -> serde_json::Value {
    let base = public_url.trim_end_matches('/');
    serde_json::json!({
        "resource": resource.resource_uri,
        "resource_name": resource.name,
        "authorization_servers": [base],
        "scopes_supported": resource.scopes,
        "bearer_methods_supported": ["header"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- redirect URI matching: the attack cases ----

    #[test]
    fn exact_match_is_required_for_normal_uris() {
        let reg = "https://app.example.com/callback";
        assert!(redirect_uri_matches(
            reg,
            "https://app.example.com/callback"
        ));

        for attack in [
            "https://evil.com/callback",
            "https://app.example.com.evil.com/callback",
            "https://app.example.com/callback/../evil",
            "https://app.example.com/callback?next=https://evil.com",
            "https://app.example.com/Callback",
            "http://app.example.com/callback",
            "https://app.example.com:8443/callback",
            "https://app.example.com/callback#x",
            "https://user@app.example.com/callback",
        ] {
            assert!(
                !redirect_uri_matches(reg, attack),
                "{attack} must not match {reg}"
            );
        }
    }

    /// RFC 8252 §7.3 — a native client's loopback port is ephemeral and unknown
    /// at registration time. Without this, no CLI agent can complete the flow.
    #[test]
    fn loopback_port_is_ignored() {
        let reg = "http://127.0.0.1:1455/callback";
        assert!(redirect_uri_matches(reg, "http://127.0.0.1:49152/callback"));
        assert!(redirect_uri_matches(reg, "http://127.0.0.1:1/callback"));
        assert!(redirect_uri_matches(
            "http://[::1]:1455/cb",
            "http://[::1]:9/cb"
        ));
    }

    /// The carve-out is for the port and nothing else.
    #[test]
    fn loopback_carve_out_does_not_leak_to_anything_else() {
        let reg = "http://127.0.0.1:1455/callback";
        for attack in [
            "http://127.0.0.1:49152/evil",             // different path
            "http://127.0.0.1:49152/callback?x=1",     // added query
            "http://evil.com:1455/callback",           // different host
            "https://127.0.0.1:1455/callback",         // different scheme
            "http://127.0.0.2:1455/callback",          // adjacent address
            "http://localhost:49152/callback",         // a different loopback name
            "http://localhost.evil.com:1455/callback", // suffix of the name
        ] {
            assert!(
                !redirect_uri_matches(reg, attack),
                "{attack} must not match {reg}"
            );
        }
    }

    /// `localhost` gets the same port carve-out as the literal addresses, and it
    /// has to: this is the exact string Claude Code registers, captured from a
    /// conformance run against the running server.
    #[test]
    fn localhost_gets_the_port_carve_out_because_that_is_what_agents_register() {
        let reg = "http://localhost:3118/callback";
        assert!(validate_registerable_redirect(reg).is_ok());
        assert!(redirect_uri_matches(reg, "http://localhost:3118/callback"));
        assert!(redirect_uri_matches(reg, "http://localhost:49152/callback"));

        // The carve-out is still the port and nothing else.
        assert!(!redirect_uri_matches(reg, "http://localhost:3118/evil"));
        assert!(!redirect_uri_matches(reg, "http://127.0.0.1:3118/callback"));
        assert!(!redirect_uri_matches(
            reg,
            "https://localhost:3118/callback"
        ));
    }

    /// The loopback branch compares scheme, host, path and query — so anything
    /// it does *not* compare has to be refused outright, or it becomes a way to
    /// make two different URIs match.
    #[test]
    fn the_loopback_branch_refuses_what_it_does_not_compare() {
        let reg = "http://localhost:3118/callback";

        // A fragment: the browser keeps it, so `?code=…` appended afterwards is
        // never sent and the client waits for a code it will never see.
        assert!(!redirect_uri_matches(
            reg,
            "http://localhost:49152/callback#x"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1/cb#x",
            "http://127.0.0.1:2/cb"
        ));

        // Userinfo: not where the code lands, and not compared below.
        assert!(!redirect_uri_matches(
            reg,
            "http://evil.com@localhost:49152/callback"
        ));
        assert!(!redirect_uri_matches(
            reg,
            "http://user:pw@localhost:49152/callback"
        ));

        // And neither may be registered in the first place.
        assert!(validate_registerable_redirect("http://evil.com@localhost:3118/cb").is_err());
        assert!(validate_registerable_redirect("https://user:pw@app.example.com/cb").is_err());
    }

    #[test]
    fn registerable_uris_are_screened() {
        assert!(validate_registerable_redirect("https://app.example.com/cb").is_ok());
        assert!(validate_registerable_redirect("http://127.0.0.1:1455/cb").is_ok());
        assert!(validate_registerable_redirect("http://[::1]:1455/cb").is_ok());
        assert!(validate_registerable_redirect("http://localhost:1455/cb").is_ok());

        // Cleartext to anywhere but loopback.
        assert!(validate_registerable_redirect("http://app.example.com/cb").is_err());
        // Fragments are never delivered to the server.
        assert!(validate_registerable_redirect("https://app.example.com/cb#frag").is_err());
        // Wildcards are not supported and must be refused loudly.
        assert!(validate_registerable_redirect("https://*.example.com/cb").is_err());
        assert!(validate_registerable_redirect("not a uri").is_err());
    }

    // ---- PKCE ----

    #[test]
    fn pkce_s256_round_trips() {
        let verifier = "a".repeat(64);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert!(verify_pkce(&challenge, "S256", &verifier).is_ok());
    }

    #[test]
    fn pkce_rejects_the_wrong_verifier() {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest("a".repeat(64).as_bytes()));
        assert!(verify_pkce(&challenge, "S256", &"b".repeat(64)).is_err());
    }

    /// `plain` offers no protection against an attacker who can observe the
    /// authorization request, which is the whole threat. OAuth 2.1 removes it.
    #[test]
    fn pkce_plain_is_refused_even_when_it_would_match() {
        let verifier = "a".repeat(64);
        assert!(verify_pkce(&verifier, "plain", &verifier).is_err());
        assert!(verify_pkce(&verifier, "", &verifier).is_err());
        assert!(verify_pkce(&verifier, "s256", &verifier).is_err());
    }

    #[test]
    fn pkce_enforces_verifier_length_and_alphabet() {
        let short = "a".repeat(42);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(short.as_bytes()));
        assert!(
            verify_pkce(&challenge, "S256", &short).is_err(),
            "42 chars is too short"
        );

        let long = "a".repeat(129);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(long.as_bytes()));
        assert!(
            verify_pkce(&challenge, "S256", &long).is_err(),
            "129 chars is too long"
        );

        let bad = format!("{}!", "a".repeat(50));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(bad.as_bytes()));
        assert!(
            verify_pkce(&challenge, "S256", &bad).is_err(),
            "'!' is outside the alphabet"
        );
    }
}
