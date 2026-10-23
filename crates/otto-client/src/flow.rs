//! The OAuth flows: browser login (authorization code + PKCE S256 on a
//! loopback redirect) and refresh.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::discovery::{self, Discovered};
use crate::error::{Error, Result};
use crate::pkce::{random_token, Pkce};
use crate::store::{Grant, Store};
use crate::Opener;

/// How long to wait for the person to finish in the browser.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
/// A token this close to expiry is refreshed rather than handed out.
const EXPIRY_SKEW_SECS: u64 = 30;

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// The server's OAuth error, reduced to its `error` code and description. The
/// body is never echoed as-is.
async fn oauth_error(resp: reqwest::Response) -> (String, String) {
    let status = resp.status();
    match resp.json::<OAuthError>().await {
        Ok(e) => (e.error, e.error_description.unwrap_or_default()),
        Err(_) => (String::new(), format!("server returned {status}")),
    }
}

pub(crate) async fn login(
    http: &reqwest::Client,
    store: &Store,
    opener: &dyn Opener,
    resource: &str,
    scopes: &[String],
) -> Result<()> {
    let meta = discovery::discover(http, resource).await?;
    let client_id = client_id(http, store, &meta).await?;

    // Port 0: the OS picks a free one. otto-auth ignores the port of a
    // loopback redirect when matching (RFC 8252 section 7.3).
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| Error::io("opening the loopback listener", &e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::io("opening the loopback listener", &e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let pkce = Pkce::generate();
    let state = random_token(24);
    let mut authorize = meta.authorization_endpoint.clone();
    {
        let mut q = authorize.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", resource)
            .append_pair("state", &state);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }

    eprintln!("Opening your browser to sign in. If it does not open, visit:\n  {authorize}");
    // A failure to launch a browser is not fatal: the URL is printed above.
    let _ = opener.open(&authorize);

    let code = tokio::time::timeout(CALLBACK_TIMEOUT, wait_for_code(&listener, &state))
        .await
        .map_err(|_| Error::Authorization("timed out waiting for the browser".into()))??;

    let resp = http
        .post(meta.token_endpoint.clone())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", pkce.verifier.as_str()),
            ("client_id", client_id.as_str()),
            ("resource", resource),
        ])
        .send()
        .await
        .map_err(|_| Error::Network(meta.token_endpoint.to_string()))?;
    if !resp.status().is_success() {
        let (code, desc) = oauth_error(resp).await;
        return Err(Error::Authorization(
            format!("{code} {desc}").trim().to_owned(),
        ));
    }
    let token: TokenResponse = resp.json().await.map_err(|_| {
        Error::Authorization("the token endpoint sent an unreadable response".into())
    })?;

    store.put_grant(resource, grant_from(token, &meta.issuer, &client_id, None))
}

async fn client_id(http: &reqwest::Client, store: &Store, meta: &Discovered) -> Result<String> {
    if let Some(id) = store.client_id(&meta.issuer)? {
        return Ok(id);
    }
    #[derive(Deserialize)]
    struct Registered {
        client_id: String,
    }
    let resp = http
        .post(meta.registration_endpoint.clone())
        .json(&serde_json::json!({
            "client_name": "otto cli",
            "software_id": "otto-cli",
            // No port: the loopback port is chosen per login.
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
        }))
        .send()
        .await
        .map_err(|_| Error::Network(meta.registration_endpoint.to_string()))?;
    if !resp.status().is_success() {
        let (code, desc) = oauth_error(resp).await;
        return Err(Error::Authorization(
            format!("registration refused: {code} {desc}")
                .trim()
                .to_owned(),
        ));
    }
    let registered: Registered = resp
        .json()
        .await
        .map_err(|_| Error::Authorization("registration sent an unreadable response".into()))?;
    store.put_client(&meta.issuer, &registered.client_id)?;
    Ok(registered.client_id)
}

fn grant_from(
    t: TokenResponse,
    issuer: &str,
    client_id: &str,
    prior_refresh: Option<String>,
) -> Grant {
    Grant {
        issuer: issuer.to_owned(),
        client_id: client_id.to_owned(),
        access_token: t.access_token,
        // A refresh response may omit the refresh token, meaning keep the old one.
        refresh_token: t.refresh_token.or(prior_refresh),
        expires_at: now() + t.expires_in.unwrap_or(0),
        scope: t.scope.unwrap_or_default(),
    }
}

/// Accept connections until one carries the callback for this login's `state`.
/// Anything else (a favicon request, a probe, a wrong state) is answered and
/// ignored, so a stray local process cannot cancel the login.
async fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut sock, _) = listener
            .accept()
            .await
            .map_err(|e| Error::io("accepting the browser callback", &e))?;
        let Some(target) = read_request_target(&mut sock).await else {
            continue;
        };
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            respond(&mut sock, "400 Bad Request", "Bad request.").await;
            continue;
        };
        if url.path() != "/callback" {
            respond(&mut sock, "404 Not Found", "Not found.").await;
            continue;
        }
        let param = |k: &str| {
            url.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
        };
        if param("state").as_deref() != Some(state) {
            respond(
                &mut sock,
                "400 Bad Request",
                "This sign-in link is not for this session.",
            )
            .await;
            continue;
        }
        if let Some(err) = param("error") {
            respond(
                &mut sock,
                "200 OK",
                "Sign-in was not completed. You can close this tab.",
            )
            .await;
            let desc = param("error_description").unwrap_or_default();
            return Err(Error::Authorization(
                format!("{err} {desc}").trim().to_owned(),
            ));
        }
        let Some(code) = param("code") else {
            respond(&mut sock, "400 Bad Request", "No authorization code.").await;
            continue;
        };
        respond(
            &mut sock,
            "200 OK",
            "Signed in. You can close this tab and return to the terminal.",
        )
        .await;
        return Ok(code);
    }
}

async fn read_request_target(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // The request line is all that is needed, and a hostile or broken client
    // gets a bounded read.
    while buf.len() < 8192 && !buf.windows(2).any(|w| w == b"\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8_lossy(buf.split(|b| *b == b'\r').next()?).into_owned();
    let mut parts = line.split(' ');
    (parts.next()? == "GET").then(|| parts.next().map(str::to_owned))?
}

async fn respond(sock: &mut TcpStream, status: &str, body: &str) {
    let html = format!("<!doctype html><meta charset=utf-8><title>otto</title><p>{body}</p>");
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    let _ = sock.write_all(msg.as_bytes()).await;
    let _ = sock.shutdown().await;
}

/// A usable access token for `resource`: the cached one if it has time left,
/// else a refreshed one. A grant that cannot be refreshed is dropped and the
/// person is told to log in again.
pub(crate) async fn fresh_grant(
    http: &reqwest::Client,
    store: &Store,
    resource: &str,
) -> Result<Option<Grant>> {
    let Some(grant) = store.grant(resource)? else {
        return Ok(None);
    };
    if grant.expires_at > now() + EXPIRY_SKEW_SECS {
        return Ok(Some(grant));
    }
    let login_required = || Error::LoginRequired {
        resource: resource.to_owned(),
    };
    let Some(refresh) = grant.refresh_token.clone() else {
        store.remove_grant(resource)?;
        return Err(login_required());
    };
    let meta = discovery::discover(http, resource).await?;
    let resp = http
        .post(meta.token_endpoint.clone())
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", grant.client_id.as_str()),
            ("resource", resource),
        ])
        .send()
        .await
        .map_err(|_| Error::Network(meta.token_endpoint.to_string()))?;
    if !resp.status().is_success() {
        let (code, desc) = oauth_error(resp).await;
        // The grant was revoked or expired, or the client is unknown: nothing
        // to retry. Anything else (a 5xx, rate limiting) leaves it in place.
        if matches!(code.as_str(), "invalid_grant" | "invalid_client") {
            store.remove_grant(resource)?;
            if code == "invalid_client" {
                store.remove_client(&meta.issuer)?;
            }
            return Err(login_required());
        }
        return Err(Error::Authorization(
            format!("{code} {desc}").trim().to_owned(),
        ));
    }
    let token: TokenResponse = resp.json().await.map_err(|_| {
        Error::Authorization("the token endpoint sent an unreadable response".into())
    })?;
    let renewed = grant_from(token, &grant.issuer, &grant.client_id, Some(refresh));
    store.put_grant(resource, renewed.clone())?;
    Ok(Some(renewed))
}
