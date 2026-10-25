//! The OAuth flows: browser login (authorization code + PKCE S256 on a
//! loopback redirect) and refresh.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use url::Url;

use crate::discovery::{self, Discovered};
use crate::error::{server_error, Error, Result};
use crate::pkce::{random_token, Pkce};
use crate::store::{Grant, Store};
use crate::{LoginOutcome, Opener};

/// How long to wait for the person to finish in the browser.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
/// How long one connection to the loopback listener may take, start to end.
/// Connections are handled concurrently, so a slow one never delays another.
/// A browser sends its request line at once; this only bounds a slow or
/// stalled client.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(2);
/// A token this close to expiry is refreshed rather than handed out.
const EXPIRY_SKEW_SECS: u64 = 30;
/// Assumed lifetime when a token response omits `expires_in`, and the most a
/// server-sent lifetime is trusted for.
const DEFAULT_LIFETIME_SECS: u64 = 300;
const MAX_LIFETIME_SECS: u64 = 30 * 24 * 3600;

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

/// The server's OAuth error code and description, cleaned for printing. The
/// body is never echoed as-is.
async fn oauth_error(resp: reqwest::Response) -> (String, String) {
    let status = resp.status();
    match resp.json::<OAuthError>().await {
        Ok(e) => {
            let message = server_error(&e.error, e.error_description.as_deref().unwrap_or(""));
            (e.error, message)
        }
        Err(_) => (String::new(), format!("server returned {status}")),
    }
}

fn usable(grant: &Grant) -> bool {
    grant.expires_at > now().saturating_add(EXPIRY_SKEW_SECS)
}

/// Whether `grant` was given every scope in `wanted`.
fn covers(grant: &Grant, wanted: &[String]) -> bool {
    wanted
        .iter()
        .all(|w| grant.scope.split_whitespace().any(|g| g == w))
}

pub(crate) async fn login(
    http: &reqwest::Client,
    store: &Store,
    opener: &dyn Opener,
    resource: &str,
    scopes: &[String],
    force: bool,
) -> Result<LoginOutcome> {
    if !force {
        // A usable grant that already covers what is asked for needs no new
        // consent. Anything else, including a grant that could not be
        // refreshed for any reason, falls through to a fresh login: that is
        // what the person is trying to fix.
        if let Ok(Some(g)) = fresh_grant(http, store, resource).await {
            if covers(&g, scopes) {
                return Ok(LoginOutcome::AlreadySignedIn);
            }
        }
    }

    let meta = discovery::discover(http, resource).await?;
    // Asked for here, the server's refusal is a sentence; asked for in the
    // browser, it is an error page the terminal never hears about.
    if !meta.server_scopes.is_empty() {
        let unoffered: Vec<String> = scopes
            .iter()
            .filter(|s| !meta.server_scopes.contains(s))
            .cloned()
            .collect();
        if !unoffered.is_empty() {
            return Err(Error::ScopeNotOffered {
                resource: resource.to_owned(),
                issuer: meta.issuer,
                scopes: unoffered,
                offered: meta.server_scopes,
            });
        }
    }
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
        .map_err(|_| {
            Error::Authorization(
                "timed out waiting for the browser; if it showed an error, try `ottoctl login \
                 --force` again"
                    .into(),
            )
        })??;

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
        let (_, message) = oauth_error(resp).await;
        return Err(Error::Authorization(message));
    }
    let token: TokenResponse = resp.json().await.map_err(|_| {
        Error::Authorization("the token endpoint sent an unreadable response".into())
    })?;

    let mut locked = store.lock().await?;
    locked.put_grant(
        resource,
        grant_from(token, &meta.issuer, &client_id, None, scopes.join(" ")),
    );
    locked.save()?;
    Ok(LoginOutcome::SignedIn)
}

/// The registered client id for this issuer, registering one if there is
/// none. Held under the store lock so two first logins register only once.
async fn client_id(http: &reqwest::Client, store: &Store, meta: &Discovered) -> Result<String> {
    let mut locked = store.lock().await?;
    if let Some(id) = locked.client_id(&meta.issuer) {
        return Ok(id.to_owned());
    }
    #[derive(Deserialize)]
    struct Registered {
        client_id: String,
    }
    let resp = http
        .post(meta.registration_endpoint.clone())
        .json(&serde_json::json!({
            "client_name": "ottoctl",
            "software_id": "ottoctl",
            // No port: the loopback port is chosen per login.
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
        }))
        .send()
        .await
        .map_err(|_| Error::Network(meta.registration_endpoint.to_string()))?;
    if !resp.status().is_success() {
        let (_, message) = oauth_error(resp).await;
        return Err(Error::Authorization(format!(
            "registration refused: {message}"
        )));
    }
    let registered: Registered = resp
        .json()
        .await
        .map_err(|_| Error::Authorization("registration sent an unreadable response".into()))?;
    locked.put_client(&meta.issuer, &registered.client_id);
    locked.save()?;
    Ok(registered.client_id)
}

fn grant_from(
    t: TokenResponse,
    issuer: &str,
    client_id: &str,
    prior_refresh: Option<String>,
    prior_scope: String,
) -> Grant {
    let lifetime = t
        .expires_in
        .unwrap_or(DEFAULT_LIFETIME_SECS)
        .min(MAX_LIFETIME_SECS);
    Grant {
        issuer: issuer.to_owned(),
        client_id: client_id.to_owned(),
        access_token: t.access_token,
        // A refresh response may omit the refresh token, meaning keep the old one.
        refresh_token: t.refresh_token.or(prior_refresh),
        expires_at: now().saturating_add(lifetime),
        // RFC 6749 section 5.1: no `scope` means the scope asked for (or, on a
        // refresh, the grant's own) was granted unchanged.
        scope: t.scope.unwrap_or(prior_scope),
    }
}

enum Callback {
    Code(String),
    Denied(String),
}

/// Accept connections until one carries the callback for this login's `state`.
/// Each connection is handled in its own task under [`CONNECTION_DEADLINE`],
/// so a local process that connects and stalls cannot hold up the browser's
/// callback. Anything else (a favicon request, a probe, a wrong state) is
/// answered and ignored, so a stray process cannot cancel the login either.
async fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String> {
    let (tx, mut rx) = mpsc::channel::<Callback>(1);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                // A failed accept (a connection reset before it was taken, or
                // too many open files while something floods the port) is
                // not a reason to abandon the login; back off and keep going.
                let Ok((sock, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                // No cap on connections in flight: a cap is a set of slots a
                // local process can fill and keep refilling, so the browser's
                // connection would be closed unread. Each task is cheap and
                // ends at CONNECTION_DEADLINE, so starving the browser means
                // exhausting this process's file descriptors.
                let (tx, state) = (tx.clone(), state.to_owned());
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        CONNECTION_DEADLINE,
                        handle_connection(sock, &state, &tx),
                    )
                    .await;
                });
            }
            // `tx` is held here, so the channel never closes while looping.
            Some(callback) = rx.recv() => {
                return match callback {
                    Callback::Code(code) => Ok(code),
                    Callback::Denied(message) => Err(Error::Authorization(message)),
                };
            }
        }
    }
}

async fn handle_connection(mut sock: TcpStream, state: &str, tx: &mpsc::Sender<Callback>) {
    let Some(target) = read_request_target(&mut sock).await else {
        return;
    };
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        respond(&mut sock, "400 Bad Request", "Bad request.").await;
        return;
    };
    if url.path() != "/callback" {
        respond(&mut sock, "404 Not Found", "Not found.").await;
        return;
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
        return;
    }
    if let Some(err) = param("error") {
        respond(
            &mut sock,
            "200 OK",
            "Sign-in was not completed. You can close this tab.",
        )
        .await;
        let desc = param("error_description").unwrap_or_default();
        let _ = tx.send(Callback::Denied(server_error(&err, &desc))).await;
        return;
    }
    let Some(code) = param("code") else {
        respond(&mut sock, "400 Bad Request", "No authorization code.").await;
        return;
    };
    respond(
        &mut sock,
        "200 OK",
        "Signed in. You can close this tab and return to the terminal.",
    )
    .await;
    let _ = tx.send(Callback::Code(code)).await;
}

async fn read_request_target(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // The request line is all that is needed; the read is bounded in size
    // here and in time by the caller's deadline.
    while buf.len() < 8192 && !buf.windows(2).any(|w| w == b"\r\n") {
        let n = sock.read(&mut chunk).await.ok()?;
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
///
/// Refresh runs under the store lock, and the grant is re-read once the lock
/// is held: if another process refreshed it meanwhile, its result is used and
/// the already-consumed refresh token is never presented again (otto-auth
/// would take that as a replay and revoke every token this client holds).
/// For the same reason, the grant that is deleted on `invalid_grant` is
/// always the one whose refresh token was just refused. Discovery happens
/// before the lock is taken, so the lock is held for one token request
/// (bounded by the HTTP timeout, well under the lock wait) and a save.
///
/// One window cannot be closed from the client: the server consumes the old
/// refresh token when it answers, so if this process dies, or the response or
/// the save is lost, after that point, the stored grant keeps a consumed token
/// and the next refresh is treated as a replay. The new grant is saved
/// immediately after the response to keep that window as small as possible.
pub(crate) async fn fresh_grant(
    http: &reqwest::Client,
    store: &Store,
    resource: &str,
) -> Result<Option<Grant>> {
    match store.grant(resource)? {
        None => return Ok(None),
        Some(g) if usable(&g) => return Ok(Some(g)),
        Some(_) => {}
    }

    let meta = discovery::discover(http, resource).await?;
    let mut locked = store.lock().await?;
    let Some(grant) = locked.grant(resource).cloned() else {
        return Ok(None);
    };
    if usable(&grant) {
        return Ok(Some(grant));
    }
    let login_required = || Error::LoginRequired {
        resource: resource.to_owned(),
    };
    let Some(refresh) = grant.refresh_token.clone() else {
        locked.remove_grant(resource);
        locked.save()?;
        return Err(login_required());
    };
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
        let (code, message) = oauth_error(resp).await;
        // The grant was revoked or expired, or the client is unknown: nothing
        // to retry. Anything else (a 5xx, rate limiting) leaves it in place.
        if matches!(code.as_str(), "invalid_grant" | "invalid_client") {
            locked.remove_grant(resource);
            if code == "invalid_client" {
                locked.remove_client(&meta.issuer);
            }
            locked.save()?;
            return Err(login_required());
        }
        return Err(Error::Authorization(message));
    }
    let token: TokenResponse = resp.json().await.map_err(|_| {
        Error::Authorization("the token endpoint sent an unreadable response".into())
    })?;
    let renewed = grant_from(
        token,
        &grant.issuer,
        &grant.client_id,
        Some(refresh),
        grant.scope.clone(),
    );
    locked.put_grant(resource, renewed.clone());
    locked.save()?;
    Ok(Some(renewed))
}
