//! The cross-site request guard.
//!
//! `SameSite=Lax` keeps a session cookie off cross-*site* POSTs, but it does
//! nothing about **same-site** siblings: every `*.savvagent.com` host is
//! same-site with `otto.savvagent.com`, so an XSS on any of them can submit a
//! form here with the victim's cookie attached — `POST /oauth/authorize` with
//! `decision=allow`, or any of the bodyless POSTs (`/api/auth/logout`,
//! `members/{user}/logout`, `sso/domains/{d}/verify`) that no body-shaped check
//! would ever notice. `__Host-` stops a sibling *setting* our cookie; it does
//! not stop one *using* it.
//!
//! So for every request that is not a safe method **and carries the session
//! cookie**, the browser must prove where it came from:
//!
//! 1. an `Origin` header, which must equal the configured public origin
//!    exactly (scheme, host and port) — a sibling subdomain's origin differs,
//!    and so does the literal `null` a sandboxed frame sends; otherwise
//! 2. with no `Origin`, `Sec-Fetch-Site: same-origin` (browsers that omit
//!    `Origin` on same-origin requests send this instead); otherwise
//! 3. `403`.
//!
//! **Requests without the session cookie are untouched.** `/oauth/token`,
//! `/oauth/register` and `/oauth/revoke` are called by agents, which send
//! neither cookie nor `Origin`; there is no ambient credential for a forged
//! request to ride, so there is nothing to guard. The corollary is that a
//! non-browser client that authenticates with the session cookie must send an
//! `Origin` of the public URL — nothing in the product does, since agents use
//! bearer tokens.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{header, StatusCode};

use crate::error::ApiError;
use crate::state::Config;

/// The origin (`scheme://host[:port]`) of the public URL, as a browser
/// serializes it in an `Origin` header. `None` only for a URL with no origin,
/// which `relying_party` already refuses at startup.
fn origin_of(public_url: &str) -> Option<String> {
    let url = url::Url::parse(public_url).ok()?;
    url.has_host().then(|| url.origin().ascii_serialization())
}

/// The allowed origin, as the middleware's state. Build it once per router.
///
/// With no parsable origin nothing could ever match, which fails closed: every
/// cookie-bearing write is refused rather than waved through.
pub fn allowed_origin(config: &Config) -> Arc<String> {
    Arc::new(origin_of(&config.public_url).unwrap_or_default())
}

/// The middleware itself; mount with
/// `axum::middleware::from_fn_with_state(allowed_origin(&config), check)`.
pub async fn check(State(origin): State<Arc<String>>, req: Request, next: Next) -> Response {
    if !allowed(&origin, &req) {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "cross_site_request",
            "this request did not come from this site, so it was refused",
        )
        .into_response();
    }
    next.run(req).await
}

fn allowed(origin: &str, req: &Request) -> bool {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    if !carries_session_cookie(req) {
        return true;
    }
    match req.headers().get(header::ORIGIN) {
        Some(value) => value
            .to_str()
            .is_ok_and(|v| !origin.is_empty() && v == origin),
        None => req
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|v| v == "same-origin"),
    }
}

fn carries_session_cookie(req: &Request) -> bool {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|pair| pair.split_once('='))
        .any(|(name, _)| name.trim() == crate::session::COOKIE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    const ORIGIN: &str = "https://otto.test";

    fn req(method: Method, headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().method(method).uri("/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    const COOKIE: (&str, &str) = ("cookie", "theme=dark; __Host-otto_session=otto_ss_abc");

    #[test]
    fn the_origin_is_scheme_host_and_port() {
        assert_eq!(origin_of("https://otto.test/").as_deref(), Some(ORIGIN));
        assert_eq!(
            origin_of("http://localhost:8080").as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn safe_methods_and_cookieless_requests_are_never_blocked() {
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(allowed(
                ORIGIN,
                &req(m, &[COOKIE, ("origin", "https://evil.test")])
            ));
        }
        // An agent calling /oauth/token: no cookie, no Origin.
        assert!(allowed(ORIGIN, &req(Method::POST, &[])));
        assert!(allowed(
            ORIGIN,
            &req(Method::POST, &[("origin", "https://evil.test")])
        ));
    }

    #[test]
    fn a_cookie_bearing_write_must_prove_its_origin() {
        let post = |h: &[(&str, &str)]| allowed(ORIGIN, &req(Method::POST, h));
        assert!(post(&[COOKIE, ("origin", ORIGIN)]));
        assert!(!post(&[COOKIE, ("origin", "https://evil.test")]));
        // Same-site sibling: the case SameSite=Lax does not cover.
        assert!(!post(&[COOKIE, ("origin", "https://blog.otto.test")]));
        assert!(!post(&[COOKIE, ("origin", "null")]));
        assert!(!post(&[COOKIE, ("origin", "http://otto.test")]));
        assert!(!post(&[COOKIE]), "no Origin and no Fetch Metadata");
        assert!(post(&[COOKIE, ("sec-fetch-site", "same-origin")]));
        assert!(!post(&[COOKIE, ("sec-fetch-site", "same-site")]));
        assert!(!post(&[COOKIE, ("sec-fetch-site", "cross-site")]));
        // A wrong Origin is not rescued by a Fetch Metadata header.
        assert!(!post(&[
            COOKIE,
            ("origin", "https://blog.otto.test"),
            ("sec-fetch-site", "same-origin")
        ]));
    }

    #[test]
    fn a_lookalike_cookie_name_does_not_trigger_the_guard_or_evade_it() {
        // Not our cookie: nothing ambient to protect.
        assert!(allowed(
            ORIGIN,
            &req(Method::POST, &[("cookie", "x__Host-otto_session=a")])
        ));
    }

    #[test]
    fn an_unparsable_public_url_fails_closed() {
        assert!(!allowed("", &req(Method::POST, &[COOKIE, ("origin", "")])));
    }
}
