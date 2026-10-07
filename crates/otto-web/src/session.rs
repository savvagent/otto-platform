//! The console's session cookie, and the extractors built on it.
//!
//! ## The cookie
//!
//! Four attributes, and each one is load-bearing:
//!
//! - **`HttpOnly`** — script must not be able to read the session. Without it
//!   any XSS anywhere in the console is a full account takeover rather than a
//!   defaced page.
//! - **`Secure`** — never sent over cleartext. Set unconditionally, including in
//!   development: browsers treat `http://localhost` as a secure context and
//!   accept `Secure` cookies there, so there is no dev exemption to make, and a
//!   flag that turns this off is a flag someone eventually ships with.
//! - **`Path=/`** — the console, the OAuth authorize page, and the API are all
//!   on one origin.
//! - **`SameSite=Lax`**, and this is the one worth explaining. `Strict` would be
//!   the reflex. It is wrong here: `/oauth/authorize` is reached by a top-level
//!   navigation from the agent that opened the browser, `Strict` withholds the
//!   cookie on exactly that kind of cross-site navigation, and the user would
//!   land on a login screen despite being signed in — an infinite loop for
//!   anyone who is already logged in, which is everyone. `Lax` sends the cookie
//!   on top-level GET navigations and withholds it on cross-site POSTs, which is
//!   the CSRF protection we actually want.
//!
//! ## `__Host-`
//!
//! The name is `__Host-otto_session`. The prefix is not decoration: browsers
//! refuse to store a `__Host-`-prefixed cookie unless it is `Secure`, has
//! `Path=/`, and carries **no `Domain`** — which makes it impossible for a
//! sibling subdomain to set one. Without it, an XSS on any `*.example.com` host
//! can write a session cookie for the parent domain and fix a victim's session.
//!
//! ## The extractors
//!
//! [`CurrentUser`] resolves the cookie to a live user on every request. There is
//! no caching layer: the same reasoning as a resource server's per-request token
//! introspection, and the same payoff — a disabled account and a revoked session
//! stop working on the next request rather than whenever something happens to
//! expire.
//!
//! [`OrgCtx`] additionally resolves the `{org}` path segment to an org the user
//! actually belongs to, and carries their role. Membership is decided here, once,
//! rather than in each handler: a handler that forgets is a handler that serves
//! another tenant's data, and the type system is a better place to put that than
//! a review checklist.

use axum::extract::{FromRef, FromRequestParts};
use http::header::{COOKIE, SET_COOKIE};
use http::request::Parts;
use http::HeaderValue;
use otto_auth::sessions::{self, Session};
use otto_core::orgs::OrgsExt;
use otto_core::orgs::{Org, Role, User};

use crate::error::ApiError;
use crate::state::AppState;

/// The cookie name. See the module docs for why the prefix is there.
pub const COOKIE_NAME: &str = "__Host-otto_session";

/// Build the `Set-Cookie` value for a freshly opened session.
///
/// `Max-Age` matches the session's **absolute** cap, not its idle window.
/// [`sessions::resolve`] slides the idle deadline forward on every use, up to
/// that same absolute cap — an actively-used session is meant to survive far
/// longer than one idle day's worth of `Max-Age` would let the browser keep
/// the cookie for. Setting `Max-Age` to the idle window instead (a prior
/// version of this function did) meant the browser silently discarded an
/// actively-used session's cookie after `IDLE_TTL_DAYS`, logging out a user
/// the server had just extended. The server remains the authority either way
/// — [`sessions::resolve`] re-checks both clocks on every request — but the
/// cookie now outlives the browser's own copy of it for as long as the
/// session could possibly still be valid, rather than for a fixed slice of
/// that window regardless of use.
pub fn set_cookie(token: &str) -> HeaderValue {
    let max_age = sessions::ABSOLUTE_TTL_DAYS * 24 * 3600;
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}"
    ))
    .expect("session cookie value is ASCII by construction")
}

/// Build the `Set-Cookie` value that clears the session.
///
/// Every attribute has to match the one that set it or the browser keeps two
/// cookies and sends the stale one — a logout that appears to work and does not.
pub fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-otto_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    )
}

/// Pull the session token out of a `Cookie` header.
///
/// Hand-parsed rather than pulled in with a cookie crate: this is one name
/// lookup in a semicolon-separated list, and the parse is exercised by the tests
/// at the bottom of this file.
pub fn token_from(parts: &Parts) -> Option<String> {
    for header in parts.headers.get_all(COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for pair in raw.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == COOKIE_NAME {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// The enterprise OIDC federation login-CSRF binding cookie.
///
/// `state` (in the callback URL) alone is replayable — it travels through
/// browser history, referrer headers, and a captured-and-replayed callback
/// URL — so `sso/start`/`sso/link/start` additionally set this cookie, and
/// the callback requires it to match the ceremony's stored `binding_hash`
/// *in addition to* `state` resolving a ceremony at all. See
/// `docs/specs/2026-09-16-oidc-federation-design.md`'s Assumptions on the
/// login-CSRF hole this closes. Same attribute shape as [`COOKIE_NAME`] and
/// for the same reasons — `HttpOnly`/`Secure`/`Path=/`/`SameSite=Lax`, the
/// `__Host-` prefix — except this cookie's `Max-Age` is the ceremony's own
/// short TTL, not the session's, because it protects nothing once the
/// ceremony it names has expired or been consumed.
pub const BINDING_COOKIE_NAME: &str = "__Host-otto_sso_binding";

/// Build the `Set-Cookie` value for a freshly started SSO ceremony.
///
/// `max_age_secs` is the ceremony's own TTL (the design's 10-minute window),
/// passed in rather than hard-coded here so the cookie's lifetime and the
/// ceremony row's `expires_at` cannot drift into two different constants.
pub fn set_binding_cookie(token: &str, max_age_secs: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{BINDING_COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}"
    ))
    .expect("binding cookie value is ASCII by construction")
}

/// Build the `Set-Cookie` value that clears the binding cookie.
///
/// The callback clears this on every outcome, success or refusal alike: the
/// cookie is useless the moment its ceremony is consumed (single-use), and a
/// stale copy lingering in the browser past its purpose is hygiene, not a
/// security gap (spec's Risks & Open Questions) — but worth cleaning up
/// anyway so it does not sit there until its own `Max-Age` expires.
pub fn clear_binding_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-otto_sso_binding=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    )
}

/// Pull the binding cookie's value out of a `Cookie` header. Mirrors
/// [`token_from`] exactly, against [`BINDING_COOKIE_NAME`] instead of
/// [`COOKIE_NAME`].
pub fn binding_token_from(parts: &Parts) -> Option<String> {
    for header in parts.headers.get_all(COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for pair in raw.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == BINDING_COOKIE_NAME {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Attach a `Set-Cookie` to a response.
pub fn with_cookie(
    mut response: axum::response::Response,
    value: HeaderValue,
) -> axum::response::Response {
    response.headers_mut().append(SET_COOKIE, value);
    response
}

/// The signed-in human.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user: User,
    pub session: Session,
}

impl<S> FromRequestParts<S> for CurrentUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let token = token_from(parts).ok_or_else(ApiError::unauthenticated)?;

        // Any failure here — unknown, revoked, expired, disabled — is one
        // answer. A caller holding a dead cookie has exactly one thing to do
        // about it, and telling them which kind of dead it was serves nobody.
        let session = sessions::resolve(&state.db, &token)
            .await
            .map_err(|_| ApiError::unauthenticated())?;

        let user = state
            .db
            .get_user(session.user_id)
            .await
            .map_err(|e| ApiError::internal("load session user", e))?
            .ok_or_else(ApiError::unauthenticated)?;

        Ok(CurrentUser { user, session })
    }
}

/// The signed-in human, acting in one org they belong to.
#[derive(Debug, Clone)]
pub struct OrgCtx {
    pub user: User,
    pub session: Session,
    pub org: Org,
    pub role: Role,
}

impl OrgCtx {
    /// Refuse unless the caller administers this org.
    ///
    /// The message names the role they have, because "you need to be an admin"
    /// without saying what you are leaves a person guessing whether they are
    /// looking at the right org.
    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.role.can_administer() {
            return Ok(());
        }
        Err(ApiError::forbidden(format!(
            "this needs an owner or admin of {}; you are a {}",
            self.org.slug,
            role_name(self.role)
        )))
    }

    /// Refuse unless the caller owns this org — billing, IdP binding, deletion.
    pub fn require_owner(&self) -> Result<(), ApiError> {
        if self.role.can_own() {
            return Ok(());
        }
        Err(ApiError::forbidden(format!(
            "this needs an owner of {}; you are a {}",
            self.org.slug,
            role_name(self.role)
        )))
    }
}

pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

impl<S> FromRequestParts<S> for OrgCtx
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let slug = org_param(parts, state).await.ok_or_else(|| {
            // A route mounted without an `{org}` segment reaching this
            // extractor is a wiring bug, not a caller error.
            ApiError::internal("org path parameter", "route has no {org} segment")
        })?;

        let CurrentUser { user, session } = CurrentUser::from_request_parts(parts, state).await?;
        let app = AppState::from_ref(state);

        let org = app
            .db
            .get_org_by_slug(&slug)
            .await
            .map_err(|e| ApiError::internal("resolve org", e))?;

        // **An org the caller is not in is reported as not found, not as
        // forbidden.** `403` on a real slug and `404` on a fake one is a
        // membership oracle: it tells anyone with a session which companies use
        // the product. The two cases are collapsed deliberately.
        let missing = || ApiError::not_found(format!("no org {slug:?} that you are a member of"));

        let org = org.ok_or_else(missing)?;
        let role = app
            .db
            .member_role(org.id, user.id)
            .await
            .map_err(|e| ApiError::internal("resolve membership", e))?
            .ok_or_else(missing)?;

        Ok(OrgCtx {
            user,
            session,
            org,
            role,
        })
    }
}

/// Read the `{org}` path segment.
///
/// `RawPathParams` rather than `Path<T>`: it clones the parameters out of the
/// request extensions rather than deserializing them into a type, so a handler
/// that also takes `Path<…>` for its *own* segments still sees everything.
async fn org_param<S: Send + Sync>(parts: &mut Parts, state: &S) -> Option<String> {
    let params = axum::extract::RawPathParams::from_request_parts(parts, state)
        .await
        .ok()?;
    params
        .iter()
        .find(|(key, _)| *key == "org")
        .map(|(_, value)| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_with(cookie: &str) -> Parts {
        let request = http::Request::builder()
            .header(COOKIE, cookie)
            .body(())
            .unwrap();
        request.into_parts().0
    }

    #[test]
    fn the_session_token_is_found_among_other_cookies() {
        let parts = parts_with("theme=dark; __Host-otto_session=otto_ss_abc; locale=en");
        assert_eq!(token_from(&parts), Some("otto_ss_abc".into()));

        let parts = parts_with("__Host-otto_session=otto_ss_abc");
        assert_eq!(token_from(&parts), Some("otto_ss_abc".into()));
    }

    /// A cookie whose *name* merely ends in ours must not be read as ours —
    /// `evil-__Host-otto_session` is a name an attacker can set on a sibling host.
    #[test]
    fn a_lookalike_cookie_name_is_not_the_session() {
        for cookie in [
            "otto_session=otto_ss_abc",
            "evil__Host-otto_session=otto_ss_abc",
            "x__Host-otto_session=otto_ss_abc",
            "__Host-otto_session_other=otto_ss_abc",
            "__Host-otto_session=",
            "theme=dark",
        ] {
            assert_eq!(
                token_from(&parts_with(cookie)),
                None,
                "{cookie:?} must not be read as a session"
            );
        }
    }

    /// The four attributes from the module docs, asserted rather than trusted.
    /// Losing any one of them is a silent security regression that no other
    /// test in the suite would notice.
    #[test]
    fn the_cookie_carries_every_attribute_that_protects_it() {
        let cookie = set_cookie("otto_ss_abc");
        let cookie = cookie.to_str().unwrap();

        assert!(cookie.starts_with("__Host-otto_session=otto_ss_abc"));
        assert!(cookie.contains("HttpOnly"), "script could read it");
        assert!(
            cookie.contains("Secure"),
            "it would cross the wire in clear"
        );
        assert!(cookie.contains("Path=/"), "__Host- requires Path=/");
        assert!(
            cookie.contains("SameSite=Lax"),
            "Lax specifically: Strict drops the cookie on the top-level \
             navigation into /oauth/authorize"
        );
        assert!(
            !cookie.contains("SameSite=Strict"),
            "Strict breaks the OAuth consent navigation"
        );
        assert!(
            !cookie.to_lowercase().contains("domain="),
            "__Host- requires no Domain attribute"
        );
    }

    /// A clearing cookie whose attributes differ from the setting one leaves the
    /// browser holding both, and sending the stale one.
    #[test]
    fn clearing_matches_the_cookie_it_clears() {
        let set = set_cookie("otto_ss_abc");
        let clear = clear_cookie();
        let (set, clear) = (set.to_str().unwrap(), clear.to_str().unwrap());

        for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(set.contains(attribute));
            assert!(
                clear.contains(attribute),
                "clearing cookie is missing {attribute}, so the browser keeps the old one"
            );
        }
        assert!(clear.contains("Max-Age=0"));
    }

    /// The binding cookie needs the same protections as the session cookie —
    /// it is what closes the login-CSRF hole on `/sso/callback` — and its
    /// own `Max-Age` must be the caller-supplied ceremony TTL, not the
    /// session's.
    #[test]
    fn the_binding_cookie_carries_every_attribute_that_protects_it() {
        let cookie = set_binding_cookie("otto_ssb_abc", 600);
        let cookie = cookie.to_str().unwrap();

        assert!(cookie.starts_with("__Host-otto_sso_binding=otto_ssb_abc"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=600"));
        assert!(!cookie.to_lowercase().contains("domain="));
    }

    #[test]
    fn clearing_the_binding_cookie_matches_the_cookie_it_clears() {
        let set = set_binding_cookie("otto_ssb_abc", 600);
        let clear = clear_binding_cookie();
        let (set, clear) = (set.to_str().unwrap(), clear.to_str().unwrap());

        for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(set.contains(attribute));
            assert!(clear.contains(attribute));
        }
        assert!(clear.contains("Max-Age=0"));
    }

    #[test]
    fn the_binding_token_is_found_among_other_cookies() {
        let parts = parts_with("theme=dark; __Host-otto_sso_binding=otto_ssb_abc; locale=en");
        assert_eq!(binding_token_from(&parts), Some("otto_ssb_abc".into()));
        assert_eq!(binding_token_from(&parts_with("theme=dark")), None);
    }
}
