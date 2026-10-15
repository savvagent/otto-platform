//! The authorization server, over HTTP.
//!
//! `otto-auth` decides everything here; this module is the transport, the
//! consent page, and nothing else. It lives in a web crate rather than beside a
//! resource server because `/oauth/authorize` is a *browser* surface that needs
//! the console's session cookie — it is the one place the two authentication
//! layers meet, and it is why the cookie is `SameSite=Lax` rather than `Strict`.
//!
//! ## One authorization server, many resource servers
//!
//! This server mints tokens for **every** resource server in the
//! [`otto_auth::resources`] registry, not for one configured audience. The
//! client names the one it wants with the RFC 8707 `resource` parameter, and
//! each step (authorize, consent, code issue, redemption, refresh) re-reads the
//! registry row for it, so registering a new otto-* service needs no change
//! here. [`resolve_resource`] is the one place a request that names no resource
//! is dealt with.
//!
//! Resource servers publish their own RFC 9728 protected-resource metadata
//! (`oauth::protected_resource_metadata` builds it); this module serves only
//! the authorization server's half of discovery.
//!
//! ## The consent screen is a security control
//!
//! Client registration is open by design: an agent's client self-registers, and
//! requiring an admin to pre-create one would defeat the zero-install premise.
//! So anyone can register a client called "Claude Code" pointing at their own
//! redirect URI. Nothing in the protocol prevents that, which puts the entire
//! defense on this page — and it means the page must lead with **the redirect
//! host**, the one fact the user can actually judge, and treat `client_name` as
//! the attacker-controlled string it is.
//!
//! Everything rendered from the request is HTML-escaped through [`escape`]. A
//! client name is not markup.
//!
//! ## Error routing
//!
//! An OAuth failure goes to one of two places, and choosing wrongly is the
//! classic open-redirector bug:
//!
//! - **Before the redirect URI is validated** — unknown client, unregistered
//!   URI — the error is rendered as a page. Redirecting here would mean sending
//!   the user, and the `state` parameter, to precisely the destination we could
//!   not verify.
//! - **After it is validated**, errors go back to the client as query
//!   parameters, which is what lets an agent show a useful message instead of
//!   hanging on a callback that never arrives.

use axum::extract::{Form, Query, RawForm, State};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use http::request::Parts;
use otto_auth::error::AuthError;
use otto_auth::{oauth, resources, tokens};
use otto_core::orgs::OrgsExt;
use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::{OrgId, UserId};
use serde::Deserialize;

use crate::error::ApiError;
use crate::i18n::{self, Key, Locale};
use crate::session::CurrentUser;
use crate::state::{client_ip, AppState};

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
///
/// Open, and necessarily so: it is what an unauthenticated client reads to find
/// out how to authenticate.
///
/// `scopes_supported` is the union across every enabled resource server in the
/// registry, so it is read from there rather than from a list compiled in here.
pub async fn as_metadata(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let servers = resources::list(&state.db)
        .await
        .map_err(|e| ApiError::from_auth_or_unavailable("as metadata", e))?;
    Ok(Json(oauth::as_metadata(
        &state.config.public_url,
        &resources::all_scopes(&servers),
    )))
}

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

/// `POST /oauth/register` (RFC 7591).
///
/// Open, and rate-limited per source address — the throttle `otto-auth`'s own
/// comment says belongs at the HTTP layer, because that is the only layer that
/// knows where the request came from. Registration grants nothing on its own: a
/// client is inert until a human consents to it.
pub async fn register_client(
    State(state): State<AppState>,
    parts: Parts,
    Json(req): Json<oauth::RegistrationRequest>,
) -> Result<Response, OAuthError> {
    if let Some(ip) = client_ip(&parts, &state.config) {
        let bucket = format!("dcr:{ip}");
        otto_auth::ratelimit::check_and_charge(&state.db, &bucket).await?;
    }

    let registered = oauth::register_client(&state.db, req).await?;

    let _ = state
        .db
        .audit_global(
            Entry::new(action::CLIENT_REGISTERED)
                .actor_label(registered.client_name.as_deref().unwrap_or("(unnamed)"))
                .target("client", registered.client_id.clone())
                .from_request(client_ip(&parts, &state.config).as_deref(), None),
        )
        .await;

    Ok((http::StatusCode::CREATED, Json(registered)).into_response())
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// The query string of an authorization request, exactly as OAuth defines it.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeParams {
    #[serde(default)]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    /// Space-separated, per RFC 6749.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8707. Required: this server refuses to mint a token whose audience
    /// the client did not name.
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Which org the sign-in is for, as a slug or an id. A hint, never a grant:
    /// it preselects the org on the consent screen, and lets a first-party
    /// client skip the screen, only when the signed-in user is a member of it.
    /// Anything else (unknown, or an org they are not in) is ignored without a
    /// word, so the parameter cannot be used to probe which orgs exist.
    #[serde(default)]
    pub org_hint: Option<String>,
}

/// The scope that means "act as an administrator of the org", on every otto-*
/// resource server.
///
/// A scope name is the resource server's to define, but this one is a platform
/// convention rather than a resource server's private word: it is the one scope
/// whose meaning depends on *who is consenting* rather than on what the client
/// asked for, so the gate that checks the human's role has to live where the
/// human is — here — and it cannot ask each resource server what its scopes
/// mean. A resource server that defines a scope called `org:admin` is opting
/// into this gate.
///
/// A requester who is not an admin of the chosen org is not refused: the scope
/// is dropped from the grant, and the token's `scope` says what was actually
/// granted. A client that needs it has to check the response, not assume it.
/// Only a request left with no scope at all is an `invalid_scope` error.
pub(crate) const ADMIN_SCOPE: &str = "org:admin";

/// The resource server a request is for.
///
/// `requested` is the client's RFC 8707 `resource` parameter. Absent, the
/// request is resolved only when that is unambiguous: exactly one enabled
/// resource server is registered. Clients that predate RFC 8707 then keep
/// working while the platform serves a single product, and are refused with a
/// message naming the missing parameter the moment a second one registers —
/// guessing between audiences would mint a token for a service the user never
/// saw named on the consent screen.
pub(crate) async fn resolve_resource(
    db: &otto_tenant::Db,
    requested: Option<&str>,
) -> Result<resources::ResourceServer, AuthError> {
    if let Some(uri) = requested {
        return resources::get_active(db, uri).await;
    }
    let mut enabled: Vec<_> = resources::list(db)
        .await?
        .into_iter()
        .filter(|rs| !rs.disabled)
        .collect();
    match enabled.len() {
        1 => Ok(enabled.remove(0)),
        0 => Err(AuthError::InvalidTarget(
            "no resource server is registered with this authorization server".into(),
        )),
        _ => Err(AuthError::InvalidTarget(
            "the resource parameter is required: this authorization server serves several \
             resource servers, and the token's audience must be named"
                .into(),
        )),
    }
}

impl AuthorizeParams {
    /// Build the `otto-auth` request, resolving the audience through the
    /// registry when the client did not name one. See [`resolve_resource`].
    async fn to_request(&self, db: &otto_tenant::Db) -> Result<oauth::AuthorizeRequest, AuthError> {
        let resource = resolve_resource(db, self.resource.as_deref())
            .await?
            .resource_uri;
        Ok(oauth::AuthorizeRequest {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            scopes: self
                .scope
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            resource,
            state: self.state.clone(),
        })
    }
}

/// The org `hint` names, if the caller belongs to it. Matches the slug or the
/// id; a miss and a non-membership are the same `None`.
fn resolve_org_hint<'a>(
    orgs: &'a [otto_core::orgs::Membership],
    hint: Option<&str>,
) -> Option<&'a otto_core::orgs::Membership> {
    let hint = hint?.trim();
    if hint.is_empty() {
        return None;
    }
    orgs.iter()
        .find(|m| m.org_slug.eq_ignore_ascii_case(hint) || m.org_id.to_string() == hint)
}

/// The scopes a member of `role` may hold: everything asked for, minus the
/// admin scope unless they can administer the org.
fn downscope(scopes: &[String], role: otto_core::orgs::Role) -> Vec<String> {
    scopes
        .iter()
        .filter(|s| *s != ADMIN_SCOPE || role.can_administer())
        .cloned()
        .collect()
}

/// One authorization request, resolved and validated: what a consent page is
/// rendered for, and what its seal binds.
struct Resolved<'a> {
    params: &'a AuthorizeParams,
    request: &'a oauth::AuthorizeRequest,
    authorization: &'a oauth::Authorization,
}

impl<'a> Resolved<'a> {
    /// What the seal binds for `user` (see [`crate::consent_seal`]).
    ///
    /// The *resolved* values, never raw query or form strings: the client the
    /// registry returned, the redirect URI `validate_authorize` accepted, the
    /// resolved resource URI and scopes, and the PKCE challenge and `state`
    /// the validated request carries. The page and the POST both build it
    /// here, so what the seal vouches for and what it is checked against
    /// cannot drift apart.
    fn bound(&self, user: UserId) -> crate::consent_seal::Expected<'a> {
        crate::consent_seal::Expected {
            client_id: &self.authorization.client.client_id,
            redirect_uri: &self.request.redirect_uri,
            resource: &self.authorization.resource.resource_uri,
            user_id: user,
            scopes: &self.authorization.scopes,
            code_challenge: &self.request.code_challenge,
            code_challenge_method: &self.request.code_challenge_method,
            state: self.request.state.as_deref(),
        }
    }
}

/// The caller's orgs, or the page that says they have none.
///
/// Every consent render goes through here first: a token opens exactly one
/// org, so with none there is nothing to choose and no form to show.
async fn consent_orgs(
    state: &AppState,
    caller: &CurrentUser,
    client: &oauth::Client,
    locale: Locale,
) -> Result<Vec<otto_core::orgs::Membership>, Box<Response>> {
    let orgs =
        state.db.list_user_orgs(caller.user.id).await.map_err(|e| {
            Box::new(ApiError::internal("list orgs for consent", e).into_response())
        })?;
    if orgs.is_empty() {
        return Err(Box::new(error_page_html(
            i18n::msg(locale, Key::ErrorNoOrgTitle),
            // Escaped once, around the whole filled sentence. Escaping the name
            // first as well double-encodes it, so a client called `<b>x</b>`
            // renders as the literal text `&lt;b&gt;x&lt;/b&gt;` — which is safe
            // but makes this page misreport the one fact it exists to show.
            &escape(&i18n::fill(
                i18n::msg(locale, Key::ErrorNoOrgBody),
                client.client_name.as_deref().unwrap_or("A client"),
            )),
            locale,
        )));
    }
    Ok(orgs)
}

/// Render the consent page for `resolved`, with `checked` ticked and a fresh
/// seal. The one place a consent page is built, for the first render and for
/// the "read only" re-render alike.
///
/// `preselect` is honoured only when it names one of `orgs`, the caller's
/// own, so neither a hint nor a hand-edited form can make the page claim an
/// org the caller is not in.
fn render_consent(
    state: &AppState,
    caller: &CurrentUser,
    resolved: &Resolved<'_>,
    orgs: &[otto_core::orgs::Membership],
    preselect: Option<OrgId>,
    checked: &[String],
    locale: Locale,
) -> Response {
    let preselected = preselect.filter(|id| orgs.iter().any(|m| m.org_id == *id));
    let request_seal =
        match crate::consent_seal::RequestSeal::new(&resolved.bound(caller.user.id), Utc::now())
            .seal(&state.consent_cipher)
        {
            Ok(seal) => seal,
            Err(e) => return ApiError::internal("seal the consent request", e).into_response(),
        };
    Html(consent_html(
        &resolved.authorization.client,
        resolved.params,
        &resolved.authorization.resource,
        &resolved.authorization.scopes,
        checked,
        orgs,
        preselected,
        caller
            .user
            .email
            .as_deref()
            .unwrap_or_else(|| i18n::msg(locale, Key::ConsentThisAccount)),
        &request_seal,
        locale,
    ))
    .into_response()
}

/// `GET /oauth/authorize` — render the consent screen.
///
/// A signed-out visitor is sent to the console's login page with `next` set to
/// this exact URL, so the flow resumes where it left off. That navigation is
/// the reason the session cookie is `SameSite=Lax`.
pub async fn authorize_page(
    State(state): State<AppState>,
    parts: Parts,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let caller = match CurrentUser::from_request_parts_public(&parts, &state).await {
        Some(caller) => caller,
        None => {
            let next = urlencode(&format!(
                "/oauth/authorize?{}",
                parts.uri.query().unwrap_or_default()
            ));
            return axum::response::Redirect::to(&state.config.url(&format!("/login?next={next}")))
                .into_response();
        }
    };

    // One resolution for every page this handler can render, so a consent
    // screen and the error that replaces it are never in different languages.
    let locale = page_locale(&caller, &parts);

    // Validated before anything is rendered. Every failure at this stage is a
    // page, never a redirect: the destination is what could not be verified.
    let request = match params.to_request(&state.db).await {
        Ok(request) => request,
        Err(e) => return error_page(&e, locale),
    };
    let authorization = match oauth::validate_authorize(&state.db, &request).await {
        Ok(authorization) => authorization,
        Err(e) => return error_page(&e, locale),
    };
    let client = &authorization.client;

    if params.response_type != "code" {
        return redirect_error(
            &params,
            "unsupported_response_type",
            "this server issues authorization codes only",
        );
    }

    let orgs = match consent_orgs(&state, &caller, client, locale).await {
        Ok(orgs) => orgs,
        Err(page) => return *page,
    };

    // The hint only ever selects among orgs the caller is already in.
    let hinted = resolve_org_hint(&orgs, params.org_hint.as_deref());

    // A first-party client is the operator's own service. Asking a person
    // whether the product they just signed in to may use itself is friction,
    // not consent, so when there is no choice left to put in front of them (the
    // org is named by a hint they belong to, or they have only one) the code is
    // issued here. A client that is not first-party always gets the screen: it
    // is the only defense against a look-alike client.
    //
    // Never for a loopback redirect, first-party or not (RFC 8252 section 8.6):
    // its port is not matched, so any local process can listen on one and take
    // the code, and the consent screen is what makes the user look at where it
    // is going. Checked here on every request rather than trusted from
    // registration, which also refuses the combination, because a row can be
    // edited by hand.
    if client.first_party && !oauth::is_loopback_redirect_uri(&params.redirect_uri) {
        let determined = hinted.or(match orgs.as_slice() {
            [only] => Some(only),
            _ => None,
        });
        if let Some(membership) = determined {
            let requested = authorization.scopes.clone();
            let mut request = request;
            request.scopes = authorization.scopes;
            return grant(
                &state,
                &parts,
                &caller,
                &params,
                request,
                &requested,
                membership.org_id,
                membership.role,
                true,
                locale,
            )
            .await;
        }
    }

    // The registry resolved the scopes: the resource server's defaults when the
    // client asked for none, otherwise exactly what it asked for. Every one
    // starts checked; the person can only take away.
    let resolved = Resolved {
        params: &params,
        request: &request,
        authorization: &authorization,
    };
    render_consent(
        &state,
        &caller,
        &resolved,
        &orgs,
        hinted.map(|m| m.org_id),
        &authorization.scopes,
        locale,
    )
}

/// The consent form's fields: the original request, plus the two decisions the
/// human makes.
///
/// The authorization parameters are written out rather than pulled in with
/// `#[serde(flatten)]`, which would be the obvious way and does not work:
/// `authorize_decision` deserializes it with `serde_urlencoded` from the raw
/// body (repeated `grant` values are read separately, because
/// `serde_urlencoded` cannot collect a repeated key into a `Vec`), and that
/// deserializer is not self-describing, which `flatten` needs. The failure is
/// a runtime rejection of every consent submission, not a compile error — so
/// the duplication stays, with [`ConsentForm::params`] as the single place it
/// is undone.
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    #[serde(default)]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub org_hint: Option<String>,
    /// Which org this token will act in. A token opens exactly one.
    pub org_id: OrgId,
    /// "allow" grants, "read_only" re-renders with only read scopes checked, and
    /// anything else is a denial.
    #[serde(default)]
    pub decision: String,
    /// The seal `authorize_page` rendered (see [`crate::consent_seal`]).
    /// Required: there is no unsealed fallback, which would let a forger
    /// simply drop it.
    #[serde(default)]
    pub request_seal: Option<String>,
    /// `"1"` on every rendered form: "this POST carries the person's
    /// selection". Its absence is read as an empty selection, never as
    /// "everything", so a form that lost it cannot grant more by omission.
    #[serde(default)]
    pub scope_choice: Option<String>,
}

impl ConsentForm {
    fn params(&self) -> AuthorizeParams {
        AuthorizeParams {
            response_type: self.response_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            // A form always submits every field, so an omitted `state` arrives
            // as an empty string rather than as absent. Treating that as a real
            // value would append `&state=` to the callback, which some clients
            // compare against the nothing they sent and reject.
            scope: blank_to_none(self.scope.clone()),
            resource: blank_to_none(self.resource.clone()),
            state: blank_to_none(self.state.clone()),
            org_hint: blank_to_none(self.org_hint.clone()),
        }
    }
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// `POST /oauth/authorize` — the user's decision.
///
/// Cross-site protection does not rest on the session cookie's `SameSite`
/// attribute. The Origin / `Sec-Fetch-Site` guard in front of every `POST`
/// refuses a cross-site submission before this handler runs, and the form's
/// `request_seal` then binds the decision to the exact request, client, user
/// and scopes the page was rendered for, so a form this server did not render
/// for this person is a 400 page and never drives a redirect.
pub async fn authorize_decision(
    State(state): State<AppState>,
    caller: CurrentUser,
    parts: Parts,
    RawForm(body): RawForm,
) -> Response {
    let locale = page_locale(&caller, &parts);
    // Read by hand rather than with `Form`: the person's selection arrives as
    // repeated `grant` values, which `serde_urlencoded` cannot collect into a
    // field, so the body is needed twice. A body that does not deserialize is
    // a 400 page, as `Form`'s rejection was a 4xx, never a 500.
    let form: ConsentForm = match serde_urlencoded::from_bytes(&body) {
        Ok(form) => form,
        Err(e) => {
            // serde's wording names fields and is for the log, not the person.
            tracing::warn!(
                user_id = %caller.user.id,
                error = %e,
                "consent form refused: the body did not deserialize"
            );
            return error_page(
                &AuthError::InvalidRequest(
                    "the consent form could not be read; start again from the app".into(),
                ),
                locale,
            );
        }
    };
    let params = form.params();
    let mut req = match params.to_request(&state.db).await {
        Ok(req) => req,
        Err(e) => return error_page(&e, locale),
    };

    // Re-validated on the way in. The form is user-supplied and could have been
    // edited between render and submit; nothing about having rendered a page is
    // evidence about what came back.
    let authorization = match oauth::validate_authorize(&state.db, &req).await {
        Ok(authorization) => authorization,
        Err(e) => return error_page(&e, locale),
    };

    // ...and re-validation proves only that the request is legal, not that it is
    // the one the person was shown. The seal does that, compared field by field
    // with the *resolved* values (the client the registry returned, the
    // redirect URI `validate_authorize` accepted, the re-resolved resource, the
    // resolved scopes, the PKCE challenge and `state`; see `Resolved::bound`),
    // never with raw form strings. Checked before every
    // branch, `deny` included: a form this server cannot vouch for must not
    // drive any redirect.
    let resolved = Resolved {
        params: &params,
        request: &req,
        authorization: &authorization,
    };
    if let Err(e) = crate::consent_seal::check(
        &state.consent_cipher,
        form.request_seal.as_deref(),
        &resolved.bound(caller.user.id),
        Utc::now(),
    ) {
        // The reason, the field and who: enough to tell tampering from an
        // expired page or a key rotation. Never the seal itself.
        tracing::warn!(
            reason = ?e,
            client_id = %authorization.client.client_id,
            user_id = %caller.user.id,
            "consent form refused: the request seal did not verify"
        );
        return error_page(&AuthError::InvalidRequest(e.to_string()), locale);
    }

    // "Read only" is a no-JS submit button: it re-renders this page with only
    // the `:read` scopes checked and issues nothing. The person still presses
    // Allow, and that POST is checked from scratch. It is the same render as
    // the first one, with a fresh seal because the page is new.
    if form.decision == "read_only" {
        let orgs = match consent_orgs(&state, &caller, &authorization.client, locale).await {
            Ok(orgs) => orgs,
            Err(page) => return *page,
        };
        let read_only: Vec<String> = authorization
            .scopes
            .iter()
            .filter(|s| resources::is_read_scope(s))
            .cloned()
            .collect();
        return render_consent(
            &state,
            &caller,
            &resolved,
            &orgs,
            Some(form.org_id),
            &read_only,
            locale,
        );
    }

    if form.decision != "allow" {
        return redirect_error(
            &params,
            "access_denied",
            "the user declined this authorization request",
        );
    }

    // The org must be one the caller actually belongs to. Without this check a
    // hand-edited form field is a cross-tenant token: everything downstream
    // trusts the org on the token, and this is where it is decided.
    let role = match state.db.member_role(form.org_id, caller.user.id).await {
        Ok(Some(role)) => role,
        Ok(None) => {
            return redirect_error(
                &params,
                "access_denied",
                "you are not a member of the selected organization",
            )
        }
        Err(e) => return ApiError::internal("check membership for consent", e).into_response(),
    };

    // What the person left checked, narrowed against what the page offered.
    // `authorization.scopes` is the resolved request (the resource server's
    // defaults when the client asked for none, which is what the page showed),
    // and the seal has already pinned it. `narrow` refuses (does not drop)
    // anything else, so a forged `grant` is a 400 page and issues nothing.
    let chosen: Vec<String> = if form.scope_choice.as_deref() == Some("1") {
        url::form_urlencoded::parse(&body)
            .filter(|(key, _)| key == "grant")
            .map(|(_, value)| value.into_owned())
            .collect()
    } else {
        Vec::new()
    };
    let narrowed = match authorization.narrow(&chosen) {
        Ok(narrowed) => narrowed,
        Err(e) => {
            // The seal verified, so this is a hand-edited `grant` on a page
            // this server rendered for this person.
            tracing::warn!(
                client_id = %authorization.client.client_id,
                user_id = %caller.user.id,
                error = %e,
                "consent form refused: a chosen scope was not on the page"
            );
            return error_page(&e, locale);
        }
    };

    // Nothing checked means nothing granted: the person declined, so this is
    // `access_denied`. `issue_authorization_code` refuses `[]` too, but a
    // failure there renders an error page. This check is the second guard; it
    // gives the client a proper `access_denied` redirect instead.
    if narrowed.is_empty() {
        return redirect_error(&params, "access_denied", "no access was selected");
    }
    req.scopes = narrowed;

    grant(
        &state,
        &parts,
        &caller,
        &params,
        req,
        &authorization.scopes,
        form.org_id,
        role,
        false,
        locale,
    )
    .await
}

/// Issue the authorization code for `org_id` and send the browser to the
/// client's callback. The single place a code is minted for the authorization
/// endpoint, so the consent POST and a first-party skip cannot drift apart.
///
/// `req` must already carry the scopes to grant: the resolved request, narrowed
/// to what the person left checked. `role` is the caller's role in
/// `org_id`, which the caller has established. `requested` is the resolved
/// request before the person narrowed it; it is recorded beside what was
/// granted.
#[allow(clippy::too_many_arguments)]
async fn grant(
    state: &AppState,
    parts: &Parts,
    caller: &CurrentUser,
    params: &AuthorizeParams,
    mut req: oauth::AuthorizeRequest,
    requested: &[String],
    org_id: OrgId,
    role: otto_core::orgs::Role,
    skipped_consent: bool,
    locale: Locale,
) -> Response {
    // `org:admin` is a real capability. A member consenting to it would hand a
    // client authority the human granting it does not have, so it is dropped
    // rather than granted. Dropped rather than refused: the client asked for
    // the most it could use, and a first-party client asks for the admin scope
    // of every user, most of whom are not admins. Only a request that loses
    // everything is an error.
    let chosen = std::mem::take(&mut req.scopes);
    req.scopes = downscope(&chosen, role);
    if req.scopes.is_empty() {
        return redirect_error(
            params,
            "invalid_scope",
            "org:admin needs an owner or admin of the selected organization",
        );
    }

    let code = match oauth::issue_authorization_code(&state.db, &req, caller.user.id, org_id).await
    {
        Ok(code) => code,
        Err(e) => return error_page(&e, locale),
    };

    // The code is already issued, so a failed audit write does not undo the
    // grant. It is logged, because for a narrowed grant this entry is the only
    // record of what was asked for beside what was granted.
    if let Err(e) = state
        .db
        .audit_for_org(
            org_id,
            Entry::new(action::AUTHORIZATION_GRANTED)
                .actor(caller.user.id)
                .target("client", params.client_id.clone())
                .from_request(client_ip(parts, &state.config).as_deref(), None)
                .detail(serde_json::json!({
                    "scopes": req.scopes,
                    "requested": requested,
                    "resource": req.resource,
                    "consent_skipped": skipped_consent,
                })),
        )
        .await
    {
        tracing::error!(
            error = %e,
            org_id = %org_id,
            client_id = %params.client_id,
            "failed to write audit event for an authorization grant"
        );
    }

    let mut location = append_query(&params.redirect_uri, &[("code", &code)]);
    if let Some(s) = &params.state {
        location = append_query(&location, &[("state", s)]);
    }

    // 303, not 302: the browser must turn a POST into a GET on the callback.
    (
        http::StatusCode::SEE_OTHER,
        [(http::header::LOCATION, location)],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Token and revocation
// ---------------------------------------------------------------------------

/// A token request. Form-encoded, per RFC 6749 §4.1.3 — not JSON, whatever a
/// modern instinct suggests. Clients send what the RFC says.
#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

/// `POST /oauth/token`.
pub async fn token(
    State(state): State<AppState>,
    Form(form): Form<TokenForm>,
) -> Result<Response, OAuthError> {
    // RFC 8707 §2.2: a token request may repeat `resource`, and if it does it
    // must name the resource the grant was issued for. Omitting it is fine; the
    // grant already carries its audience.
    let requested_resource = form.resource.as_deref();

    let client_id = form
        .client_id
        .clone()
        .ok_or_else(|| AuthError::InvalidRequest("client_id is required".into()))?;

    let issued = match form.grant_type.as_str() {
        "authorization_code" => {
            let code = form
                .code
                .as_deref()
                .ok_or_else(|| AuthError::InvalidRequest("code is required".into()))?;
            let redirect_uri = form.redirect_uri.as_deref().ok_or_else(|| {
                AuthError::InvalidRequest("redirect_uri is required for authorization_code".into())
            })?;
            let verifier = form.code_verifier.as_deref().ok_or_else(|| {
                AuthError::InvalidRequest(
                    "code_verifier is required — PKCE S256 is mandatory".into(),
                )
            })?;

            let (issued, user, org) = oauth::redeem_code(
                &state.db,
                code,
                &client_id,
                redirect_uri,
                verifier,
                requested_resource,
            )
            .await?;

            let _ = state
                .db
                .audit_for_org(
                    org,
                    Entry::new(action::TOKEN_ISSUED)
                        .actor(user)
                        .target("client", client_id.clone()),
                )
                .await;

            issued
        }

        "refresh_token" => {
            let presented = form
                .refresh_token
                .as_deref()
                .ok_or_else(|| AuthError::InvalidRequest("refresh_token is required".into()))?;

            let (issued, user, org, _reused) =
                tokens::redeem_refresh(&state.db, presented, &client_id, requested_resource)
                    .await?;

            let _ = state
                .db
                .audit_for_org(
                    org,
                    Entry::new(action::TOKEN_REFRESHED)
                        .actor(user)
                        .target("client", client_id.clone()),
                )
                .await;

            issued
        }

        other => {
            return Err(OAuthError(AuthError::UnsupportedGrantType(format!(
                "{other:?}; this server implements authorization_code and refresh_token"
            ))))
        }
    };

    // RFC 6749 §5.1, including the no-store headers: an authorization response
    // must not sit in a shared cache.
    Ok((
        [
            (http::header::CACHE_CONTROL, "no-store"),
            (http::header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": issued.expires_in,
            "refresh_token": issued.refresh_token,
            "scope": issued.scopes.join(" "),
        })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: String,
}

/// `POST /oauth/revoke` (RFC 7009).
///
/// Always `200`, even for a token that never existed. The RFC requires it, and
/// the reason is the same one that makes `introspect` collapse unknown and
/// revoked: an endpoint that reports whether a string was a valid token is an
/// oracle for testing stolen ones.
pub async fn revoke(
    State(state): State<AppState>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, OAuthError> {
    tokens::revoke_presented(&state.db, &form.token).await?;
    Ok(http::StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// Error shapes
// ---------------------------------------------------------------------------

/// An OAuth protocol error, rendered per RFC 6749 §5.2.
///
/// Deliberately not [`ApiError`]: the console's envelope is
/// `{"error": {"code", "message"}}`, and an OAuth client parses
/// `{"error", "error_description"}` at the top level. A client handed the wrong
/// shape reports "unknown error" and the user has nothing to go on.
#[derive(Debug)]
pub struct OAuthError(pub AuthError);

impl From<AuthError> for OAuthError {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status =
            http::StatusCode::from_u16(self.0.status()).unwrap_or(http::StatusCode::BAD_REQUEST);
        let code = self.0.oauth_code().unwrap_or("invalid_request");

        // Protocol errors describe the client's *request*, not the user's
        // identity, so they are returned verbatim — there is no enumeration
        // risk and a vague message makes integration impossible. Anything
        // else falls back to the deliberately vague public string.
        let description = match self.0.oauth_code() {
            Some(_) => self.0.to_string(),
            None => self.0.public().to_string(),
        };

        let mut response = (
            status,
            Json(serde_json::json!({
                "error": code,
                "error_description": description,
            })),
        )
            .into_response();

        if status == http::StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static(r#"Basic realm="otto-platform""#),
            );
        }

        response
    }
}

/// Bounce an error back to a **validated** redirect URI.
fn redirect_error(params: &AuthorizeParams, code: &str, description: &str) -> Response {
    let mut location = append_query(
        &params.redirect_uri,
        &[("error", code), ("error_description", description)],
    );
    if let Some(s) = &params.state {
        location = append_query(&location, &[("state", s)]);
    }
    (
        http::StatusCode::SEE_OTHER,
        [(http::header::LOCATION, location)],
    )
        .into_response()
}

/// What language to render these two pages in.
///
/// **Stored choice first, header second, and both pages use this same rule.**
/// The account's own setting is the better signal — somebody who set Spanish on
/// an English-configured work laptop meant it — and `Accept-Language` is what
/// answers when they have chosen nothing.
///
/// An earlier draft had the error page negotiate on the header alone, on the
/// reasoning that it could be reached without a session. It cannot: every
/// `error_page` call site here is downstream of a resolved [`CurrentUser`],
/// because `authorize_page` bounces a signed-out visitor to `/login` and
/// `authorize_decision` takes the extractor. Splitting the rule would have
/// produced a German consent page and an English error page in one flow.
fn page_locale(caller: &CurrentUser, parts: &Parts) -> Locale {
    caller
        .user
        .locale
        .as_deref()
        .and_then(|l| l.parse::<Locale>().ok())
        .unwrap_or_else(|| {
            i18n::negotiate(
                parts
                    .headers
                    .get(http::header::ACCEPT_LANGUAGE)
                    .and_then(|v| v.to_str().ok()),
            )
        })
}

/// Render an error the user has to read, because it cannot safely be redirected.
///
/// The body is the `AuthError`'s own text, which is English: translating the
/// server's error strings is out of scope for #42, and they are also the
/// strings an integrator pastes into a bug report. The page *around* it — its
/// title, its closing note, and `<html lang>` — is localized, so the error
/// reads as a scoped boundary rather than an untouched page.
fn error_page(e: &AuthError, locale: Locale) -> Response {
    let detail = match e.oauth_code() {
        Some(_) => e.to_string(),
        None => e.public().to_string(),
    };
    error_page_html(i18n::msg(locale, Key::ErrorTitle), &escape(&detail), locale)
}

fn error_page_html(title: &str, body_html: &str, locale: Locale) -> Response {
    let title = escape(title);
    let lang = locale.as_str();
    let closing = escape(i18n::msg(locale, Key::ErrorNothingAuthorized));
    (
        http::StatusCode::BAD_REQUEST,
        Html(format!(
            "<!doctype html><html lang={lang}><meta charset=utf-8><title>{title}</title>{STYLE}\
             <main><h1>{title}</h1><p>{body_html}</p>\
             <p class=note>{closing}</p></main></html>"
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// The consent page
// ---------------------------------------------------------------------------

const STYLE: &str = "<style>\
body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}\
main{max-width:34rem;margin:3rem auto;padding:2rem;background:#fff;border-radius:12px;\
box-shadow:0 1px 3px rgba(0,0,0,.1)}\
h1{font-size:1.35rem;margin:0 0 1rem}\
.host{font:600 1.05rem ui-monospace,monospace;background:#eef;padding:.3rem .5rem;\
border-radius:6px}\
.name{color:#555}\
fieldset{border:0;padding:0;margin:0}\
legend{padding:0;margin:0 0 .5rem}\
.grant{margin:.35rem 0}\
.grant label{margin-left:.4rem}\
code.scope{color:#666;font-size:.8rem;margin-left:.25rem}\
.note{color:#666;font-size:.875rem}\
label.field{display:block;margin:1rem 0 .35rem;font-weight:600}\
select{font:inherit;padding:.5rem;width:100%;border:1px solid #ccc;border-radius:8px}\
.row{display:flex;gap:.75rem;margin-top:1.75rem}\
button{font:inherit;padding:.6rem 1.2rem;border-radius:8px;border:1px solid #ccc;cursor:pointer}\
button.primary{background:#111;color:#fff;border-color:#111}\
</style>";

#[allow(clippy::too_many_arguments)]
fn consent_html(
    client: &oauth::Client,
    params: &AuthorizeParams,
    resource: &resources::ResourceServer,
    scopes: &[String],
    checked: &[String],
    orgs: &[otto_core::orgs::Membership],
    preselected: Option<OrgId>,
    signed_in_as: &str,
    request_seal: &str,
    locale: Locale,
) -> String {
    // The fact the user can actually judge. `client_name` is self-asserted
    // through open registration; the redirect host is where the code will
    // really be delivered, so it gets the visual weight.
    let host = url::Url::parse(&params.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| params.redirect_uri.clone());

    let named = client
        .client_name
        .as_deref()
        .map(|n| {
            format!(
                "<p class=name>{}</p>",
                escape(&i18n::fill(i18n::msg(locale, Key::ConsentCallsItself), n))
            )
        })
        .unwrap_or_default();

    // One native checkbox per resolved scope, each with its own <label for>,
    // so it is keyboard-operable and announced with its text and no script.
    // The id is the index rather than the scope, because a scope token may
    // hold characters that are awkward in an id. The description is the main
    // text and the raw name stays beside it as `<code>`; a scope with no
    // description is just its name. Descriptions are single-language (see
    // `ResourceServer::scope_descriptions`) and operator-supplied text, never
    // markup.
    let scope_items = scopes
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let text = match resource.scope_description(s) {
                Some(d) => format!("{} <code class=scope>{}</code>", escape(d), escape(s)),
                None => format!("<code>{}</code>", escape(s)),
            };
            format!(
                "<div class=grant><input type=checkbox id=grant-{i} name=grant value=\"{}\"{}>\
                 <label for=grant-{i}>{text}</label></div>",
                escape(s),
                if checked.contains(s) { " checked" } else { "" },
            )
        })
        .collect::<String>();

    // "Read only" only where it would change something without emptying the
    // grant. It is the first submit button in tree order, so an implicit
    // (Enter) submission re-renders instead of granting.
    let mixed = scopes.iter().any(|s| resources::is_read_scope(s))
        && scopes.iter().any(|s| !resources::is_read_scope(s));
    let read_only = if mixed {
        format!(
            "<button type=submit name=decision value=read_only>{}</button>",
            escape(i18n::msg(locale, Key::ConsentReadOnly))
        )
    } else {
        String::new()
    };

    let org_options = orgs
        .iter()
        .map(|m| {
            format!(
                "<option value=\"{}\"{}>{}</option>",
                escape(&m.org_id.to_string()),
                if preselected == Some(m.org_id) {
                    " selected"
                } else {
                    ""
                },
                escape(&m.org_name)
            )
        })
        .collect::<String>();

    let hidden = [
        ("response_type", params.response_type.as_str()),
        ("client_id", params.client_id.as_str()),
        ("redirect_uri", params.redirect_uri.as_str()),
        ("code_challenge", params.code_challenge.as_str()),
        (
            "code_challenge_method",
            params.code_challenge_method.as_str(),
        ),
        ("scope", params.scope.as_deref().unwrap_or("")),
        // The *resolved* audience, not the client's original value. A client
        // that named none gets an empty field echoed back, and the decision POST
        // would resolve it again — possibly to a different resource server if
        // one registered in between, so the human would consent to the page
        // they saw and be issued a code for something else. Pinning it here
        // makes the form say exactly what the page showed.
        ("resource", resource.resource_uri.as_str()),
        ("state", params.state.as_deref().unwrap_or("")),
        ("org_hint", params.org_hint.as_deref().unwrap_or("")),
        // Marks a form that rendered the scope checkboxes. A POST without it
        // comes from an older or forged form that never offered a choice, so
        // its missing `grant` fields must not be read as "grant everything".
        ("scope_choice", "1"),
        ("request_seal", request_seal),
    ]
    .iter()
    .map(|(k, v)| format!("<input type=hidden name={k} value=\"{}\">", escape(v)))
    .collect::<String>();

    // The redirect host is interpolated into the *middle* of a sentence whose
    // word order differs by language, so the whole sentence is one message with
    // one placeholder rather than two fragments concatenated around a span.
    // Splitting it is what makes a sentence untranslatable.
    let asking = i18n::fill(
        i18n::msg(locale, Key::ConsentAsking),
        &format!("<span class=host>{}</span>", escape(&host)),
    );

    format!(
        "<!doctype html><html lang={lang}><meta charset=utf-8><title>{title}</title>{STYLE}\
         <main>\
         <h1>{heading}</h1>\
         <p>{asking}</p>\
         {named}\
         <p class=note>{warn}</p>\
         <form method=post action=\"/oauth/authorize\">{hidden}\
         <fieldset><legend>{asking_to}</legend>{scope_items}</fieldset>\
         <p class=note>{narrow_hint}</p>\
         {read_only}\
         <label class=field for=org_id>{organization}</label>\
         <select id=org_id name=org_id>{org_options}</select>\
         <p class=note>{org_note}</p>\
         <div class=row>\
         <button class=primary type=submit name=decision value=allow>{allow}</button>\
         <button type=submit name=decision value=deny>{cancel}</button>\
         </div></form>\
         <p class=note>{signed_in}</p>\
         </main></html>",
        lang = locale.as_str(),
        title = escape(i18n::msg(locale, Key::ConsentTitle)),
        // The resource server's registered name is operator-supplied, but it
        // is still text, not markup.
        heading = escape(&i18n::fill(
            i18n::msg(locale, Key::ConsentHeading),
            &resource.name
        )),
        // `asking` already carries escaped markup for the host span.
        warn = escape(i18n::msg(locale, Key::ConsentWarnName)),
        asking_to = escape(i18n::msg(locale, Key::ConsentItIsAskingTo)),
        organization = escape(i18n::msg(locale, Key::ConsentOrganization)),
        org_note = escape(i18n::msg(locale, Key::ConsentOrgScopeNote)),
        allow = escape(i18n::msg(locale, Key::ConsentAllow)),
        cancel = escape(i18n::msg(locale, Key::ConsentCancel)),
        narrow_hint = escape(i18n::msg(locale, Key::ConsentNarrowHint)),
        signed_in = escape(&i18n::fill(
            i18n::msg(locale, Key::ConsentSignedInAs),
            signed_in_as
        )),
    )
}

/// Escape text for interpolation into HTML.
///
/// Covers attribute contexts too, which is why `"` and `'` are here: every
/// interpolation on the consent page is either element text or a
/// double-quoted attribute value.
pub fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a query-parameter value.
///
/// Hand-rolled against RFC 3986's unreserved set — everything outside it is
/// encoded, which is conservative and cannot under-encode. The failure this
/// guards against is real: an unencoded `state` containing `&` splits into two
/// parameters and the client's CSRF check silently compares the wrong string.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Append `key=value` query parameters onto a redirect URI that may already
/// carry its own query string.
///
/// RFC 6749 §3.1.2 requires a registered redirect URI's existing query
/// component to be retained, with the response parameters appended to it. A
/// client registered at `https://app.example.com/cb?tenant=acme` still needs
/// `code`/`state` (or `error`/`error_description`) appended with `&`, not a
/// second `?` — `?tenant=acme?code=…` is not a query string any conformant
/// parser reads correctly, and the client would never see `code` or `state`.
/// `validate_registerable_redirect` accepts a query component (it only
/// rejects fragments, wildcards, and non-loopback cleartext), so this case is
/// reachable with any client that registers one.
fn append_query(redirect_uri: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = redirect_uri.to_string();
    let mut sep = if redirect_uri.contains('?') { '&' } else { '?' };
    for (key, value) in pairs {
        out.push(sep);
        out.push_str(key);
        out.push('=');
        out.push_str(&urlencode(value));
        sep = '&';
    }
    out
}

impl CurrentUser {
    /// Resolve a session without turning its absence into a rejection.
    ///
    /// The consent page needs "signed in, or send them to log in", not "signed
    /// in, or 401" — a `401` there is a dead end for a person who simply has not
    /// logged in yet.
    async fn from_request_parts_public(parts: &Parts, state: &AppState) -> Option<CurrentUser> {
        let token = crate::session::token_from(parts)?;
        let session = otto_auth::sessions::resolve(&state.db, &token).await.ok()?;
        let user = state.db.get_user(session.user_id).await.ok()??;
        Some(CurrentUser { user, session })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escaping_neutralizes_a_client_name() {
        let attack = r#"<script>alert('xss')</script>"#;
        let escaped = escape(attack);
        assert!(!escaped.contains('<'), "{escaped}");
        assert!(!escaped.contains('>'));
        assert_eq!(escaped, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
    }

    /// A client name that breaks out of a double-quoted attribute is the other
    /// half of the same attack, and the one an element-only escaper misses.
    #[test]
    fn html_escaping_covers_attribute_contexts() {
        assert_eq!(
            escape(r#"" onmouseover="steal()"#),
            "&quot; onmouseover=&quot;steal()"
        );
    }

    fn membership(slug: &str, role: otto_core::orgs::Role) -> otto_core::orgs::Membership {
        otto_core::orgs::Membership {
            org_id: OrgId::new(),
            user_id: otto_tenant::ids::UserId::new(),
            role,
            org_slug: slug.into(),
            org_name: slug.into(),
            plan: otto_core::orgs::Plan::Free,
        }
    }

    fn fixture_client() -> oauth::Client {
        oauth::Client {
            client_id: "otto_client_x".into(),
            client_name: Some("Agent".into()),
            redirect_uris: vec!["http://127.0.0.1:1455/callback".into()],
            disabled: false,
            first_party: false,
        }
    }

    fn fixture_params() -> AuthorizeParams {
        AuthorizeParams {
            response_type: "code".into(),
            client_id: "otto_client_x".into(),
            redirect_uri: "http://127.0.0.1:1455/callback".into(),
            code_challenge: "x".repeat(43),
            code_challenge_method: "S256".into(),
            scope: Some("things:read things:write".into()),
            resource: None,
            state: Some("s".into()),
            org_hint: None,
        }
    }

    fn fixture_resource(scopes: &[&str], described: &[(&str, &str)]) -> resources::ResourceServer {
        resources::ResourceServer {
            resource_uri: "https://things.otto.test/mcp".into(),
            name: "Things".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            default_scopes: vec!["things:read".into()],
            scope_descriptions: sqlx::types::Json(
                described
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            disabled: false,
            webhook_url: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn render(scopes: &[&str], checked: &[&str], described: &[(&str, &str)]) -> String {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let checked: Vec<String> = checked.iter().map(|s| s.to_string()).collect();
        consent_html(
            &fixture_client(),
            &fixture_params(),
            &fixture_resource(&["things:read", "things:write", "org:admin"], described),
            &scopes,
            &checked,
            &[membership("acme", otto_core::orgs::Role::Owner)],
            None,
            "rob@acme.test",
            "SEAL-VALUE",
            Locale::En,
        )
    }

    #[test]
    fn each_requested_scope_is_a_labelled_checkbox() {
        let html = render(
            &["things:read", "things:write"],
            &["things:read"],
            &[("things:write", "<b>Change</b> everything")],
        );
        assert!(
            html.contains(
                "<input type=checkbox id=grant-0 name=grant value=\"things:read\" checked>\
                 <label for=grant-0><code>things:read</code></label>"
            ),
            "{html}"
        );
        assert!(
            html.contains(
                "<input type=checkbox id=grant-1 name=grant value=\"things:write\">\
                 <label for=grant-1>&lt;b&gt;Change&lt;/b&gt; everything \
                 <code class=scope>things:write</code></label>"
            ),
            "an unchecked box has no `checked`, and a hostile description is escaped: {html}"
        );
        assert!(!html.contains("<b>Change</b>"));
        assert!(html.contains("<fieldset><legend>It is asking to:</legend>"));
        assert!(html.contains(
            "Uncheck anything you don&#39;t want to allow. It can never be given more than this."
        ));
    }

    #[test]
    fn the_read_only_button_appears_only_for_a_mixed_set() {
        let button = "<button type=submit name=decision value=read_only>Read only</button>";
        assert!(render(&["things:read", "things:write"], &[], &[]).contains(button));
        assert!(render(&["things:read", "org:admin"], &[], &[]).contains(button));
        assert!(
            !render(&["things:read"], &[], &[]).contains(button),
            "a no-op"
        );
        assert!(
            !render(&["things:write", "org:admin"], &[], &[]).contains(button),
            "it would empty the grant"
        );
    }

    /// Implicit submission (Enter) uses the first submit button in tree order.
    /// When Read only is shown, it must come before Allow, so Enter re-renders
    /// and never grants.
    #[test]
    fn read_only_precedes_allow_in_tree_order() {
        let html = render(&["things:read", "things:write"], &[], &[]);
        let read_only = html.find("value=read_only").unwrap();
        let allow = html.find("value=allow").unwrap();
        assert!(read_only < allow);
    }

    #[test]
    fn the_form_carries_the_scope_choice_marker_and_the_seal() {
        let html = render(&["things:read"], &["things:read"], &[]);
        assert!(html.contains("<input type=hidden name=scope_choice value=\"1\">"));
        assert!(html.contains("<input type=hidden name=request_seal value=\"SEAL-VALUE\">"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("tabindex"));
    }

    #[test]
    fn an_org_hint_matches_slug_or_id_among_the_callers_orgs_only() {
        use otto_core::orgs::Role;
        let orgs = vec![
            membership("acme", Role::Owner),
            membership("globex", Role::Member),
        ];

        assert_eq!(resolve_org_hint(&orgs, Some("globex")), Some(&orgs[1]));
        assert_eq!(resolve_org_hint(&orgs, Some("ACME")), Some(&orgs[0]));
        let id = orgs[1].org_id.to_string();
        assert_eq!(resolve_org_hint(&orgs, Some(&id)), Some(&orgs[1]));

        // A real org the caller is not in looks exactly like one that does not exist.
        assert!(resolve_org_hint(&orgs, Some("initech")).is_none());
        assert!(resolve_org_hint(&orgs, Some(&OrgId::new().to_string())).is_none());
        assert!(resolve_org_hint(&orgs, Some("  ")).is_none());
        assert!(resolve_org_hint(&orgs, None).is_none());
    }

    #[test]
    fn only_administrators_keep_the_admin_scope() {
        use otto_core::orgs::Role;
        let asked: Vec<String> = ["things:read", ADMIN_SCOPE].map(String::from).to_vec();

        assert_eq!(downscope(&asked, Role::Owner), asked);
        assert_eq!(downscope(&asked, Role::Admin), asked);
        assert_eq!(downscope(&asked, Role::Member), vec!["things:read"]);
        assert!(downscope(&[ADMIN_SCOPE.to_string()], Role::Member).is_empty());
    }

    #[test]
    fn url_encoding_protects_the_state_parameter() {
        assert_eq!(urlencode("abc-123_x.y~z"), "abc-123_x.y~z");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("é"), "%C3%A9");
    }

    /// The phishing defense, asserted: the redirect host must be in the page,
    /// and a hostile client name must not be able to escape into markup.
    #[test]
    fn the_consent_page_leads_with_the_redirect_host() {
        let client = oauth::Client {
            client_id: "otto_client_x".into(),
            client_name: Some("<b>Claude Code</b>".into()),
            redirect_uris: vec!["http://127.0.0.1:1455/callback".into()],
            disabled: false,
            first_party: false,
        };
        let params = AuthorizeParams {
            response_type: "code".into(),
            client_id: "otto_client_x".into(),
            redirect_uri: "http://127.0.0.1:1455/callback".into(),
            code_challenge: "x".repeat(43),
            code_challenge_method: "S256".into(),
            scope: Some("things:read".into()),
            resource: None,
            state: Some("opaque".into()),
            org_hint: None,
        };
        let orgs = vec![otto_core::orgs::Membership {
            org_id: OrgId::new(),
            user_id: otto_tenant::ids::UserId::new(),
            role: otto_core::orgs::Role::Owner,
            org_slug: "acme".into(),
            org_name: "Acme".into(),
            plan: otto_core::orgs::Plan::Free,
        }];

        let html = consent_html(
            &client,
            &params,
            &resources::ResourceServer {
                resource_uri: "https://things.otto.test/mcp".into(),
                name: "Things <Server>".into(),
                scopes: vec!["things:read".into()],
                default_scopes: vec!["things:read".into()],
                scope_descriptions: Default::default(),
                disabled: false,
                webhook_url: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            &["things:read".to_string()],
            &["things:read".to_string()],
            &orgs,
            None,
            "rob@acme.test",
            "SEAL",
            Locale::En,
        );

        assert!(
            html.contains("127.0.0.1"),
            "the redirect host is the only fact a user can judge, and it is missing"
        );
        assert!(
            !html.contains("<b>Claude Code</b>"),
            "the client name reached the page as markup"
        );
        assert!(html.contains("&lt;b&gt;Claude Code&lt;/b&gt;"));
        assert!(
            html.contains("Authorize access to Things &lt;Server&gt;"),
            "the consent page must name the resource server, escaped"
        );
        assert!(
            html.contains("<code>things:read</code>"),
            "a scope with no description falls back to its raw name"
        );
        assert!(html.contains("name=org_id"), "no organization picker");
        assert!(
            html.contains("name=resource value=\"https://things.otto.test/mcp\""),
            "the form must carry the resolved resource, not the request's original (empty) one"
        );
    }
}
