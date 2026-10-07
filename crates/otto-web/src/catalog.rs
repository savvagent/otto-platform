//! The endpoint catalog — one description of the console API, used twice.
//!
//! **Why a catalog rather than annotations on each handler.** The plan asks for
//! an OpenAPI document generated from the handlers, and the failure mode it is
//! guarding against is a document that drifts from the code. A macro on each
//! handler is one way; this is another, and it makes drift impossible rather
//! than merely detectable: [`crate::router`] is *built from* this list, and
//! [`crate::openapi::document`] is *rendered from* the same list. There is no
//! second place where a route is declared, so there is nothing for a document
//! to fall out of step with.
//!
//! It also keeps the OpenAPI vocabulary out of `otto-core`. The alternative —
//! deriving schema traits on the domain types — spreads a documentation
//! dependency across every crate to describe an interface only this one serves.
//!
//! The cost is honest and worth naming: request and response bodies are
//! referenced by component name rather than derived from the Rust types, so a
//! field added to a response struct does not appear in the document until
//! someone adds it to [`crate::openapi::components`]. The test at the bottom of
//! `openapi.rs` catches a *missing* component, not a stale field.

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post, put, MethodRouter};

use crate::routes::{auth, orgs, sso, teams, tokens, usage};
use crate::state::AppState;
use crate::{oauth, openapi};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "get",
            Verb::Post => "post",
            Verb::Put => "put",
            Verb::Patch => "patch",
            Verb::Delete => "delete",
        }
    }
}

/// What a caller must hold to reach an endpoint.
///
/// Documentation *and* an assertion: the test in `openapi.rs` checks that every
/// endpoint claiming an org scope actually sits under an `{org}` path segment,
/// which is what makes [`crate::session::OrgCtx`] able to resolve one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// No credential. Discovery documents, and the endpoints someone who cannot
    /// yet log in has to be able to reach.
    Public,
    /// A console session cookie.
    Session,
    /// A session, plus membership of the org in the path.
    OrgMember,
    /// A session, plus `owner` or `admin` of the org in the path.
    OrgAdmin,
}

impl Auth {
    pub fn as_str(self) -> &'static str {
        match self {
            Auth::Public => "public",
            Auth::Session => "session",
            Auth::OrgMember => "org member",
            Auth::OrgAdmin => "org admin",
        }
    }

    pub fn needs_org(self) -> bool {
        matches!(self, Auth::OrgMember | Auth::OrgAdmin)
    }
}

pub struct Endpoint {
    pub verb: Verb,
    pub path: &'static str,
    pub summary: &'static str,
    pub description: &'static str,
    pub auth: Auth,
    /// Component schema name for the request body, if any.
    pub request: Option<&'static str>,
    /// Component schema name for the response body, if any.
    pub response: Option<&'static str>,
    /// The success status this endpoint actually answers with. Defaults to
    /// `200`; call [`Endpoint::status`] for anything else. Getting this wrong
    /// is not cosmetic — a generated client that expects `200` treats a real
    /// `201`/`204`/`303` success as an error.
    pub success: u16,
    pub route: MethodRouter<AppState>,
}

impl Endpoint {
    fn build(verb: Verb, path: &'static str, route: MethodRouter<AppState>) -> Self {
        Self {
            verb,
            path,
            summary: "",
            description: "",
            auth: Auth::Session,
            request: None,
            response: None,
            success: 200,
            route,
        }
    }

    pub fn get<H, T>(path: &'static str, handler: H) -> Self
    where
        H: axum::handler::Handler<T, AppState>,
        T: 'static,
    {
        Self::build(Verb::Get, path, get(handler))
    }

    pub fn post<H, T>(path: &'static str, handler: H) -> Self
    where
        H: axum::handler::Handler<T, AppState>,
        T: 'static,
    {
        Self::build(Verb::Post, path, post(handler))
    }

    pub fn put<H, T>(path: &'static str, handler: H) -> Self
    where
        H: axum::handler::Handler<T, AppState>,
        T: 'static,
    {
        Self::build(Verb::Put, path, put(handler))
    }

    pub fn patch<H, T>(path: &'static str, handler: H) -> Self
    where
        H: axum::handler::Handler<T, AppState>,
        T: 'static,
    {
        Self::build(Verb::Patch, path, patch(handler))
    }

    pub fn delete<H, T>(path: &'static str, handler: H) -> Self
    where
        H: axum::handler::Handler<T, AppState>,
        T: 'static,
    {
        Self::build(Verb::Delete, path, delete(handler))
    }

    pub fn summary(mut self, summary: &'static str) -> Self {
        self.summary = summary;
        self
    }

    pub fn describe(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    pub fn takes(mut self, schema: &'static str) -> Self {
        self.request = Some(schema);
        self
    }

    pub fn returns(mut self, schema: &'static str) -> Self {
        self.response = Some(schema);
        self
    }

    /// Declare a success status other than the `200` default —
    /// `201 Created`, `204 No Content`, `303 See Other`, and so on, matching
    /// exactly what the handler actually sends.
    pub fn status(mut self, code: u16) -> Self {
        self.success = code;
        self
    }

    /// Cap the request body this route will read into memory, in bytes.
    ///
    /// Only needed on `Auth::Public` routes: session/token-authenticated
    /// endpoints already require a caller who spent a credential to reach
    /// them, but a public route like `/webhooks/{provider}` is reachable by
    /// anyone on the internet, and `Bytes`/`Json` extractors buffer the whole
    /// body before a handler ever runs. Without an explicit limit, an
    /// oversized payload is a free memory/CPU DoS against an unauthenticated
    /// surface.
    pub fn body_limit(mut self, bytes: usize) -> Self {
        self.route = self.route.layer(DefaultBodyLimit::max(bytes));
        self
    }

    /// `GET /api/orgs/{org}/teams` → `getApiOrgsOrgTeams`. Stable across
    /// renames of the Rust function, which is what an OpenAPI operation id has
    /// to be — client generators turn it into a method name.
    pub fn operation_id(&self) -> String {
        let mut id = String::from(self.verb.as_str());
        for segment in self.path.split('/').filter(|s| !s.is_empty()) {
            let segment = segment.trim_matches(|c| c == '{' || c == '}');
            // Filtered before the first character is singled out, not after:
            // a segment like `.well-known` would otherwise capitalize the
            // leading `.` and leave it in place, producing an identifier that
            // starts with a dot. `operationId` becomes a method name in most
            // generators, and a leading `.` is not a legal identifier start
            // anywhere that matters.
            let mut chars = segment.chars().filter(|c| c.is_ascii_alphanumeric());
            if let Some(first) = chars.next() {
                id.push(first.to_ascii_uppercase());
                id.extend(chars);
            }
        }
        id
    }

    /// The `{name}` segments in this endpoint's path.
    pub fn path_params(&self) -> Vec<&'static str> {
        self.path
            .split('/')
            .filter(|s| s.starts_with('{') && s.ends_with('}'))
            .map(|s| s.trim_matches(|c| c == '{' || c == '}'))
            .collect()
    }
}

/// Every endpoint the console API serves.
pub fn catalog() -> Vec<Endpoint> {
    vec![
        // ------------------------------------------------------ discovery
        Endpoint::get(
            "/.well-known/oauth-authorization-server",
            oauth::as_metadata,
        )
        .auth(Auth::Public)
        .summary("Authorization server metadata")
        .describe(
            "RFC 8414. How a client learns where to register, authorize, and \
                 exchange tokens, and which scopes the registered resource servers \
                 define. Open by necessity — it is what an unauthenticated client \
                 reads to find out how to authenticate. Each resource server publishes \
                 its own RFC 9728 protected-resource metadata; this document is the \
                 authorization server's half.",
        ),
        Endpoint::get("/api/openapi.json", openapi::serve)
            .auth(Auth::Public)
            .summary("This document")
            .describe("The OpenAPI description of everything below."),
        // ----------------------------------------------------------- oauth
        Endpoint::post("/oauth/register", oauth::register_client)
            .auth(Auth::Public)
            .status(201)
            .summary("Register a client")
            .describe(
                "RFC 7591 dynamic client registration. Open by design — clients \
                 self-register (MCP clients included) — and rate limited per source address. Registration \
                 grants nothing: a client is inert until a human consents to it.",
            ),
        Endpoint::get("/oauth/authorize", oauth::authorize_page)
            .auth(Auth::Public)
            .summary("Consent screen")
            .describe(
                "Renders the consent screen for an authorization request, or redirects \
                 to the login page with `next` set so the flow resumes afterwards. \
                 Reached by a top-level browser navigation, which is why the session \
                 cookie is SameSite=Lax.",
            ),
        Endpoint::post("/oauth/authorize", oauth::authorize_decision)
            .auth(Auth::Session)
            .status(303)
            .summary("Record the consent decision")
            .describe(
                "On approval, issues an authorization code and redirects to the \
                 client's callback. The selected org must be one the caller belongs \
                 to — this is where a token's org is fixed, and it cannot be changed \
                 afterwards.",
            ),
        Endpoint::post("/oauth/token", oauth::token)
            .auth(Auth::Public)
            .summary("Exchange a code or refresh token")
            .describe(
                "Form-encoded, per RFC 6749. `authorization_code` requires a PKCE \
                 S256 `code_verifier`; `refresh_token` rotates, and replaying a \
                 consumed refresh token revokes the whole chain.",
            ),
        Endpoint::post("/oauth/revoke", oauth::revoke)
            .auth(Auth::Public)
            .summary("Revoke a token")
            .describe("RFC 7009. Always 200, even for a token that never existed."),
        // ---------------------------------------------------- enterprise sso
        Endpoint::get("/sso/callback", sso::callback)
            .auth(Auth::Public)
            .status(303)
            .summary("The identity provider's redirect back")
            .describe(
                "Server-rendered, not a console page: it mints the same __Host-otto_session \
                 cookie passkey login does and redirects, or answers a generic failure page \
                 on any of several refusal paths (an invalid/expired/reused state, a missing \
                 or mismatched __Host-otto_sso_binding binding cookie, an unverified email, or \
                 an email collision) — deliberately not distinguished to the caller, since \
                 this is the unauthenticated bootstrap surface. No credential is spent by \
                 reaching this URL alone; the binding cookie is what stops a captured-and-\
                 replayed callback URL from opening a session in a different browser.",
            ),
        // ------------------------------------------------------------ auth
        Endpoint::post("/api/auth/signup/start", auth::signup_start)
            .auth(Auth::Public)
            .returns("RegistrationChallenge")
            .summary("Create an account and get a passkey challenge")
            .describe(
                "Takes no body — there is no identifier to give. Creates an account \
                 with no address and returns a WebAuthn creation challenge; it \
                 becomes usable only when a credential is registered against it at \
                 /api/auth/signup/finish. Because nothing is submitted, nothing here \
                 can reveal whether an address or account already exists.",
            ),
        Endpoint::post("/api/auth/signup/finish", auth::signup_finish)
            .auth(Auth::Public)
            .takes("FinishRegistration")
            .returns("SessionOpened")
            .summary("Register the passkey and open the first session"),
        Endpoint::post("/api/auth/login/start", auth::login_start)
            .auth(Auth::Public)
            .returns("AuthenticationChallenge")
            .summary("Get a sign-in challenge")
            .describe(
                "Takes no identifier: the credential the browser picks is what says \
                 who is signing in. allowCredentials is empty, so only discoverable \
                 passkeys answer it.",
            ),
        Endpoint::post("/api/auth/login/finish", auth::login_finish)
            .auth(Auth::Public)
            .takes("FinishAuthentication")
            .returns("SessionOpened")
            .summary("Present the signature and sign in")
            .describe(
                "Failures collapse into one `invalid_credentials` answer once an \
                 account has been resolved — bad signature, wrong origin, no keys, \
                 disabled account — because the differences would tell an attacker \
                 holding a stolen device which part to work on. Two answers are \
                 deliberately distinct. `unknown_credential` means this server has \
                 no record of the credential you presented; it is decided before any \
                 account is looked up, so it names no user, address or org, and it \
                 is what lets a console retire a dead passkey from the browser's \
                 vault instead of offering it forever.",
            ),
        Endpoint::post("/api/auth/claim/start", auth::claim_start)
            .auth(Auth::Public)
            .takes("ClaimRequest")
            .returns("RegistrationChallenge")
            .summary("Begin re-registering with an admin-issued claim code")
            .describe(
                "For an account whose passkeys an admin cleared. The code is not \
                 spent here, so an interrupted ceremony does not burn somebody's \
                 only way back in.",
            ),
        Endpoint::post("/api/auth/claim/finish", auth::claim_finish)
            .auth(Auth::Public)
            .takes("FinishClaim")
            .returns("SessionOpened")
            .summary("Register the new passkey and sign in")
            .describe("Spends the claim code."),
        Endpoint::get("/api/auth/webauthn", auth::webauthn_config)
            .auth(Auth::Public)
            .returns("WebauthnConfig")
            .summary("The relying party this deployment signs passkeys with")
            .describe(
                "The WebAuthn rp_id — the identifier every passkey on this server is \
                 bound to, and the one a console must name when it calls \
                 PublicKeyCredential.signalCurrentUserDetails or its siblings. Read it \
                 here rather than taking the page's hostname: an rp_id may be a \
                 registrable parent domain of the origin, and a signal sent for the \
                 wrong rp_id is discarded without an error. Public because the same \
                 string is inside every creation challenge an unauthenticated caller \
                 can already ask for.",
            ),
        Endpoint::post("/api/auth/logout", auth::logout)
            .auth(Auth::Public)
            .status(204)
            .summary("End this session")
            .describe("Succeeds even for a caller holding a cookie that resolves to nothing."),
        Endpoint::post("/api/auth/sso/start", sso::sso_start)
            .auth(Auth::Public)
            .takes("SsoStartRequest")
            .returns("SsoStartResponse")
            .summary("Begin signing in through an org's identity provider")
            .describe(
                "Resolves the identity provider purely from the email's domain — no account \
                 is looked up. sso_not_configured means no org has claimed and verified this \
                 domain; sign in with a passkey instead. Sets a short-lived binding cookie the \
                 callback requires, and returns a redirectUrl to navigate the browser to.",
            ),
        // -------------------------------------------------------------- me
        Endpoint::get("/api/me", auth::me)
            .returns("Me")
            .summary("Who is signed in")
            .describe("The account, its org memberships, and whether it still needs to enrol."),
        Endpoint::get("/api/me/sessions", auth::list_sessions)
            .returns("SessionList")
            .summary("Where this account is signed in"),
        Endpoint::delete("/api/me/sessions", auth::revoke_all_sessions)
            .summary("Sign out everywhere")
            .describe(
                "Ends every browser session, including this one. Leaves access tokens \
                 alone — those are a separate credential with their own revocation.",
            ),
        Endpoint::post("/api/me/passkeys/start", auth::add_passkey_start)
            .returns("RegistrationChallenge")
            .summary("Challenge to add another authenticator")
            .describe(
                "One passkey is one device, and there is no email to recover \
                 through. A second is the recovery story.",
            ),
        Endpoint::post("/api/me/passkeys/finish", auth::add_passkey_finish)
            .takes("FinishRegistration")
            .status(204)
            .summary("Register the additional authenticator"),
        Endpoint::get("/api/me/passkeys", auth::list_passkeys)
            .returns("PasskeyList")
            .summary("Authenticators registered to this account"),
        Endpoint::delete("/api/me/passkeys/{id}", auth::remove_passkey)
            .status(204)
            .summary("Remove an authenticator")
            .describe(
                "Refuses to remove the last one: that would lock the account out \
                 permanently, and the click looks like tidying up.",
            ),
        Endpoint::patch("/api/me/passkeys/{id}", auth::rename_passkey)
            .takes("RenameKeyRequest")
            .status(204)
            .summary("Name an authenticator"),
        Endpoint::post("/api/me/sso/link/start", sso::sso_link_start)
            .returns("SsoStartResponse")
            .summary("Link this account to an org's identity provider")
            .describe(
                "The authenticated counterpart to /api/auth/sso/start. Requires the account \
                 to already have an email (PATCH /api/me first if it does not); the ceremony \
                 carries this account's own user id, so the callback links to it by \
                 construction rather than by any email match. This is the self-service path \
                 for an existing passkey account whose email collides with what the anonymous \
                 sign-in path refuses.",
            ),
        Endpoint::patch("/api/me", auth::set_profile)
            .takes("ProfileRequest")
            .returns("User")
            .summary("Set the address, display name and language")
            .describe(
                "The one endpoint that will say an address is already in use. It \
                 needs a session, which makes that answer attributable and \
                 rate-limited rather than something a stranger can walk a list \
                 against — which is why the address is set here and not at signup. \
                 `locale` takes three states, not two: omit it to leave the console \
                 language alone, send a supported locale to set it, or send an \
                 explicit `null` to clear it and go back to following the browser.",
            ),
        // ------------------------------------------------------------ orgs
        Endpoint::get("/api/orgs", orgs::list_orgs)
            .returns("MembershipList")
            .summary("Orgs this account belongs to"),
        Endpoint::post("/api/orgs", orgs::create_org)
            .takes("CreateOrgRequest")
            .returns("Org")
            .status(201)
            .summary("Create an org")
            .describe("The creator becomes its owner. Requires a registered passkey."),
        Endpoint::get("/api/orgs/{org}", orgs::get_org)
            .auth(Auth::OrgMember)
            .returns("Joined")
            .summary("One org, with your role in it"),
        Endpoint::get("/api/orgs/{org}/members", orgs::list_members)
            .auth(Auth::OrgMember)
            .returns("OrgMemberList")
            .summary("Everyone in the org")
            .describe("Open to any member: who else is in your own org is not privileged."),
        Endpoint::patch("/api/orgs/{org}/members/{user}", orgs::set_member_role)
            .auth(Auth::OrgAdmin)
            .takes("RoleRequest")
            .status(204)
            .summary("Change someone's role")
            .describe(
                "Only an owner may create or demote another owner, and the last owner \
                 cannot be demoted.",
            ),
        Endpoint::post(
            "/api/orgs/{org}/members/{user}/reset-passkeys",
            orgs::reset_member_passkeys,
        )
        .auth(Auth::OrgAdmin)
        .returns("ClaimCode")
        .status(201)
        .summary("Clear a member's passkeys and issue a re-registration code")
        .describe(
            "The only assisted account recovery there is. Clears every passkey, ends \
             every session, and returns a one-time code the admin hands over — the \
             code is what stops the account being claimable by whoever reaches \
             registration first. Only an owner may reset an owner.",
        ),
        Endpoint::delete("/api/orgs/{org}/members/{user}", orgs::remove_member)
            .auth(Auth::OrgAdmin)
            .status(204)
            .summary("Remove a member")
            .describe(
                "Also clears their team memberships and revokes the tokens they held \
                 in this org. Removing yourself needs no privilege; the last owner \
                 cannot be removed.",
            ),
        Endpoint::post("/api/orgs/{org}/members/{user}/logout", orgs::force_logout)
            .auth(Auth::OrgAdmin)
            .summary("Force a member to sign out")
            .describe(
                "Ends every browser session that user holds. For a lost laptop — it \
             leaves membership and tokens alone.",
            ),
        // --------------------------------------------------------- invites
        Endpoint::get("/api/orgs/{org}/invites", orgs::list_invites)
            .auth(Auth::OrgAdmin)
            .returns("InviteList")
            .summary("Outstanding invitations"),
        Endpoint::post("/api/orgs/{org}/invites", orgs::create_invite)
            .auth(Auth::OrgAdmin)
            .takes("InviteRequest")
            .returns("CreatedInvite")
            .status(201)
            .summary("Invite someone by email address")
            .describe(
                "Returns a single-use code, good for 14 days, which the admin \
                 delivers however they like — nothing is emailed. The code is shown \
                 only in this response and cannot be read back; only its hash is \
                 stored. Supersedes any live invitation for the same address. Only an \
                 owner may invite an owner. Redeemable only by someone signed in as \
                 the address invited, so a leaked code is not a free seat.",
            ),
        Endpoint::delete("/api/orgs/{org}/invites/{id}", orgs::revoke_invite)
            .auth(Auth::OrgAdmin)
            .status(204)
            .summary("Withdraw an invitation"),
        Endpoint::post("/api/orgs/{org}/invites/accept", orgs::accept_invite)
            .takes("AcceptInviteRequest")
            .returns("Joined")
            .summary("Accept an invitation")
            .describe(
                "Requires a session whose verified address matches the one invited — \
                 otherwise a forwarded invitation mail is a way into someone else's \
                 org. POST, like every other credential redemption here.",
            ),
        // ----------------------------------------------------------- teams
        Endpoint::get("/api/orgs/{org}/teams", teams::list_teams)
            .auth(Auth::OrgMember)
            .returns("TeamList")
            .summary("Teams in this org"),
        Endpoint::post("/api/orgs/{org}/teams", teams::create_team)
            .auth(Auth::OrgAdmin)
            .takes("CreateTeamRequest")
            .returns("Team")
            .status(201)
            .summary("Create a team"),
        Endpoint::get("/api/orgs/{org}/teams/{team}", teams::get_team)
            .auth(Auth::OrgMember)
            .returns("Team")
            .summary("One team, by slug"),
        Endpoint::patch("/api/orgs/{org}/teams/{team}", teams::update_team)
            .auth(Auth::OrgAdmin)
            .takes("TeamPatch")
            .returns("Team")
            .summary("Rename a team"),
        Endpoint::delete("/api/orgs/{org}/teams/{team}", teams::delete_team)
            .auth(Auth::OrgAdmin)
            .status(204)
            .summary("Delete a team")
            .describe(
                "Deletes the team outright. Resource servers hold their own rows scoped \
                 to a team and are responsible for cleaning up after one that no \
                 longer exists.",
            ),
        Endpoint::get(
            "/api/orgs/{org}/teams/{team}/members",
            teams::list_team_members,
        )
        .auth(Auth::OrgMember)
        .returns("TeamMemberList")
        .summary("Who is on a team"),
        Endpoint::put(
            "/api/orgs/{org}/teams/{team}/members/{user}",
            teams::add_team_member,
        )
        .auth(Auth::OrgAdmin)
        .status(204)
        .summary("Put a member on a team")
        .describe("Idempotent. The user must already be a member of the org."),
        Endpoint::delete(
            "/api/orgs/{org}/teams/{team}/members/{user}",
            teams::remove_team_member,
        )
        .auth(Auth::OrgAdmin)
        .status(204)
        .summary("Take a member off a team"),
        // ---------------------------------------------------- enterprise sso
        Endpoint::get("/api/orgs/{org}/sso/connection", sso::get_connection)
            .auth(Auth::OrgAdmin)
            .returns("IdpConnection")
            .summary("This org's bound identity provider, if any")
            .describe(
                "204 with no body when nothing is bound. Never the secret: IdpConnection \
                 carries only issuer, clientId, and the cached discovery document — \
                 clientSecret is sealed at rest and has no read path at all.",
            ),
        Endpoint::put("/api/orgs/{org}/sso/connection", sso::upsert_connection)
            .auth(Auth::OrgAdmin)
            .takes("SsoConnectionRequest")
            .returns("IdpConnection")
            .summary("Bind (or replace) this org's identity provider")
            .describe(
                "Fetches the issuer's discovery document before writing anything, and \
                 rejects if it is unreachable or missing authorization_endpoint/\
                 token_endpoint/jwks_uri — a connection is never saved half-configured. \
                 clientSecret is write-only: it is sealed at rest and never returned by any \
                 endpoint. Binding a second IdP replaces the first, one connection per org.",
            ),
        Endpoint::delete("/api/orgs/{org}/sso/connection", sso::delete_connection)
            .auth(Auth::OrgAdmin)
            .status(204)
            .summary("Remove this org's identity provider")
            .describe(
                "Refused while enforce_sso is on: removing the org's only IdP while every \
                 member's passkey login is refused would lock everyone out, including the \
                 admin issuing this call, with no path back in. Turn off enforce_sso first.",
            ),
        Endpoint::get("/api/orgs/{org}/sso/domains", sso::list_domains)
            .auth(Auth::OrgAdmin)
            .returns("ClaimedDomainList")
            .summary("This org's claimed email domains, verified or not"),
        Endpoint::post("/api/orgs/{org}/sso/domains", sso::claim_domain)
            .auth(Auth::OrgAdmin)
            .takes("ClaimDomainRequest")
            .returns("ClaimedDomain")
            .status(201)
            .summary("Claim an email domain and mint its verification token")
            .describe(
                "A domain is globally unique — claimed by at most one org at a time. \
                 Re-claiming a domain this org already holds mints a fresh token and resets \
                 verification. Returns the exact TXT record name and value to publish.",
            ),
        Endpoint::post(
            "/api/orgs/{org}/sso/domains/{domain}/verify",
            sso::verify_domain,
        )
        .auth(Auth::OrgAdmin)
        .returns("VerifyDomainResponse")
        .summary("Check the domain's DNS TXT record")
        .describe(
            "A synchronous, admin-initiated DNS lookup — not a background poller. \
             {verified: false} is not an error; it means DNS has not propagated yet, and the \
             admin can retry.",
        ),
        Endpoint::delete("/api/orgs/{org}/sso/domains/{domain}", sso::delete_domain)
            .auth(Auth::OrgAdmin)
            .status(204)
            .summary("Release a claimed domain")
            .describe(
                "Refused while enforce_sso is on and this is the org's only verified domain — \
                 removing the last routable SSO path would strand every member who is not \
                 already linked. Deleting a non-last verified domain, or an unverified one, \
                 always proceeds.",
            ),
        Endpoint::put("/api/orgs/{org}/sso/enforce", sso::set_enforce)
            .auth(Auth::OrgAdmin)
            .takes("EnforceSsoRequest")
            .returns("Org")
            .summary("Require single sign-on for this org's members")
            .describe(
                "Refuses to turn this on unless the org already has both a bound identity \
                 provider and at least one verified domain — enabling it with no working IdP \
                 path would lock every passkey-only member out with no way back in. Once on, \
                 no member of this org can complete a passkey sign-in; they must authenticate \
                 through the org's IdP.",
            ),
        // -------------------------------------------------- tokens & usage
        Endpoint::get("/api/orgs/{org}/tokens", tokens::list_tokens)
            .auth(Auth::OrgMember)
            .returns("TokenSummaryList")
            .summary("Your live tokens in this org")
            .describe("Yours only, OAuth tokens included, so you can cut off any agent."),
        Endpoint::post("/api/orgs/{org}/tokens", tokens::mint_token)
            .auth(Auth::OrgMember)
            .takes("MintTokenRequest")
            .returns("MintedToken")
            .status(201)
            .summary("Mint a personal access token")
            .describe(
                "The compatibility path for clients whose OAuth support is partial. \
                 Names the resource server it is for (optional while exactly one is \
                 registered) and scopes that server defines. Shown once. You can only \
                 mint your own, and only with scopes you hold.",
            ),
        Endpoint::delete("/api/orgs/{org}/tokens/{id}", tokens::revoke_token)
            .auth(Auth::OrgMember)
            .status(204)
            .summary("Revoke one of your tokens")
            .describe(
                "Takes effect when the resource server next introspects the token, \
                 not at some later expiry.",
            ),
        Endpoint::get("/api/orgs/{org}/usage", usage::get_usage)
            .auth(Auth::OrgMember)
            .returns("UsageStatus")
            .summary("This period's usage against the plan")
            .describe("Free to read, and readable by an org that has run out."),
        Endpoint::get("/api/orgs/{org}/audit", usage::get_audit)
            .auth(Auth::OrgAdmin)
            .returns("AuditEventList")
            .summary("The org's security log")
            .describe(
                "Admin-only, unlike the rest of the console's reads: membership \
                 changes and failed logins are what an attacker with a low-privilege \
                 session would read before choosing a target.",
            ),
    ]
}
