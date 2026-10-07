//! Signing up, signing in, and the passkey that is both.
//!
//! ## No email, and now no identifier either
//!
//! A passkey brings an account into existence: [`signup_start`] creates the row
//! with **no address at all**, and [`signup_finish`] turns it into an account
//! once a credential is registered against it. The address is a profile field
//! set afterwards, by someone already holding the key.
//!
//! That ordering is what finally closes the account-enumeration oracle. Removing
//! email forced signup to hand a TOTP secret back in its own response, which
//! meant refusing addresses that already had one — and that refusal was the
//! leak. Nothing is submitted to [`signup_start`] or [`login_start`], so there
//! is no question for either to answer differently. The one place the product
//! will say "that address is taken" is [`set_profile`], which needs a session.
//!
//! ## Every ceremony is two requests
//!
//! `…/start` issues a challenge and stores its state server-side; `…/finish`
//! presents the signature. The ceremony id in between is a lookup key, not a
//! credential: it is single-use, expiring, and useless without a signature the
//! matching authenticator can produce.
//!
//! ## No credential is ever spent on a `GET`
//!
//! Unchanged, and it still matters: an invitation code travels through chat,
//! and chat unfurls links.

use axum::extract::{Json, State};
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use otto_auth::ratelimit::{self, CapPolicy, LOGIN_CRED_CAP, LOGIN_IP_CAP};
use otto_auth::{login, passkeys, sessions, AuthError};
use otto_core::invites::AccountClaimsExt;
use otto_core::orgs::OrgsExt;
use otto_core::orgs::User;
use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::UserId;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::session::{self, CurrentUser};
use crate::state::{client_ip, AppState};

// --------------------------------------------------------------- payloads

/// Finish a registration ceremony.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistration {
    pub ceremony_id: uuid::Uuid,
    pub credential: passkeys::RegisterPublicKeyCredential,
    /// What to call this authenticator in the list. Worth asking for: an
    /// unlabelled set of keys is a set nobody dares delete from.
    #[serde(default)]
    pub nickname: Option<String>,
}

/// Finish an authentication ceremony.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishAuthentication {
    pub ceremony_id: uuid::Uuid,
    pub credential: passkeys::PublicKeyCredential,
}

/// Start re-registering with an admin-issued claim code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRequest {
    pub code: String,
}

/// Finish re-registering. Carries the code again, because it is spent at
/// `finish` rather than `start` — an interrupted ceremony must not burn
/// somebody's only way back into their account.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishClaim {
    pub ceremony_id: uuid::Uuid,
    pub code: String,
    pub credential: passkeys::RegisterPublicKeyCredential,
    #[serde(default)]
    pub nickname: Option<String>,
}

/// Set the profile on an account that has a passkey.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// The console language, in three states rather than two.
    ///
    /// | Body | Effect |
    /// |---|---|
    /// | field absent | leave the stored locale alone |
    /// | `"locale": "de"` | set it, if it is one of the supported locales |
    /// | `"locale": null` | clear it — go back to following the browser |
    ///
    /// The third state is why this is a [`super::double_option`] and `email`
    /// and `name` are not: "match my browser" is a real choice, and serde
    /// would otherwise collapse it into "leave alone".
    #[serde(default, deserialize_with = "super::double_option")]
    pub locale: Option<Option<String>>,
}

/// Name a registered key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameKeyRequest {
    pub nickname: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOpened {
    pub user: User,
    /// The account holds exactly one passkey.
    ///
    /// Not a failure — it signs in fine. It is the console's cue to ask for a
    /// second one, because one passkey is one device and there is no email to
    /// recover through if it is lost.
    pub should_add_passkey: bool,
}

// ---------------------------------------------------------------- handlers

/// The challenge half of a ceremony, as the browser needs it.
///
/// `ceremonyId` is opaque and worthless on its own: the server keeps the state
/// it names, single-use and expiring, and nothing here can be redeemed without
/// a signature from an authenticator that holds the matching key.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse<T> {
    pub ceremony_id: uuid::Uuid,
    pub challenge: T,
}

/// What the browser needs before it can talk about credentials at all.
///
/// The one field is public by necessity: the same string is inside every
/// creation challenge, and `/api/auth/signup/start` hands one to anybody who
/// asks. Publishing it costs nothing and saves the console from guessing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnConfig {
    pub rp_id: String,
}

/// `GET /api/auth/webauthn` — the relying party this deployment signs with.
///
/// Takes no session: a console needs this before anyone has signed in, and it
/// reveals nothing a challenge does not.
pub async fn webauthn_config(State(state): State<AppState>) -> ApiResult<Json<WebauthnConfig>> {
    // Not an unwrap and not a null. `otto_web::relying_party` refuses to build a
    // relying party without a host, so a running server always has one and this
    // arm is unreachable — but a `null` here would reach the console as a
    // silently skipped signal rather than as a failure, and the console has no
    // way to tell the two apart.
    let rp_id = state.config.rp_id().ok_or_else(|| {
        ApiError::internal(
            "webauthn_config",
            format!(
                "OTTO_PUBLIC_URL ({}) has no host, so there is no relying party id to publish",
                state.config.public_url
            ),
        )
    })?;

    Ok(Json(WebauthnConfig { rp_id }))
}

/// `POST /api/auth/signup/start` — create an account and challenge for a passkey.
///
/// Takes **no body**. The account is created here with no address, because the
/// passkey is what makes it an account; nothing about it is reachable by anyone
/// who does not go on to hold the key, so an abandoned signup leaves an inert
/// row rather than a claimable identity.
pub async fn signup_start(
    State(state): State<AppState>,
    parts: Parts,
) -> ApiResult<Json<ChallengeResponse<passkeys::CreationChallengeResponse>>> {
    throttle_by_source(&state, &parts).await?;

    let ceremony = passkeys::start_registration(&state.db, &state.webauthn, None).await?;
    Ok(Json(ChallengeResponse {
        ceremony_id: ceremony.id,
        challenge: ceremony.challenge,
    }))
}

/// `POST /api/auth/signup/finish` — register the passkey and open the first session.
pub async fn signup_finish(
    State(state): State<AppState>,
    parts: Parts,
    Json(req): Json<FinishRegistration>,
) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);
    let user = passkeys::finish_registration(
        &state.db,
        &state.webauthn,
        req.ceremony_id,
        &req.credential,
        req.nickname.as_deref(),
        passkeys::RegistrationVia::Signup,
        None,
        ip.as_deref(),
    )
    .await?;

    let opened = login::with_passkey(&state.db, user, ip.as_deref()).await?;
    signed_in_response(&state, opened).await
}

/// `POST /api/auth/login/start` — challenge for any passkey this server knows.
///
/// Deliberately takes no identifier and no body. The credential the browser
/// picks is what says who is signing in.
pub async fn login_start(
    State(state): State<AppState>,
) -> ApiResult<Json<ChallengeResponse<passkeys::RequestChallengeResponse>>> {
    let ceremony = passkeys::start_authentication(&state.db, &state.webauthn).await?;
    Ok(Json(ChallengeResponse {
        ceremony_id: ceremony.id,
        challenge: ceremony.challenge,
    }))
}

/// `POST /api/auth/login/finish` — present the signature and open a session.
///
/// Throttled on two independent keys (savvagent/otto-factory#75), both billed
/// through `otto_auth::ratelimit`'s rate **cap** rather than its exponential
/// lockout — see that module's docs for why a lockout is the wrong tool here.
/// `passkeys::finish_authentication` decides the credential's account from the
/// credential id alone, before any signature is verified, so this endpoint
/// answers a question — "is this id one we store?" — that costs an attacker
/// nothing to ask and writes no audit row to notice:
///
/// - `login:ip:{ip}` prices repeated probing from one source, generously,
///   because the source is frequently an office NAT or a CGNAT pool shared by
///   many honest sign-ins.
/// - `login:cred:{sha256(credential_id)}` prices repeated probing of one
///   specific credential, independent of source — the thing the address cap
///   alone cannot bound, since a botnet or an exit-node list gets a fresh
///   address-bucket per id.
///
/// `AuthError::CeremonyExpired` is excluded from both: a client that simply
/// took too long to answer its challenge is not an attack, and charging it
/// would let an ordinary slow connection do an attacker's accounting for them.
pub async fn login_finish(
    State(state): State<AppState>,
    parts: Parts,
    Json(req): Json<FinishAuthentication>,
) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);
    let ip_bucket = ip.as_deref().map(|ip| format!("login:ip:{ip}"));
    let cred_bucket = ratelimit::credential_bucket(req.credential.raw_id.as_ref());

    // Cheap and approximate (see `ratelimit::cap_peek`), not the enforcement
    // itself: skip the signature verification below for a caller already well
    // past a cap, without relying on this read to be exact.
    if let Some(bucket) = &ip_bucket {
        refuse_if_capped(&state, bucket, &LOGIN_IP_CAP).await?;
    }
    refuse_if_capped(&state, &cred_bucket, &LOGIN_CRED_CAP).await?;

    let outcome = passkeys::finish_authentication(
        &state.db,
        &state.webauthn,
        req.ceremony_id,
        &req.credential,
        ip.as_deref(),
    )
    .await;

    if matches!(outcome, Err(ref e) if !matches!(e, AuthError::CeremonyExpired)) {
        // Charge both buckets regardless of which one (if either) is already
        // over its cap: the credential bucket still needs this attempt's
        // accounting even when the source address is the one that refuses it,
        // since a future attempt against the same credential may arrive from
        // a different address.
        let mut refusal = None;
        if let Some(bucket) = &ip_bucket {
            if let Err(e) = ratelimit::cap_charge(&state.db, bucket, &LOGIN_IP_CAP).await {
                refusal.get_or_insert(e);
            }
        }
        if let Err(e) = ratelimit::cap_charge(&state.db, &cred_bucket, &LOGIN_CRED_CAP).await {
            refusal.get_or_insert(e);
        }
        if let Some(e) = refusal {
            return Err(e.into());
        }
    }

    let user = outcome?;
    let opened = login::with_passkey(&state.db, user, ip.as_deref()).await?;
    signed_in_response(&state, opened).await
}

/// Refuse early, without doing any credential work, if `bucket` is already
/// past `policy.hard_cap`. Best-effort only — see `ratelimit::cap_peek`.
async fn refuse_if_capped(state: &AppState, bucket: &str, policy: &CapPolicy) -> ApiResult<()> {
    let failures = ratelimit::cap_peek(&state.db, bucket, policy).await?;
    if failures >= policy.hard_cap {
        return Err(AuthError::RateLimited {
            retry_after_secs: policy.window_secs,
        }
        .into());
    }
    Ok(())
}

/// `POST /api/auth/claim/start` — begin re-registering after an admin reset.
///
/// The code is proof that an admin of an org this account belongs to issued it.
/// Without this endpoint an account with no passkeys would be claimable by
/// whoever reached signup first, which is the takeover this exists to prevent.
pub async fn claim_start(
    State(state): State<AppState>,
    parts: Parts,
    Json(req): Json<ClaimRequest>,
) -> ApiResult<Json<ChallengeResponse<passkeys::CreationChallengeResponse>>> {
    throttle_by_source(&state, &parts).await?;

    let user = state.db.peek_account_claim(&hash_claim(&req.code)).await?;
    let ceremony = passkeys::start_registration(&state.db, &state.webauthn, Some(user)).await?;

    Ok(Json(ChallengeResponse {
        ceremony_id: ceremony.id,
        challenge: ceremony.challenge,
    }))
}

/// `POST /api/auth/claim/finish` — register the new passkey and sign in.
///
/// The code is spent here rather than at `start`, so an interrupted ceremony
/// does not burn somebody's only way back into their account. Throttled the
/// same way `claim_start` is: this endpoint has no secret of its own to
/// rate-limit a guess against (the rollback below hands a wrong code straight
/// back rather than spending it), so the per-source cap is the only thing
/// pricing a script that tries codes against it.
///
/// The claim consumption, the ceremony consumption, the credential insert,
/// and the audit write all share one transaction (`savvagent/otto-factory#132`):
/// before this, the claim was spent by an autocommitted `UPDATE` and the
/// ceremony by `finish_registration`'s own autocommitted `DELETE`, both
/// *before* the credential/audit transaction `#131` added even opened. A
/// failure anywhere after either point — including the credential insert
/// itself, the audit write, `tx.commit()`, or this function's own
/// ceremony-ownership check below — used to leave the account with a burned
/// claim, a burned ceremony, and no passkey: for an org's last owner, nobody
/// above them can issue a second claim. Now any such failure rolls back
/// everything up to that point, and the claim and ceremony are both still
/// there for a retry. (This only covers up to `tx.commit()` itself — a
/// failure in `login::with_passkey` below runs after commit and cannot roll
/// the credential back; that path already tolerates its own audit-write
/// failure, logging rather than losing the session, see its doc comment.)
///
/// A rejection here — the ownership mismatch, or a failure inside
/// `finish_registration_tx` — writes a best-effort [`action::CLAIM_REFUSED`]
/// row once the transaction has rolled back. Without it, nothing durable
/// records the attempt at all: the row `finish_registration_tx` would have
/// written (`auth.passkey.registered`, `via = "claim"`) never lands, because
/// nothing commits. That row is the one event proving who completed an
/// admin-assisted takeover (see `finish_registration_tx`'s own doc comment),
/// so a *rejected* substitution attempt against this same, unauthenticated
/// endpoint deserves a trace for the same reason a successful one does.
pub async fn claim_finish(
    State(state): State<AppState>,
    parts: Parts,
    Json(req): Json<FinishClaim>,
) -> ApiResult<Response> {
    throttle_by_source(&state, &parts).await?;

    let ip = client_ip(&parts, &state.config);

    // Unpinned: `account_claims`, `webauthn_ceremonies`, and `passkeys` carry
    // no `org_id` and no `<table>_tenant_isolation` policy. Do not write a
    // tenant table on this connection — it has no `app.org_id` set, so guard
    // 2 (see `Db::begin`'s doc comment) does not apply to it at all.
    let mut tx = state.db.begin_unpinned().await?;
    let user =
        otto_core::invites::consume_account_claim_tx(tx.conn(), &hash_claim(&req.code)).await?;

    let registered = match passkeys::finish_registration_tx(
        &mut tx,
        &state.webauthn,
        req.ceremony_id,
        &req.credential,
        req.nickname.as_deref(),
        passkeys::RegistrationVia::Claim,
        None,
        ip.as_deref(),
    )
    .await
    {
        Ok(registered) => registered,
        Err(e) => {
            // `tx` drops here uncommitted, restoring the claim consumed
            // above — nothing durable happened. Attributed to `user` (the
            // claimed account), the one identity a code the request held
            // actually proved.
            drop(tx);
            note_claim_refused(&state, user, ip.as_deref(), "registration failed").await;
            return Err(e.into());
        }
    };

    // The ceremony was started against the claimed account; if these
    // disagree, something has been substituted and the safe answer is to
    // refuse — before anything commits, so a mismatch rolls back the claim
    // consumption and the credential/audit writes together instead of
    // leaving them durable for a request that gets rejected.
    if registered != user {
        drop(tx);
        // Attributed to `registered` — the ceremony's actual owner, whose
        // ownership a real signature just backed — rather than `user`, which
        // is only a claim the request itself made about which account it
        // wanted; `user` is still named in the detail for the trail to show
        // what was attempted.
        note_claim_refused(
            &state,
            registered,
            ip.as_deref(),
            &format!("ceremony belongs to a different account than claim code for {user}"),
        )
        .await;
        return Err(ApiError::forbidden(
            "that claim code is not for this ceremony",
        ));
    }

    if let Err(e) = tx.commit().await {
        note_claim_refused(&state, user, ip.as_deref(), "commit failed").await;
        return Err(e.into());
    }

    let opened = login::with_passkey(&state.db, user, ip.as_deref()).await?;
    signed_in_response(&state, opened).await
}

/// Best-effort audit trace for a `claim/finish` request that rolled back —
/// see [`claim_finish`]'s own doc comment for why this exists. Follows
/// `Db::audit_global`'s own best-effort-by-design contract: logged rather
/// than propagated, because losing this one row is worse to compound into a
/// second failure on an already-failed request than it is to simply lose it.
async fn note_claim_refused(state: &AppState, actor: UserId, ip: Option<&str>, reason: &str) {
    let entry = Entry::new(action::CLAIM_REFUSED)
        .actor(actor)
        .detail(serde_json::json!({ "reason": reason }))
        .from_request(ip, None);
    if let Err(e) = state.db.audit_global(entry).await {
        tracing::error!(
            error = %e,
            actor = %actor,
            "failed to write audit event for a refused claim"
        );
    }
}

/// Limit how many account-creating or claim attempts one source may make.
///
/// Signup no longer leaks anything, so this is not an anti-enumeration measure
/// any more — it is what stops a script minting accounts, and what prices
/// guessing at claim codes.
async fn throttle_by_source(state: &AppState, parts: &Parts) -> ApiResult<()> {
    let Some(ip) = client_ip(parts, &state.config) else {
        // Nothing trustworthy to key on. Deliberately not a shared "unknown"
        // bucket: the first attacker to trip it would lock out everyone else.
        return Ok(());
    };

    let bucket = format!("signup:{ip}");
    otto_auth::ratelimit::check_and_charge(&state.db, &bucket).await?;
    Ok(())
}

/// Attach the session cookie and describe the account that just signed in.
async fn signed_in_response(state: &AppState, logged_in: login::LoggedIn) -> ApiResult<Response> {
    let user = state
        .db
        .get_user(logged_in.user)
        .await?
        .ok_or_else(ApiError::unauthenticated)?;

    let body = Json(SessionOpened {
        user,
        should_add_passkey: logged_in.should_add_passkey,
    });

    Ok(session::with_cookie(
        body.into_response(),
        session::set_cookie(&logged_in.session_token),
    ))
}

fn hash_claim(code: &str) -> Vec<u8> {
    otto_auth::crypto::hash(code.trim())
}

/// `POST /api/auth/logout` — end this session.
///
/// Succeeds for a caller holding a cookie that resolves to nothing. Logging out
/// is not a privileged operation, and a visitor with a stale cookie asking to
/// be rid of it should be obliged.
pub async fn logout(State(state): State<AppState>, parts: Parts) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);

    if let Some(token) = session::token_from(&parts) {
        login::logout(&state.db, &token, ip.as_deref()).await?;
    }

    Ok(session::with_cookie(
        http::StatusCode::NO_CONTENT.into_response(),
        session::clear_cookie(),
    ))
}

// ------------------------------------------------------------------- me

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    pub user: User,
    pub orgs: Vec<otto_core::orgs::Membership>,
    /// One passkey. The console nags for a second; see [`SessionOpened`].
    pub should_add_passkey: bool,
    pub passkey_count: i64,
    /// What a fresh registration would file this account's credential under.
    ///
    /// Handed over rather than derived in the browser, because the console
    /// sends this pair straight back through `signalCurrentUserDetails` to
    /// repair credentials registered before there was anything to name them
    /// with. A second copy of the precedence and the prefix in TypeScript would
    /// drift, and the drift would be silent — the signal is accepted either way
    /// and would write words subtly unlike what registering again writes. See
    /// `otto_auth::passkeys::credential_names`.
    pub credential_name: String,
    /// The row a human reads when a vault asks them to choose a key. Same rule:
    /// the console must never compose it.
    pub credential_display_name: String,
}

/// `GET /api/me` — who is signed in, and what they can act in.
///
/// The console's first call on every load. Includes the org list because the
/// alternative is a second round trip before anything can be rendered.
pub async fn me(State(state): State<AppState>, caller: CurrentUser) -> ApiResult<Json<Me>> {
    let orgs = state.db.list_user_orgs(caller.user.id).await?;
    let passkey_count = passkeys::count(&state.db, caller.user.id).await?;
    let names = passkeys::credential_names(&caller.user);

    Ok(Json(Me {
        user: caller.user,
        orgs,
        should_add_passkey: passkey_count < 2,
        passkey_count,
        credential_name: names.name,
        credential_display_name: names.display_name,
    }))
}

/// `GET /api/me/sessions` — where this account is signed in.
pub async fn list_sessions(
    State(state): State<AppState>,
    caller: CurrentUser,
) -> ApiResult<Json<Vec<sessions::Session>>> {
    Ok(Json(sessions::list(&state.db, caller.user.id).await?))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokedSessions {
    pub revoked: u64,
}

/// `DELETE /api/me/sessions` — sign out everywhere, including here.
///
/// Sessions only. Access tokens and PATs are a separate credential with their
/// own revocation path, and someone dealing with a lost laptop needs both — but
/// quietly killing an org's agents from a button labelled "sign out everywhere"
/// is a different decision than the button describes.
pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    caller: CurrentUser,
) -> ApiResult<Response> {
    let revoked = sessions::revoke_all(&state.db, caller.user.id).await?;
    Ok(session::with_cookie(
        Json(RevokedSessions { revoked }).into_response(),
        session::clear_cookie(),
    ))
}

// ------------------------------------------------------- passkeys and profile

/// `POST /api/me/passkeys/start` — challenge to add another authenticator.
///
/// The recovery story, and the console asks for it straight after signup: one
/// passkey is one device, and there is no email to recover through.
pub async fn add_passkey_start(
    State(state): State<AppState>,
    caller: CurrentUser,
) -> ApiResult<Json<ChallengeResponse<passkeys::CreationChallengeResponse>>> {
    let ceremony =
        passkeys::start_registration(&state.db, &state.webauthn, Some(caller.user.id)).await?;
    Ok(Json(ChallengeResponse {
        ceremony_id: ceremony.id,
        challenge: ceremony.challenge,
    }))
}

/// `POST /api/me/passkeys/finish` — register it.
pub async fn add_passkey_finish(
    State(state): State<AppState>,
    caller: CurrentUser,
    parts: Parts,
    Json(req): Json<FinishRegistration>,
) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);
    passkeys::finish_registration(
        &state.db,
        &state.webauthn,
        req.ceremony_id,
        &req.credential,
        req.nickname.as_deref(),
        passkeys::RegistrationVia::Add,
        Some(caller.user.id),
        ip.as_deref(),
    )
    .await?;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/me/passkeys` — the authenticators on this account.
pub async fn list_passkeys(
    State(state): State<AppState>,
    caller: CurrentUser,
) -> ApiResult<Json<Vec<passkeys::RegisteredKey>>> {
    Ok(Json(passkeys::list(&state.db, caller.user.id).await?))
}

/// `DELETE /api/me/passkeys/{id}` — remove one, never the last.
pub async fn remove_passkey(
    State(state): State<AppState>,
    caller: CurrentUser,
    parts: Parts,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);
    passkeys::remove(&state.db, caller.user.id, id, ip.as_deref()).await?;
    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `PATCH /api/me/passkeys/{id}` — name one.
pub async fn rename_passkey(
    State(state): State<AppState>,
    caller: CurrentUser,
    parts: Parts,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Json(req): Json<RenameKeyRequest>,
) -> ApiResult<Response> {
    let ip = client_ip(&parts, &state.config);
    passkeys::rename(&state.db, caller.user.id, id, &req.nickname, ip.as_deref()).await?;
    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `PATCH /api/me` — set the address, display name and console language.
///
/// **The one place this product says "that address is taken."** It needs a
/// session, which makes the answer attributable, rate-limited and auditable —
/// unlike a signup endpoint, which a stranger can walk a list against. That is
/// the whole reason the address is set here rather than at signup.
pub async fn set_profile(
    State(state): State<AppState>,
    caller: CurrentUser,
    Json(req): Json<ProfileRequest>,
) -> ApiResult<Json<User>> {
    let updated = state
        .db
        .set_profile(
            caller.user.id,
            req.email.as_deref().filter(|e| !e.trim().is_empty()),
            req.name.as_deref().filter(|n| !n.trim().is_empty()),
            // Not filtered for emptiness the way the two above are: `""` is not
            // a locale and has to be refused by name, whereas silently reading
            // it as "leave alone" would make a broken picker look like it
            // worked. `null` is the way to clear it, and that arrives here as
            // `Some(None)`.
            req.locale
                .as_ref()
                .map(|inner| inner.as_deref().map(str::trim)),
        )
        .await?;
    Ok(Json(updated))
}
