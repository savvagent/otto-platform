//! Orgs, members, and invitations.
//!
//! Two rules run through the whole file.
//!
//! **An org you are not in is `404`, never `403`.** Answering "forbidden" on a
//! real slug and "not found" on a fake one turns any signed-in account into a
//! directory of which companies use the product. Both collapse into one answer
//! in [`crate::session::OrgCtx`], and nothing here re-opens the distinction.
//!
//! **The last owner cannot be removed or demoted.** An org with no owner has
//! nobody who can change its billing, bind an IdP, or delete it — a state only
//! someone with database access can undo. It is refused at the last one rather
//! than repaired afterwards.

use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use otto_core::invites::Invite;
use otto_core::invites::InvitesExt;
use otto_core::orgs::OrgsExt;
use otto_core::orgs::OrgsTxExt;
use otto_core::orgs::{Membership, Org, OrgMember, Role};
use otto_core::teams::TeamsExt;
use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::UserId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::session::{role_name, CurrentUser, OrgCtx};
use crate::state::{client_ip, AppState};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRequest {
    pub role: Role,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteRequest {
    pub email: String,
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Member
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Joined {
    pub org: Org,
    pub role: Role,
}

/// `GET /api/orgs` — the orgs this account belongs to.
pub async fn list_orgs(
    State(state): State<AppState>,
    caller: CurrentUser,
) -> ApiResult<Json<Vec<Membership>>> {
    Ok(Json(state.db.list_user_orgs(caller.user.id).await?))
}

/// `POST /api/orgs` — create an org, with the caller as its owner.
///
/// Self-serve: any verified account may create one, which is what makes the
/// product's first five minutes work without a sales conversation. The creator
/// is the owner because an org with no owner cannot be administered at all.
pub async fn create_org(
    State(state): State<AppState>,
    caller: CurrentUser,
    Json(req): Json<CreateOrgRequest>,
) -> ApiResult<Response> {
    // Claiming an org slug — a public identifier — must cost more than typing an
    // address. There is no email verification to lean on, so the bar is a
    // confirmed authenticator: the account has to be one somebody can actually
    // sign back into.
    //
    // Very nearly redundant, since signup issues no session until enrollment is
    // confirmed. Not quite: `login_recovery_code` opens a session, and an admin
    // may have reset that member's credential, which leaves a signed-in account
    // with nothing enrolled. This is the check that notices.
    if !otto_auth::passkeys::has_credential(&state.db, caller.user.id).await? {
        return Err(ApiError::forbidden(
            "register a passkey before creating an organization",
        ));
    }

    let org = state
        .db
        .create_org_with_owner(req.slug.trim(), req.name.trim(), caller.user.id)
        .await?;

    let _ = state
        .db
        .audit_for_org(
            org.id,
            Entry::new(action::MEMBER_JOINED)
                .actor(caller.user.id)
                .target("org", org.id.to_string())
                .detail(serde_json::json!({ "role": "owner", "reason": "created the org" })),
        )
        .await;

    Ok((http::StatusCode::CREATED, Json(org)).into_response())
}

/// `GET /api/orgs/{org}` — one org, with the caller's role in it.
pub async fn get_org(ctx: OrgCtx) -> ApiResult<Json<Joined>> {
    Ok(Json(Joined {
        org: ctx.org,
        role: ctx.role,
    }))
}

/// `GET /api/orgs/{org}/members` — everyone in the org.
///
/// Readable by any member, not just admins: knowing who else is in your own org
/// is not privileged information, and an org where you cannot see who else is
/// in it is not a team.
pub async fn list_members(
    State(state): State<AppState>,
    ctx: OrgCtx,
) -> ApiResult<Json<Vec<OrgMember>>> {
    Ok(Json(state.db.list_org_members(ctx.org.id).await?))
}

/// `PATCH /api/orgs/{org}/members/{user}` — change someone's role.
pub async fn set_member_role(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, user)): Path<(String, Uuid)>,
    Json(req): Json<RoleRequest>,
) -> ApiResult<Response> {
    ctx.require_admin()?;
    let target = UserId::from(user);

    let current = state
        .db
        .member_role(ctx.org.id, target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this org"))?;

    // Only an owner may mint another owner. An admin who could promote
    // themselves to owner is an admin with owner powers one request away, which
    // makes the distinction between the two roles decorative.
    if req.role == Role::Owner || current == Role::Owner {
        ctx.require_owner()?;
    }

    // The guard and the write share one transaction: see
    // `Tx::count_owners_for_update`'s doc comment for why a separate
    // read-then-write across two connections is not enough.
    let mut tx = state.db.begin(ctx.org.id).await?;
    if current == Role::Owner && req.role != Role::Owner {
        guard_last_owner_locked(&mut tx, &ctx).await?;
    }
    tx.add_member(target, req.role).await?;
    tx.commit().await?;

    let _ = state
        .db
        .audit_for_org(
            ctx.org.id,
            Entry::new(action::MEMBER_ROLE_CHANGED)
                .actor(ctx.user.id)
                .target("user", target.to_string())
                .detail(serde_json::json!({
                    "from": role_name(current),
                    "to": role_name(req.role),
                })),
        )
        .await;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/orgs/{org}/members/{user}` — remove someone from the org.
///
/// Also clears their team memberships and revokes the tokens they held **in
/// this org**. Leaving those behind is the whole failure: a removed member's
/// agent keeps working with a token that outlives their membership by
/// up to its full lifetime, and nothing in the console would show why.
///
/// Their *sessions* are untouched, because a session is not org-scoped — it is
/// how they reach their other orgs, and signing someone out of an unrelated
/// customer's console is not this endpoint's business.
pub async fn remove_member(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, user)): Path<(String, Uuid)>,
) -> ApiResult<Response> {
    let target = UserId::from(user);

    // Leaving on your own account needs no privilege; removing someone else
    // does. Without the self case, the last member of an org they no longer
    // want cannot get out of it.
    if target != ctx.user.id {
        ctx.require_admin()?;
    }

    let current = state
        .db
        .member_role(ctx.org.id, target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this org"))?;

    // Deletion is strictly stronger than demotion: an admin who cannot demote
    // an owner (`set_member_role` requires `require_owner()` for that) must
    // not be able to reach the same outcome by removing them outright. Not
    // gated on self-removal — an owner may always leave on their own account,
    // subject to the last-owner guard below.
    if current == Role::Owner && target != ctx.user.id {
        ctx.require_owner()?;
    }

    // The guard, the team cleanup, the membership removal, the token
    // revocation, and the audit entry all share one transaction. Revoking
    // tokens on a second connection (as a prior version of this handler did)
    // left a window where a failure after the membership row was already
    // gone left the removed member's bearer token still live — introspection
    // does not re-check membership, so it would keep working until it
    // expired on its own. Sharing this transaction with the last-owner guard
    // also closes the TOCTOU race two concurrent removals could otherwise hit.
    let mut tx = state.db.begin(ctx.org.id).await?;
    if current == Role::Owner {
        guard_last_owner_locked(&mut tx, &ctx).await?;
    }
    tx.remove_from_all_teams(target).await?;
    tx.remove_member(target).await?;
    let revoked = otto_auth::tokens::revoke_all_in_org_tx(tx.conn(), target, ctx.org.id).await?;
    tx.audit(
        Entry::new(action::MEMBER_REMOVED)
            .actor(ctx.user.id)
            .target("user", target.to_string())
            .detail(serde_json::json!({ "role": role_name(current) })),
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        org = %ctx.org.slug,
        %target,
        revoked,
        "removed a member and revoked their tokens for this org"
    );

    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// Refuse to leave an org ownerless.
///
/// Locks the owner rows for the rest of `tx` (see
/// `Tx::count_owners_for_update`), so the caller's own write further down the
/// same transaction is guaranteed consistent with what this just counted.
async fn guard_last_owner_locked(tx: &mut otto_tenant::Tx<'_>, ctx: &OrgCtx) -> ApiResult<()> {
    if tx.count_owners_for_update().await? <= 1 {
        return Err(ApiError::conflict(
            "last_owner",
            format!(
                "{} would be left with no owner. Make someone else an owner first — \
                 an org without one has nobody who can manage billing or members.",
                ctx.org.slug
            ),
        ));
    }
    Ok(())
}

/// `POST /api/orgs/{org}/members/{user}/logout` — end every session that user
/// holds, everywhere.
///
/// The button an admin reaches for when a laptop goes missing. Deliberately
/// *not* the same action as removing them: this ends browser sessions and
/// leaves membership alone, so they can sign back in on a device that is still
/// theirs.
///
/// Sessions are deliberately not org-scoped (see `otto_auth::sessions`'s module
/// doc — one login reaches every org a person belongs to, so they are not
/// asked to sign in twice), which means this org-scoped action's effect is
/// not: an admin here also ends that member's sessions for orgs unrelated to
/// this one. Org-scoped sessions would be the complete fix and do not exist
/// yet, so in the meantime this is restricted to owners rather than any
/// admin, narrowing who can trigger a cross-org effect from inside one org.
pub async fn force_logout(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, user)): Path<(String, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    ctx.require_owner()?;
    let target = UserId::from(user);

    state
        .db
        .member_role(ctx.org.id, target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this org"))?;

    let revoked = otto_auth::sessions::revoke_all(&state.db, target).await?;
    Ok(Json(serde_json::json!({ "sessionsRevoked": revoked })))
}

// ---------------------------------------------------------------- invites

/// `POST /api/orgs/{org}/members/{user}/reset-passkeys` — clear a member's
/// authenticators and issue a one-time code to register a new one.
///
/// **The only assisted way back into an account.** There is no email, so
/// someone who has lost every device they registered has exactly one other
/// route: an admin of an org they belong to.
///
/// Clearing and issuing happen together, and that is the whole point. An
/// account with no passkeys and no outstanding claim is claimable by whoever
/// reaches registration first — which is precisely the takeover an earlier
/// version of this endpoint opened, where a stranger who knew the address could
/// win the race against the member. The code is what makes the account
/// re-registrable *only* by whoever the admin hands it to.
///
/// The limits are deliberate:
///
/// - Admin-only, and an owner's credentials may be reset only by an owner —
///   the same ordering as `remove_member`, so this is not a way around it.
///   The same ordering must hold in **every other org the member belongs
///   to**, because the account is not org-scoped: see the check below.
/// - Every live session of theirs dies, so a reset interrupts whoever is
///   currently holding the account.
/// - It grants the admin nothing *directly*: no session is opened here. But the
///   code is a way in until it is redeemed, so an admin who keeps it can use it
///   — assisted recovery always means the assistant could impersonate, and the
///   honest mitigations are that it is auditable and that it expires.
pub async fn reset_member_passkeys(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, user)): Path<(String, Uuid)>,
    parts: Parts,
) -> ApiResult<Response> {
    ctx.require_admin()?;
    let target = UserId::from(user);

    let current = state
        .db
        .member_role(ctx.org.id, target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this org"))?;

    if current == Role::Owner && target != ctx.user.id {
        ctx.require_owner()?;
    }

    // An account is not org-scoped: clearing its passkeys and handing out a
    // claim code is a full takeover of a person who may belong to — and own —
    // other orgs this caller has no authority in. Being an admin *here* must
    // not be a way into an owner seat *there*, so the caller must hold at
    // least the same authority over the account in every org it belongs to
    // (owner where the target is an owner, admin otherwise). Resetting your
    // own account is always yours to do. The refusal does not name the other
    // orgs, which are not this caller's to learn.
    if target != ctx.user.id {
        for membership in state.db.list_user_orgs(target).await? {
            if membership.org_id == ctx.org.id {
                continue;
            }
            let held = state.db.member_role(membership.org_id, ctx.user.id).await?;
            let sufficient = match (held, membership.role) {
                (Some(Role::Owner), _) => true,
                (Some(_), Role::Owner) => false,
                (Some(role), _) => role.can_administer(),
                (None, _) => false,
            };
            if !sufficient {
                return Err(ApiError::forbidden(
                    "this account belongs to other organizations you do not administer, so \
                     its authenticators cannot be reset from here. The member can sign in \
                     with another registered passkey, or an admin of their other \
                     organizations can reset them",
                ));
            }
        }
    }

    let ip = client_ip(&parts, &state.config);
    let token = otto_auth::crypto::generate(otto_auth::crypto::prefix::INVITE);

    // Clearing the passkeys, ending the sessions they opened, minting the
    // claim code, and recording the audit row all share one transaction: a
    // failure partway through must not leave the account cleared with no way
    // back in (savvagent/otto-factory#87), and must not leave the audit row
    // losable independently of the destructive change it records
    // (savvagent/otto-factory#134). This used to also write a second,
    // best-effort, post-commit `auth.passkey.cleared` row on an unpinned
    // connection, on the theory that it mirrored what a self-service clear
    // writes globally (`otto_auth::passkeys::clear`) — but there is no
    // self-service passkey clear in production, so that write had no live
    // counterpart to mirror and only duplicated this row under a second
    // action name. Dropped rather than merely re-scoped: this one row,
    // already atomic and already org-scoped, is `#134`'s actual fix for this
    // call site. See `otto_auth::passkeys::clear`'s doc comment.
    let mut tx = state.db.begin(ctx.org.id).await?;
    otto_auth::passkeys::clear_tx(tx.conn(), target).await?;
    otto_auth::sessions::revoke_all_tx(tx.conn(), target).await?;
    otto_core::invites::create_account_claim_tx(tx.conn(), target, &token.hash, Some(ctx.user.id))
        .await?;
    tx.audit(
        Entry::new(action::MEMBER_PASSKEYS_RESET)
            .actor(ctx.user.id)
            .target("user", target.to_string())
            .from_request(ip.as_deref(), None),
    )
    .await?;
    tx.commit().await?;

    let code = token.into_plaintext();
    let link = state.config.url(&format!("/claim?code={code}"));

    Ok((
        http::StatusCode::CREATED,
        Json(serde_json::json!({ "code": code, "link": link })),
    )
        .into_response())
}

/// `GET /api/orgs/{org}/invites` — invitations still outstanding.
pub async fn list_invites(
    State(state): State<AppState>,
    ctx: OrgCtx,
) -> ApiResult<Json<Vec<Invite>>> {
    ctx.require_admin()?;
    let mut tx = state.db.begin(ctx.org.id).await?;
    let invites = tx.list_invites().await?;
    tx.commit().await?;
    Ok(Json(invites))
}

/// `POST /api/orgs/{org}/invites` — invite someone by email address.
///
/// **The code comes back to the admin, who delivers it themselves.** otto-platform
/// sends no mail, so there is no "we have emailed them" step and no window in
/// which a live invitation exists that nobody received — the two failure modes
/// the mailed version had to work around. How the code travels is the admin's
/// business: Slack, a ticket, out loud across a desk. The server ships no
/// opinion about the workflow around it.
///
/// The token is generated here and stored only as a hash, like every other
/// credential in the product; `otto-core` never sees the plaintext. It is
/// returned **once**, in this response. There is no endpoint that reads it
/// back, because only the hash is kept — an admin who loses it re-invites,
/// which supersedes the old one.
///
/// The address is the account the invitation is *for*, and acceptance checks it
/// (`Error::InviteWrongAccount`), so a leaked code is not a free seat: it is
/// only redeemable by someone signed in as that address.
pub async fn create_invite(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Json(req): Json<InviteRequest>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    // Only an owner may hand out ownership.
    if req.role == Role::Owner {
        ctx.require_owner()?;
    }

    let token = otto_auth::crypto::generate(otto_auth::crypto::prefix::INVITE);
    let email = req.email.trim().to_string();

    let mut tx = state.db.begin(ctx.org.id).await?;
    let invite = tx
        .create_invite(&email, req.role, Some(ctx.user.id), &token.hash)
        .await?;
    tx.audit(
        Entry::new(action::MEMBER_INVITED)
            .actor(ctx.user.id)
            .target("invite", invite.id.to_string())
            .detail(serde_json::json!({ "email": email, "role": role_name(req.role) })),
    )
    .await?;
    tx.commit().await?;

    let code = token.into_plaintext();
    let link = state
        .config
        .url(&format!("/invite/{}?token={}", ctx.org.slug, code));

    Ok((
        http::StatusCode::CREATED,
        Json(CreatedInvite { invite, code, link }),
    )
        .into_response())
}

/// An invitation, plus the one-time code — returned only from the call that
/// mints it.
///
/// `code` and `link` are the same secret twice: the bare code for an admin
/// reading it out or pasting it into chat, and a URL that drops the invitee on
/// the console page which redeems it. Neither is recoverable afterwards.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedInvite {
    #[serde(flatten)]
    pub invite: otto_core::invites::Invite,
    pub code: String,
    pub link: String,
}

/// `DELETE /api/orgs/{org}/invites/{id}` — withdraw an invitation.
pub async fn revoke_invite(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, id)): Path<(String, Uuid)>,
) -> ApiResult<Response> {
    ctx.require_admin()?;
    let mut tx = state.db.begin(ctx.org.id).await?;
    tx.revoke_invite(id).await?;
    tx.commit().await?;
    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/orgs/{org}/invites/accept` — join, using the invite token the
/// admin delivered.
///
/// **A `POST`, like every other credential redemption here** — the link an
/// admin pastes into chat or a ticket points at a page that renders a button,
/// and a link-preview fetcher or mail scanner that follows it finds a page
/// rather than a spent invitation.
///
/// Requires a session whose address matches the one invited. Signing in is what
/// proves the address — a session exists only for an account holding a confirmed
/// authenticator — so a forwarded code is not a way into someone else's org for
/// whoever reads it first. This is what keeps a leaked invite code from being a
/// free seat.
pub async fn accept_invite(
    State(state): State<AppState>,
    caller: CurrentUser,
    Path(org_slug): Path<String>,
    parts: Parts,
    Json(req): Json<AcceptInviteRequest>,
) -> ApiResult<Json<Joined>> {
    if !otto_auth::passkeys::has_credential(&state.db, caller.user.id).await? {
        return Err(ApiError::forbidden(
            "register a passkey before accepting an invitation",
        ));
    }

    // Not `OrgCtx`: the whole point is that the caller is not a member yet, so
    // the org is resolved by slug directly. The invitation itself is the
    // authority for admission, and it is scoped to this org by the pinned
    // transaction below.
    let org = state
        .db
        .get_org_by_slug(&org_slug)
        .await?
        .ok_or(otto_core::Error::InviteInvalid)?;

    let hash = otto_auth::crypto::hash(req.token.trim());

    // An account with no address cannot be the one an invitation names, and
    // saying so plainly beats a generic refusal — the fix is to set it.
    let Some(address) = caller.user.email.as_deref() else {
        return Err(ApiError::forbidden(
            "set your email address before accepting an invitation — an invitation \
             names an address, and this account does not have one yet",
        ));
    };

    let mut tx = state.db.begin(org.id).await?;
    let role = tx.accept_invite(&hash, caller.user.id, address).await?;
    tx.audit(
        Entry::new(action::MEMBER_JOINED)
            .actor(caller.user.id)
            .from_request(client_ip(&parts, &state.config).as_deref(), None)
            .target("user", caller.user.id.to_string())
            .detail(serde_json::json!({ "role": role_name(role) })),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(Joined { org, role }))
}
