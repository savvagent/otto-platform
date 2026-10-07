//! The human login front door.
//!
//! Thin now, and deliberately so. [`crate::passkeys`] does the work: a sign-in
//! is a WebAuthn ceremony that identifies the account from the credential the
//! browser produced, so there is no address typed into a form and no lookup to
//! answer carefully.
//!
//! What remains is session issuance, the disabled-account check, and logout.

use otto_core::orgs::OrgsExt;
use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::UserId;
use otto_tenant::Db;
use serde::Serialize;

use crate::error::{AuthError, Result};
use crate::passkeys;
use crate::sessions::{self, Session};

/// How the human proved who they were.
///
/// One variant, and it stays an enum because the audit trail records it and a
/// bare string there is a typo waiting to happen. A second variant appearing
/// means a second way into an account exists, which is a thing to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Passkey,
}

/// A successful login.
pub struct LoggedIn {
    pub user: UserId,
    /// The session cookie value, handed over once.
    pub session_token: String,
    pub session: Session,
    pub method: Method,
    /// The account holds exactly one passkey.
    ///
    /// Not a failure — it signs in perfectly well. It is the console's cue to
    /// ask for a second one, because a single passkey is a single device, and
    /// with no email there is no self-service way back from losing it.
    pub should_add_passkey: bool,
}

/// Open a session for an account that has just completed a WebAuthn ceremony.
///
/// The signature was already checked by [`passkeys::finish_authentication`];
/// what is left is the account-level question that a valid credential does not
/// answer — whether this account is still allowed in.
pub async fn with_passkey(db: &Db, user: UserId, ip: Option<&str>) -> Result<LoggedIn> {
    let account = db.get_user(user).await?.ok_or(AuthError::UnknownUser)?;

    // Checked *after* the ceremony rather than before, and the difference
    // matters: a disabled account's keys still produce valid signatures, and
    // refusing here means the refusal is attributable in the trail instead of
    // being a silent non-answer.
    if account.disabled_at.is_some() {
        note_refusal(db, user, ip, "account disabled").await;
        return Err(AuthError::Disabled);
    }

    // Enterprise OIDC federation: a member of any org with `enforce_sso =
    // true` cannot complete a passkey sign-in, full stop — `enforce_sso` is
    // scoped to org membership, not to which address the account holds, so
    // this is a membership check, not a domain check. Checked here, at the
    // same resolved-user_id-before-session-mint point every other login-time
    // decision (the disabled check above) already uses, rather than as a
    // second lookup bolted on elsewhere.
    if db.is_member_of_sso_enforced_org(user).await? {
        note_refusal(db, user, ip, "member of an org that requires SSO").await;
        return Err(AuthError::SsoRequired);
    }

    let session = sessions::create(db, user).await?;

    let entry = Entry::new(action::LOGIN_SUCCEEDED)
        .actor(user)
        .from_request(ip, None)
        .detail(serde_json::json!({ "method": "passkey" }));
    if let Err(e) = db.audit_global(entry).await {
        tracing::error!(error = %e, "failed to write audit event for a sign-in");
    }

    Ok(LoggedIn {
        user,
        session_token: session.token,
        session: session.session,
        method: Method::Passkey,
        should_add_passkey: passkeys::count(db, user).await? < 2,
    })
}

/// End a session and record it. The counterpart to every constructor above.
pub async fn logout(db: &Db, session_token: &str, ip: Option<&str>) -> Result<()> {
    // Resolve before revoking so the audit row names the user. A cookie that
    // resolves to nothing is still revoked below — logging out is not a
    // privileged operation and must not fail for a visitor holding a stale one.
    let user = sessions::resolve(db, session_token)
        .await
        .ok()
        .map(|s| s.user_id);

    sessions::revoke(db, session_token).await?;

    if let Some(user) = user {
        if let Err(e) = db
            .audit_global(
                Entry::new(action::LOGOUT)
                    .actor(user)
                    .from_request(ip, None),
            )
            .await
        {
            tracing::error!(error = %e, user_id = %user, "failed to write audit event for logout");
        }
    }
    Ok(())
}
/// The audit row a refused sign-in writes.
///
/// Best-effort: an audit write that fails is logged, never turned into an
/// authentication outage. The row names the account because by this point the
/// credential has already identified it — there is no address being guessed at.
async fn note_refusal(db: &Db, user: UserId, ip: Option<&str>, reason: &str) {
    let entry = Entry::new(action::LOGIN_FAILED)
        .actor(user)
        .from_request(ip, None)
        .detail(serde_json::json!({ "method": "passkey", "reason": reason }));
    if let Err(e) = db.audit_global(entry).await {
        tracing::error!(error = %e, "failed to write audit event for a refused sign-in");
    }
}
