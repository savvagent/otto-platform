//! Passkeys — WebAuthn registration and authentication.
//!
//! - **Phishing resistance.** A passkey signs over the origin it was registered
//!   to. A user can be talked into typing a six-digit code into a lookalike
//!   site; they cannot be talked into producing a signature their authenticator
//!   will only make for this server's public origin.
//! - **No shared secret at rest.** `passkeys` holds public keys. Losing the
//!   whole table to an attacker lets them sign in as nobody.
//! - **No identifier at sign-in.** Credentials are *discoverable*, so the
//!   browser resolves who you are from the key you pick. Nothing is submitted
//!   before the ceremony, so [`start_authentication`] has no address to leak —
//!   there is no account-enumeration oracle here at all.
//!
//! ## Two round trips, and the state between them
//!
//! Every ceremony is start-then-finish, and the challenge issued by the first
//! is what makes the second's signature meaningful. That state lives in
//! `webauthn_ceremonies` — **server side**, single-use, and expiring. Handing it
//! to the client to give back would let an attacker keep one and replay it,
//! which webauthn-rs warns about in capitals; holding it in process memory
//! would break the moment a second machine answered the second request.
//!
//! ## Two places this deliberately overrides webauthn-rs
//!
//! Both are on the challenge, never on the verification state, so neither
//! weakens what the server checks when the signature comes back.
//!
//! 1. **Resident keys are required.** `start_registration` sets
//!    `require_resident_key(false)` (webauthn-rs's own default) and then
//!    overrides it below. A non-discoverable credential cannot be found
//!    without being told the user first, which would put the identifier back
//!    into sign-in and undo the reason for choosing passkeys here.
//! 2. **Conditional mediation is cleared.** `start_authentication` forces
//!    `mediation: conditional` off, which is otherwise the autofill flow and
//!    shows no prompt of its own. A console that signs in from a button needs
//!    the modal instead.

use crate::error::{AuthError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use otto_core::orgs::{OrgsExt, User};
use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::UserId;
use otto_tenant::{Db, Unpinned};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// The wire types a caller needs, re-exported so a web layer talks to this
/// module rather than to webauthn-rs directly. The HTTP layer should not have
/// an opinion about which crate implements the ceremony.
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn,
};
// Not in the prelude; needed to require discoverable credentials.
use webauthn_rs_proto::ResidentKeyRequirement;

/// How long a half-finished ceremony stays redeemable.
///
/// Short on purpose: the window only has to cover a human picking a key and
/// touching a sensor, and a challenge that outlives its ceremony is a challenge
/// somebody can come back to.
const CEREMONY_TTL_SECONDS: i64 = 300;

/// The relying party's name, as both the challenge and the relying party itself
/// report it. One constant so the two cannot disagree — an authenticator that
/// was told one name and shown another has no way to reconcile them.
const RP_NAME: &str = "Otto Platform";

/// A registered authenticator, as the console lists it.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKey {
    pub id: Uuid,
    /// The credential's own id, base64url **unpadded** — the same alphabet the
    /// ceremony speaks, so the console can compare it to what an authenticator
    /// reports without re-encoding either side.
    ///
    /// This is not a secret. It is a public handle the authenticator already
    /// holds and hands to any origin it is asked to sign for; withholding it
    /// protects nothing. It is here because `signalAllAcceptedCredentials`
    /// cannot work without it: a browser matches the surviving credentials by
    /// this id, so a list that omitted it would leave a deleted passkey being
    /// offered in the picker forever. Do not remove it as a tightening.
    pub credential_id: String,
    pub nickname: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A ceremony handed to the browser: the challenge, and the id that lets the
/// server find its own state again.
pub struct Ceremony<T> {
    pub id: Uuid,
    pub challenge: T,
}

/// Build the relying party.
///
/// `rp_id` is a *hostname*, and it is the thing a passkey is bound to. Changing
/// it invalidates every credential ever registered, so it should be derived
/// from the server's public URL and asserted at startup rather than typed
/// twice.
pub fn relying_party(rp_id: &str, rp_origin: &str) -> Result<Webauthn> {
    let origin = Url::parse(rp_origin).map_err(|_| {
        AuthError::Config(format!(
            "{rp_origin:?} is not a URL WebAuthn can use as an origin"
        ))
    })?;

    WebauthnBuilder::new(rp_id, &origin)
        .and_then(|b| b.rp_name(RP_NAME).build())
        .map_err(|e| {
            AuthError::Config(format!(
                "could not build the WebAuthn relying party for rp_id {rp_id:?} \
                 and origin {rp_origin}: {e}. The rp_id must be the origin's host, \
                 or a registrable parent domain of it."
            ))
        })
}

// ---------------------------------------------------------------- registration

/// The pair an authenticator files a credential under: `name` is what a
/// credential manager sorts and searches by, `display_name` is the row a human
/// reads when they are asked to choose.
#[derive(Debug, Clone)]
pub struct CredentialNames {
    pub name: String,
    pub display_name: String,
}

/// Name a credential after the account rather than after the site.
///
/// **One function, and not two `format!`s at the call site**, because a
/// console can send this same pair back through `signalCurrentUserDetails` to
/// repair credentials that were registered before there was anything to name
/// them with. A browser that composed the pair itself would hold a second copy
/// of the prefix and of the email → name → label precedence, in TypeScript,
/// with nothing keeping the two in step.
pub fn credential_names(user: &User) -> CredentialNames {
    CredentialNames {
        // The address when there is one: it is what a manager sorts and
        // searches by, and the label is only ever a stand-in for it.
        name: user
            .email
            .clone()
            .or_else(|| user.name.clone())
            .unwrap_or_else(|| user.label.clone()),
        // The generated words, address or not. Someone who has learned which
        // key is `Otto Platform · brisk-harbor-42` does not lose that the day
        // they fill in a profile — and the vault entry keeps the old words
        // regardless, so a rename here would only make the two disagree.
        display_name: format!("{RP_NAME} · {}", user.label),
    }
}

/// Begin registering a passkey.
///
/// `user` is `None` for a brand-new account: the row is created here, with no
/// address, because the passkey is what brings the account into existence. Pass
/// `Some` to add a second key to an account that already exists — which is the
/// recovery story, and what a console should ask for straight after signup.
pub async fn start_registration(
    db: &Db,
    webauthn: &Webauthn,
    user: Option<UserId>,
) -> Result<Ceremony<CreationChallengeResponse>> {
    // Both arms end at the account's own row, because the names below are a
    // function of it and nothing else — a brand-new account is named by the
    // label its insert just generated, not by a stand-in.
    let account = match user {
        Some(id) => db.get_user(id).await?.ok_or(AuthError::UnknownUser)?,
        None => db.create_unclaimed_user().await?,
    };
    let user_id = account.id;
    let names = credential_names(&account);

    let existing_credentials = credential_ids_for(db, user_id).await?;

    let (mut challenge, state) = webauthn
        .start_passkey_registration(
            user_id.as_uuid(),
            &names.name,
            &names.display_name,
            Some(existing_credentials),
        )
        .map_err(webauthn_failed)?;

    // See the module docs: webauthn-rs leaves resident keys optional, and a
    // non-discoverable credential cannot be used to sign in without naming the
    // account first.
    let selection = challenge
        .public_key
        .authenticator_selection
        .get_or_insert_with(Default::default);
    selection.resident_key = Some(ResidentKeyRequirement::Required);
    selection.require_resident_key = true;
    // Left unset so a security key is as welcome as a platform authenticator —
    // pinning this to Platform is how someone with a YubiKey and no biometrics
    // discovers they cannot register at all.
    selection.authenticator_attachment = None;

    let id = store_ceremony(db, "register", Some(user_id), &state).await?;
    Ok(Ceremony { id, challenge })
}

/// Which flow reached [`finish_registration`]. `Claim` is the takeover-completion
/// event that follows an admin-assisted passkey reset — the one case that
/// needs distinguishing from an ordinary signup or an already-signed-in
/// session adding a second key.
#[derive(Debug, Clone, Copy)]
pub enum RegistrationVia {
    Signup,
    Add,
    Claim,
}

impl RegistrationVia {
    fn as_str(self) -> &'static str {
        match self {
            RegistrationVia::Signup => "signup",
            RegistrationVia::Add => "add",
            RegistrationVia::Claim => "claim",
        }
    }
}

/// Finish registering, and return the account the key now belongs to.
///
/// `via` names which flow drove the ceremony and is written into the audit
/// row's detail rather than left to be inferred later. The claim case is the
/// one that matters most: it is the takeover-completion event that follows an
/// admin-assisted reset, and without `via` it is indistinguishable from an
/// ordinary signup.
///
/// Opens its own transaction and commits immediately — for the ordinary
/// signup and add-a-second-key flows, which have nothing else to fold into
/// the same commit. A claim-completion flow should use
/// [`finish_registration_tx`] directly instead and open its own transaction
/// around it, so its claim-code consumption can share *that* transaction
/// rather than commit separately, before it, with nothing to roll it back if
/// what follows fails.
///
/// `expected` is forwarded to [`finish_registration_tx`], which documents it
/// and the ordering guarantee it establishes. This wrapper additionally
/// writes a best-effort [`action::PASSKEY_REGISTRATION_REFUSED`] audit row on
/// a mismatch, on a connection independent of the rolled-back transaction.
/// A caller that uses [`finish_registration_tx`] directly does not get this
/// for free and is responsible for its own trace of a refused attempt.
// Eight parameters, all load-bearing; a bundling struct would only add a type
// whose job is to be immediately unpacked.
#[allow(clippy::too_many_arguments)]
pub async fn finish_registration(
    db: &Db,
    webauthn: &Webauthn,
    ceremony: Uuid,
    credential: &RegisterPublicKeyCredential,
    nickname: Option<&str>,
    via: RegistrationVia,
    expected: Option<UserId>,
    ip: Option<&str>,
) -> Result<UserId> {
    let mut tx = db.begin_unpinned().await?;
    match finish_registration_tx(
        &mut tx, webauthn, ceremony, credential, nickname, via, expected, ip,
    )
    .await
    {
        Ok(user_id) => {
            tx.commit().await?;
            Ok(user_id)
        }
        Err(AuthError::CeremonyAccountMismatch {
            ceremony_account,
            caller_account,
        }) => {
            // Dropping `tx` uncommitted rolls back the ceremony's own
            // consumption along with everything else. Writing the refusal on `tx` would roll back
            // with the attempt it records, so it goes through
            // `db.audit_global`, which uses a fresh connection.
            drop(tx);
            // Attributed to `ceremony_account`, whose ownership a real
            // signature just backed, rather than `caller_account`, which is
            // only an identity the request's own session asserted. The caller
            // is still named in `detail`.
            let entry = Entry::new(action::PASSKEY_REGISTRATION_REFUSED)
                .actor(ceremony_account)
                .detail(serde_json::json!({ "attemptedBy": caller_account.to_string() }))
                .from_request(ip, None);
            if let Err(e) = db.audit_global(entry).await {
                tracing::error!(
                    error = %e,
                    ceremony_account = %ceremony_account,
                    "failed to write audit event for a refused passkey registration"
                );
            }
            Err(AuthError::CeremonyAccountMismatch {
                ceremony_account,
                caller_account,
            })
        }
        Err(e) => Err(e),
    }
}

/// The connection-taking half of [`finish_registration`], for a caller that
/// must fold another single-use secret's consumption into the same commit —
/// a claim-completion flow runs the account claim's own consumption on this
/// same connection, so a failure anywhere in this function restores the
/// claim rather than having already burned it.
///
/// Does not commit. The caller opens the transaction this runs on and
/// decides when to commit it: [`finish_registration`] commits immediately
/// after; a claim-completion caller commits only once it has also checked
/// that the ceremony's account matches the claim's.
///
/// **The connection must be unpinned** — the same requirement [`clear_tx`]
/// documents for the same reason, and `conn`'s type says so now instead of
/// only a comment asking nicely: this function ends by calling
/// [`Db::audit_global_on`] on it, which takes `&mut Unpinned` specifically
/// and (per its own doc comment) also re-checks at call time that nothing
/// has pinned the transaction to an org since it was opened.
///
/// `expected`, when `Some`, is checked against the ceremony's stored account
/// after signature verification and before anything is written. Verification
/// comes first so that reaching the mismatch path (and the audit row the
/// wrapper writes for it) requires an authenticator to have actually signed
/// the challenge; checking first would let anyone holding a live ceremony id
/// repeat the 403 at request cost with no proof of possession. On a mismatch
/// this returns [`AuthError::CeremonyAccountMismatch`] carrying both accounts.
/// `None` skips the check. A caller that passes `Some(_)` directly to this
/// function is responsible for its own trace of a rejected attempt, since the
/// rollback leaves nothing durable to find one in.
#[allow(clippy::too_many_arguments)]
pub async fn finish_registration_tx(
    conn: &mut Unpinned,
    webauthn: &Webauthn,
    ceremony: Uuid,
    credential: &RegisterPublicKeyCredential,
    nickname: Option<&str>,
    via: RegistrationVia,
    expected: Option<UserId>,
    ip: Option<&str>,
) -> Result<UserId> {
    let (user_id, state): (Option<UserId>, PasskeyRegistration) =
        take_ceremony(conn.conn(), ceremony, "register").await?;
    let user_id = user_id.ok_or(AuthError::CeremonyExpired)?;

    let passkey = webauthn
        .finish_passkey_registration(credential, &state)
        .map_err(webauthn_failed)?;

    if let Some(expected) = expected {
        if user_id != expected {
            return Err(AuthError::CeremonyAccountMismatch {
                ceremony_account: user_id,
                caller_account: expected,
            });
        }
    }

    let credential_id = passkey.cred_id().as_ref().to_vec();
    let encoded = serde_json::to_value(&passkey)
        .map_err(|e| AuthError::Config(format!("could not store a passkey: {e}")))?;

    // The unique index on credential_id is the real guard: an authenticator
    // must not be registrable twice, to two accounts, which is what the
    // exclude-credentials list asks for politely and this enforces.
    sqlx::query(
        "INSERT INTO passkeys (user_id, credential_id, credential, nickname) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&credential_id)
    .bind(&encoded)
    .bind(nickname)
    .execute(conn.conn())
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
            AuthError::CredentialAlreadyRegistered
        }
        _ => AuthError::from(e),
    })?;

    // The credential and its audit row commit together: a live credential
    // with no audit row would be a security-relevant event with no trace,
    // most of all on the `claim` path, which is the one event that proves
    // who actually completed an admin-assisted takeover.
    Db::audit_global_on(
        conn,
        Entry::new(action::PASSKEY_REGISTERED)
            .actor(user_id)
            .detail(serde_json::json!({ "via": via.as_str() }))
            .from_request(ip, None),
    )
    .await?;

    Ok(user_id)
}

// -------------------------------------------------------------- authentication

/// Begin signing in. Takes no identifier — that is the point.
pub async fn start_authentication(
    db: &Db,
    webauthn: &Webauthn,
) -> Result<Ceremony<RequestChallengeResponse>> {
    let (mut challenge, state) = webauthn
        .start_discoverable_authentication()
        .map_err(webauthn_failed)?;

    // See the module docs: a console should sign in from a button, not from
    // an autofill hint on a text field.
    challenge.mediation = None;

    let id = store_ceremony(db, "authenticate", None, &state).await?;
    Ok(Ceremony { id, challenge })
}

/// Finish signing in.
///
/// The browser hands back a credential carrying the user handle it was
/// registered with, which is how an account is found without one being typed.
/// That handle is a claim, not proof — the signature checked below is the
/// proof, and it is checked against the key stored for that account.
pub async fn finish_authentication(
    db: &Db,
    webauthn: &Webauthn,
    ceremony: Uuid,
    credential: &PublicKeyCredential,
    ip: Option<&str>,
) -> Result<UserId> {
    let (_, state): (Option<UserId>, DiscoverableAuthentication) =
        take_ceremony(db.pool(), ceremony, "authenticate").await?;

    // Resolve the account from the **credential ID**, not the user handle.
    //
    // webauthn-rs offers `identify_discoverable_authentication`, which reads the
    // user handle the authenticator returns. That works, but it trusts the one
    // field an authenticator is allowed to omit — and several do, including
    // every software authenticator available to test with. The credential ID is
    // always present, it is what the unique index is on, and looking the account
    // up by it is strictly more robust.
    //
    // It is not a weaker check. Neither field is evidence of anything: both are
    // claims the client makes about *which* account to check against, and the
    // signature verified below is what makes the answer true.
    let credential_id = credential.raw_id.as_ref();

    let owner: Option<UserId> =
        sqlx::query_scalar("SELECT user_id FROM passkeys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(db.pool())
            .await?;

    let Some(user_id) = owner else {
        // An unknown credential, and the one sign-in failure this server names.
        //
        // Nothing to attribute an audit row to, so `note_failure` is not called
        // here — otherwise any id a stranger posted would write a row.
        //
        // Naming it is not the enumeration leak the rest of this module avoids.
        // A credential ID is unguessable bytes minted by an authenticator and is
        // never disclosed cross-origin, so the only caller who can ask this
        // question is one already holding the answer's subject. And it resolves
        // no account: the lookup above asks `passkeys` alone, no `users` row is
        // read on this path, and there is no address or org anywhere in the
        // answer. That ordering is the load-bearing half of the argument — the
        // entropy is why the question is hard to ask, but the ordering is why
        // the answer says nothing.
        return Err(AuthError::UnknownCredential);
    };

    // Only this account's keys. Passing every key in the database would
    // authenticate whoever the signature happened to match, which is a
    // different and much worse function.
    let stored: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT credential FROM passkeys WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db.pool())
            .await?;

    let keys: Vec<DiscoverableKey> = stored
        .into_iter()
        .filter_map(|raw| match serde_json::from_value::<Passkey>(raw) {
            Ok(passkey) => Some(passkey),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_id = %user_id,
                    "stored passkey credential failed to deserialize; skipping it"
                );
                None
            }
        })
        .map(|p| DiscoverableKey::from(&p))
        .collect();

    if keys.is_empty() {
        note_failure(db, user_id, ip).await;
        return Err(AuthError::InvalidCredentials);
    }

    let result = match webauthn.finish_discoverable_authentication(credential, state, &keys) {
        Ok(result) => result,
        Err(_) => {
            note_failure(db, user_id, ip).await;
            return Err(AuthError::InvalidCredentials);
        }
    };

    // A counter that has not moved forward is the documented signal of a cloned
    // authenticator. Most passkeys report zero and never move, which is normal
    // and not what this is looking for — a *decrease* from a nonzero counter is.
    if result.needs_update() {
        update_stored_credential(db, user_id, credential_id, &result).await?;
    }

    sqlx::query(
        "UPDATE passkeys SET last_used_at = now() \
         WHERE user_id = $1 AND credential_id = $2",
    )
    .bind(user_id)
    .bind(credential_id)
    .execute(db.pool())
    .await?;

    Ok(user_id)
}

// ------------------------------------------------------------------ management

/// One row of the key list, before it becomes a [`RegisteredKey`].
///
/// A named struct rather than a tuple, and matched by **column name**. This was
/// a four-element tuple decoded by position, which was survivable; adding
/// `credential_id` made it five, with a bare `Vec<u8>` sitting between an id and
/// two timestamps. At that width, inserting a column into the `SELECT` below or
/// swapping two type-compatible neighbours would compile cleanly and file every
/// key's data one field over — and nothing about that is visible until a browser
/// is comparing credential ids that never match.
#[derive(sqlx::FromRow)]
struct KeyRow {
    id: Uuid,
    credential_id: Vec<u8>,
    nickname: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn list(db: &Db, user: UserId) -> Result<Vec<RegisteredKey>> {
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT id, credential_id, nickname, created_at, last_used_at FROM passkeys \
             WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user)
    .fetch_all(db.pool())
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| RegisteredKey {
            id: row.id,
            credential_id: URL_SAFE_NO_PAD.encode(row.credential_id),
            nickname: row.nickname,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        })
        .collect())
}

pub async fn count(db: &Db, user: UserId) -> Result<i64> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys WHERE user_id = $1")
        .bind(user)
        .fetch_one(db.pool())
        .await?;
    Ok(n)
}

/// Whether this account can be signed into at all.
pub async fn has_credential(db: &Db, user: UserId) -> Result<bool> {
    Ok(count(db, user).await? > 0)
}

/// Remove a key, refusing to remove the last one.
///
/// **The refusal is the feature.** Deleting your only passkey locks you out of
/// your own account with no email to recover through, and the click that does
/// it looks exactly like tidying up a stale device. Someone who genuinely wants
/// out deletes the account.
///
/// Opens its own transaction and commits immediately: the delete and its
/// `auth.passkey.removed` audit row commit together, so a failure on either
/// leaves the account untouched instead of a destroyed credential with no
/// audit row.
///
/// No `_tx` split here (unlike `finish_registration`/`finish_registration_tx`):
/// nothing else needs to fold another statement into this same commit, so a
/// speculative second entry point would be unused indirection. Add one if a
/// caller actually needs it.
pub async fn remove(db: &Db, user: UserId, key: Uuid, ip: Option<&str>) -> Result<()> {
    let mut tx = db.begin_unpinned().await?;

    // `FOR UPDATE` rather than `count(*)`: an aggregate takes no row locks, so
    // two concurrent `remove` calls naming different keys on a two-key
    // account could each read `remaining == 2`, each pass the guard, and both
    // commit — leaving zero passkeys, the exact permanent lockout this check
    // exists to prevent on a product with no email recovery. Locking the rows
    // forces the second transaction to block here until the first commits or
    // rolls back, then re-evaluate against what it left behind — the same
    // pattern `otto_core::orgs::OrgsTxExt::count_owners_for_update` already
    // uses for the structurally identical last-owner invariant. An aggregate
    // cannot ride `FOR UPDATE`, hence selecting ids and counting in Rust.
    let remaining: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM passkeys WHERE user_id = $1 ORDER BY id FOR UPDATE")
            .bind(user)
            .fetch_all(tx.conn())
            .await?;
    if remaining.len() <= 1 {
        return Err(AuthError::LastPasskey);
    }

    let affected = sqlx::query("DELETE FROM passkeys WHERE user_id = $1 AND id = $2")
        .bind(user)
        .bind(key)
        .execute(tx.conn())
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AuthError::UnknownCredential);
    }

    // The delete and its audit row commit together: a destroyed credential
    // with no audit row is at least as attacker-interesting as a created one
    // with no audit row — arguably more, since this is the step that evicts
    // a legitimate owner after a session takeover.
    Db::audit_global_on(
        &mut tx,
        Entry::new(action::PASSKEY_REMOVED)
            .actor(user)
            .target("passkey", key.to_string())
            .from_request(ip, None),
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Rename a key's nickname. Cosmetic — unlike [`remove`] and [`clear`], there
/// is no destructive statement here for the audit write to be atomic with, so
/// it stays best-effort on the pool: a lost `auth.passkey.renamed` row loses a
/// label, not evidence of a credential change.
pub async fn rename(
    db: &Db,
    user: UserId,
    key: Uuid,
    nickname: &str,
    ip: Option<&str>,
) -> Result<()> {
    let affected = sqlx::query("UPDATE passkeys SET nickname = $3 WHERE user_id = $1 AND id = $2")
        .bind(user)
        .bind(key)
        .bind(nickname.trim())
        .execute(db.pool())
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AuthError::UnknownCredential);
    }

    if let Err(e) = db
        .audit_global(
            Entry::new(action::PASSKEY_RENAMED)
                .actor(user)
                .target("passkey", key.to_string())
                .from_request(ip, None),
        )
        .await
    {
        tracing::error!(
            error = %e,
            user_id = %user,
            "failed to write audit event for passkey rename"
        );
    }

    Ok(())
}

/// Clear every passkey on an account. The admin-assisted half of recovery.
///
/// Leaves the account with no way in **by design** — the caller must issue a
/// claim code, or the account becomes claimable by whoever reaches registration
/// first. An admin-assisted reset flow should run this, the session
/// revocation, and the claim-code insert in one transaction via [`clear_tx`],
/// so a failure partway through cannot leave the account cleared with no way
/// back in.
///
/// The audit row is attributed to `actor`, not `user`: `actor` is whoever
/// initiated the clear (an admin for an assisted reset today, or the account
/// holder themselves for a hypothetical self-service caller — this
/// function's own tests exercise `actor == user`), and `user` is the account
/// being cleared. Recording both, rather than collapsing to one field, is
/// what keeps an admin-initiated clear from misattributing to the person it
/// happened to when the two differ.
///
/// The delete and its `auth.passkey.cleared` audit row commit together, the
/// same reasoning as [`remove`] above and `finish_registration`: an
/// admin-assisted-reset row is the one that names who initiated a takeover,
/// and it must not be losable independently of the delete it records.
///
/// **Warning for any caller:** this function has no last-passkey guard
/// (unlike [`remove`]) and mints no claim code. Calling it directly wipes
/// every credential on the account with no way back in — a permanent,
/// unrecoverable lockout on a product with no email recovery. Any caller
/// must mint a claim code (or an equivalent re-entry mechanism) in the
/// *same transaction* as the wipe, via [`clear_tx`] rather than this
/// function, unless it genuinely means to leave the account unreachable.
pub async fn clear(db: &Db, user: UserId, actor: UserId, ip: Option<&str>) -> Result<u64> {
    let mut tx = db.begin_unpinned().await?;
    let removed = clear_tx(tx.conn(), user).await?;

    Db::audit_global_on(
        &mut tx,
        Entry::new(action::PASSKEY_CLEARED)
            .actor(actor)
            .target("user", user.to_string())
            .from_request(ip, None),
    )
    .await?;

    tx.commit().await?;
    Ok(removed)
}

/// The delete half of [`clear`], against a connection the caller already holds
/// a transaction on.
///
/// No audit row here: the row [`clear`] writes is global (no org), and an
/// admin-assisted reset flow — the other caller of this function — typically
/// runs it on a transaction pinned to one org, where an insert with a null
/// `org_id` would violate `audit_events`'s row-level-security policy.
/// [`clear`] writes its own global row on the `Unpinned` connection it opens
/// itself, before its own commit; an org-pinned caller should instead record
/// its own org-scoped audit row via `Tx::audit`.
pub async fn clear_tx(conn: &mut sqlx::PgConnection, user: UserId) -> Result<u64> {
    let removed = sqlx::query("DELETE FROM passkeys WHERE user_id = $1")
        .bind(user)
        .execute(conn)
        .await?
        .rows_affected();
    Ok(removed)
}

/// Delete ceremonies nobody came back for.
pub async fn sweep(db: &Db) -> Result<u64> {
    let n = sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at < now()")
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok(n)
}

// ---------------------------------------------------------------------- internals

async fn credential_ids_for(db: &Db, user: UserId) -> Result<Vec<CredentialID>> {
    let rows: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE user_id = $1")
            .bind(user)
            .fetch_all(db.pool())
            .await?;
    Ok(rows.into_iter().map(CredentialID::from).collect())
}

async fn store_ceremony<T: serde::Serialize>(
    db: &Db,
    kind: &str,
    user: Option<UserId>,
    state: &T,
) -> Result<Uuid> {
    let encoded = serde_json::to_value(state)
        .map_err(|e| AuthError::Config(format!("could not store a ceremony: {e}")))?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO webauthn_ceremonies (kind, user_id, state, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(secs => $4)) RETURNING id",
    )
    .bind(kind)
    .bind(user)
    .bind(&encoded)
    .bind(CEREMONY_TTL_SECONDS as f64)
    .fetch_one(db.pool())
    .await?;

    Ok(id)
}

/// Consume a ceremony: read it and delete it in one statement.
///
/// `DELETE … RETURNING` rather than select-then-delete, so two requests racing
/// the same challenge cannot both succeed. The `kind` predicate is part of the
/// same statement for the same reason — a registration state must never be
/// finishable as an authentication, and checking that after the fact would
/// leave a window where it could.
///
/// Generic over the executor — `db.pool()` for [`finish_authentication`],
/// which has nothing else to fold into a transaction, or a connection
/// reborrowed from a caller-owned transaction for
/// [`finish_registration_tx`], so a failure later in that same transaction
/// restores the ceremony instead of leaving it burned for nothing. Mirrors
/// `otto_tenant::audit::Entry::write`'s identical generic-executor shape.
async fn take_ceremony<'e, T, E>(conn: E, id: Uuid, kind: &str) -> Result<(Option<UserId>, T)>
where
    T: serde::de::DeserializeOwned,
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(Option<UserId>, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM webauthn_ceremonies \
         WHERE id = $1 AND kind = $2 AND expires_at > now() \
         RETURNING user_id, state",
    )
    .bind(id)
    .bind(kind)
    .fetch_optional(conn)
    .await?;

    let (user, state) = row.ok_or(AuthError::CeremonyExpired)?;
    let state = serde_json::from_value(state)
        .map_err(|e| AuthError::Config(format!("could not read a ceremony: {e}")))?;
    Ok((user, state))
}

async fn update_stored_credential(
    db: &Db,
    user: UserId,
    credential_id: &[u8],
    result: &AuthenticationResult,
) -> Result<()> {
    let raw: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT credential FROM passkeys WHERE user_id = $1 AND credential_id = $2",
    )
    .bind(user)
    .bind(credential_id)
    .fetch_optional(db.pool())
    .await?;

    let Some(raw) = raw else { return Ok(()) };
    let mut passkey = match serde_json::from_value::<Passkey>(raw) {
        Ok(passkey) => passkey,
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user,
                "stored passkey credential failed to deserialize during a sign-counter update; skipping it"
            );
            return Ok(());
        }
    };

    if passkey.update_credential(result).is_some() {
        if let Ok(encoded) = serde_json::to_value(&passkey) {
            sqlx::query(
                "UPDATE passkeys SET credential = $3 \
                 WHERE user_id = $1 AND credential_id = $2",
            )
            .bind(user)
            .bind(credential_id)
            .bind(&encoded)
            .execute(db.pool())
            .await?;
        }
    }
    Ok(())
}

async fn note_failure(db: &Db, user: UserId, ip: Option<&str>) {
    let entry = Entry::new(action::LOGIN_FAILED)
        .actor(user)
        .from_request(ip, None)
        .detail(serde_json::json!({ "method": "passkey" }));
    if let Err(e) = db.audit_global(entry).await {
        tracing::error!(error = %e, "failed to write audit event for a sign-in attempt");
    }
}

/// Every WebAuthn failure becomes one opaque answer.
///
/// The library's errors are specific and useful in a log — "the origin did not
/// match", "user verification was not performed" — and handing that specificity
/// to the caller tells an attacker which part of their forgery to fix next.
fn webauthn_failed(e: WebauthnError) -> AuthError {
    tracing::warn!(error = %e, "webauthn ceremony failed");
    AuthError::InvalidCredentials
}
