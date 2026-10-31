//! Token generation and hashing.
//!
//! Nothing here invents a scheme. Random bytes from the OS, SHA-256 from
//! RustCrypto, constant-time comparison from `subtle`. The only decisions worth
//! documenting are *which* primitive applies where, and those are below.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Bytes of entropy in every generated credential.
///
/// 256 bits. These are bearer credentials with no rate limit on offline
/// guessing if a hash ever leaks, so there is no reason to be clever or frugal.
const TOKEN_BYTES: usize = 32;

/// Prefixes make a leaked credential identifiable on sight — in a log, a
/// bug report, or a secret scanner. Distinct per kind so an access token
/// pasted where a PAT belongs fails loudly rather than subtly.
///
/// No `MAGIC`/`RECOVERY` prefixes here: otto-platform issues neither a magic
/// link nor a recovery code — see `savvagent-tenant`'s auth migration docs for why
/// those otto-factory-era credential kinds are not part of this baseline.
pub mod prefix {
    pub const ACCESS: &str = "sav_at_";
    pub const REFRESH: &str = "sav_rt_";
    pub const AUTH_CODE: &str = "sav_ac_";
    pub const SESSION: &str = "sav_ss_";
    pub const PAT: &str = "sav_pat_";
    pub const INVITE: &str = "sav_inv_";
    /// Enterprise OIDC federation (`sso_ceremonies.state_hash`) — see
    /// otto-factory's `docs/specs/2026-09-16-oidc-federation-design.md` §5.
    pub const SSO_STATE: &str = "sav_sst_";
    /// The `__Host-savvagent_sso_binding` cookie value (`sso_ceremonies.binding_hash`).
    pub const SSO_BINDING: &str = "sav_ssb_";
    /// A client id handed out by dynamic client registration. An id, not a
    /// secret: it is stored in plaintext, and the hash [`super::generate`]
    /// computes alongside it goes unused.
    pub const CLIENT_ID: &str = "sav_client_";
}

/// Prefixes of the sign-in credentials minted before the switch to Savvagent
/// (savvagent/otto-platform#128): access, refresh, authorization code,
/// session and personal access token.
///
/// #128 is a hard switch: every sign-in credential minted under the old
/// prefixes stops working at the deploy, and users sign in again. Their rows
/// are stored by hash only, so nothing in the database tells an old token
/// from a new one; the presented prefix is the only place the line can be
/// drawn. Deliberately absent, because they keep working until phase 3
/// rotates them per service: `otto_client_` ids, `otto_rs_` introspection and
/// `otto_whsec_` webhook secrets, `otto_inv_` invite and claim codes (the
/// cutover's passkey recovery redeems one minted before the deploy), and the
/// `otto_sst_`/`otto_ssb_` values of an SSO ceremony in flight across it.
const RETIRED_SIGN_IN: [&str; 5] = ["otto_at_", "otto_rt_", "otto_ac_", "otto_ss_", "otto_pat_"];

/// Whether `presented` is a sign-in credential retired by the switch to
/// Savvagent (`RETIRED_SIGN_IN`), ignoring surrounding whitespace as the
/// lookups do.
///
/// Each place that looks a sign-in credential up by its presented value
/// checks this first and, for a retired one, answers exactly as it does for
/// an unknown value without touching the database: introspection of an
/// access token or PAT ([`crate::tokens::introspect`]), the refresh grant
/// ([`crate::tokens::redeem_refresh`]), code redemption
/// ([`crate::oauth::redeem_code`]), session resolution
/// ([`crate::sessions::resolve`]), and the two revocations, RFC 7009
/// ([`crate::tokens::revoke_presented`]) and logout
/// ([`crate::sessions::revoke`]), which succeed silently and revoke nothing.
/// A retired credential is thereby indistinguishable from one that never
/// existed, even if a row still carries its hash.
pub fn is_retired_sign_in(presented: &str) -> bool {
    let presented = presented.trim();
    RETIRED_SIGN_IN.iter().any(|p| presented.starts_with(p))
}

/// A freshly minted credential: the plaintext to hand out **once**, and the
/// hash to store.
///
/// Deliberately not `Clone` and deliberately without a `Display`/`Debug` that
/// reveals the plaintext, so a credential cannot end up in a log line by
/// accident.
pub struct Secret {
    plaintext: String,
    pub hash: Vec<u8>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl Secret {
    /// Consume the wrapper to get the plaintext. Consuming rather than
    /// borrowing forces the caller to decide, once, where it goes.
    pub fn into_plaintext(self) -> String {
        self.plaintext
    }

    pub fn expose(&self) -> &str {
        &self.plaintext
    }
}

/// Mint a new credential with the given prefix.
pub fn generate(prefix: &str) -> Secret {
    let mut buf = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    let plaintext = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(buf));
    let hash = hash(&plaintext);
    Secret { plaintext, hash }
}

/// A plain random string with no prefix and no matching hash — for the OIDC
/// `nonce` (`sso_ceremonies.nonce`), which is not a bearer credential: it is
/// sent to the IdP as a plaintext query parameter and stored in plaintext,
/// its only job anti-replay on the returned `id_token`. Deliberately not
/// [`generate`] — a prefixed, `sav_ss...`-shaped value handed to a third-party
/// IdP as `nonce` would be a strange thing for that IdP to log back, and
/// there is no hash to keep in step with a [`Secret`] here in the first
/// place.
pub fn generate_nonce() -> String {
    let mut buf = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Hash a credential for storage.
///
/// **SHA-256, not Argon2 — on purpose.** Password hashes are slow to resist
/// brute force against low-entropy human input. These are 256-bit random
/// strings: there is nothing to brute-force, and a slow hash would only add
/// latency to every authenticated request, which is a denial-of-service vector
/// rather than a defense. Argon2 belongs on passwords, and otto-platform has
/// none.
pub fn hash(token: &str) -> Vec<u8> {
    hash_bytes(token.as_bytes())
}

/// Hash arbitrary bytes for use as a rate-limit bucket key — a WebAuthn
/// credential id, say, which is not text and must not be decoded as any.
///
/// Same algorithm as [`hash`] and the same justification: these are
/// high-entropy bytes minted by an authenticator, not a guessable secret, so
/// there is nothing for a slow hash to protect against.
pub fn hash_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Constant-time comparison. Used wherever a comparison result could otherwise
/// leak a secret one byte at a time through timing.
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_prefixed_and_unique() {
        let a = generate(prefix::ACCESS);
        let b = generate(prefix::ACCESS);
        assert!(a.expose().starts_with(prefix::ACCESS));
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn hash_is_stable_and_verifies() {
        let s = generate(prefix::PAT);
        assert_eq!(hash(s.expose()), s.hash);
        assert!(verify(&hash(s.expose()), &s.hash));
        assert!(!verify(&hash("sav_pat_wrong"), &s.hash));
    }

    /// The plaintext must never reach a log through `Debug`, which is how
    /// credentials most often escape.
    #[test]
    fn debug_does_not_leak_the_plaintext() {
        let s = generate(prefix::SESSION);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains(s.expose()), "Debug leaked the token");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn sso_prefixes_are_distinct_and_sav_scoped() {
        let state = generate(prefix::SSO_STATE);
        let binding = generate(prefix::SSO_BINDING);
        assert!(state.expose().starts_with("sav_sst_"));
        assert!(binding.expose().starts_with("sav_ssb_"));
        assert_ne!(state.hash, binding.hash);
    }

    /// Savvagent (#128): every kind minted here carries its `sav_` prefix.
    #[test]
    fn every_minted_kind_carries_its_sav_prefix() {
        for (prefix, expected) in [
            (prefix::ACCESS, "sav_at_"),
            (prefix::REFRESH, "sav_rt_"),
            (prefix::AUTH_CODE, "sav_ac_"),
            (prefix::SESSION, "sav_ss_"),
            (prefix::PAT, "sav_pat_"),
            (prefix::INVITE, "sav_inv_"),
            (prefix::SSO_STATE, "sav_sst_"),
            (prefix::SSO_BINDING, "sav_ssb_"),
            (prefix::CLIENT_ID, "sav_client_"),
        ] {
            assert_eq!(prefix, expected);
            let minted = generate(prefix);
            assert!(minted.expose().starts_with(expected), "{prefix}");
            assert!(
                !is_retired_sign_in(minted.expose()),
                "{prefix} is minted retired"
            );
        }
    }

    /// The five sign-in kinds minted before the switch are retired, padded or
    /// not; the kinds that keep working until phase 3 are not.
    #[test]
    fn only_old_sign_in_prefixes_are_retired() {
        let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for old in ["otto_at_", "otto_rt_", "otto_ac_", "otto_ss_", "otto_pat_"] {
            assert!(is_retired_sign_in(&format!("{old}{body}")), "{old}");
            assert!(
                is_retired_sign_in(&format!("  {old}{body}\n")),
                "{old} padded"
            );
        }
        for kept in [
            "otto_client_",
            "otto_rs_",
            "otto_whsec_",
            "otto_inv_",
            "otto_sst_",
            "otto_ssb_",
            "sav_at_",
            "sav_rt_",
            "sav_ac_",
            "sav_ss_",
            "sav_pat_",
            "",
        ] {
            assert!(!is_retired_sign_in(&format!("{kept}{body}")), "{kept}");
        }
    }

    /// The nonce is sent to a third-party IdP in the clear, so it must carry
    /// none of this crate's credential prefixes, and must never repeat.
    #[test]
    fn nonce_is_unprefixed_url_safe_and_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
        assert!(!a.starts_with("sav_") && !a.starts_with("otto_"));
        assert_eq!(a.len(), 43, "32 bytes, base64url without padding");
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}
