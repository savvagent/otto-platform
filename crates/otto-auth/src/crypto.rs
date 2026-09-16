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
/// link nor a recovery code — see `otto-tenant`'s auth migration docs for why
/// those otto-factory-era credential kinds are not part of this baseline.
pub mod prefix {
    pub const ACCESS: &str = "otto_at_";
    pub const REFRESH: &str = "otto_rt_";
    pub const AUTH_CODE: &str = "otto_ac_";
    pub const SESSION: &str = "otto_ss_";
    pub const PAT: &str = "otto_pat_";
    pub const INVITE: &str = "otto_inv_";
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
        assert!(!verify(&hash("otto_pat_wrong"), &s.hash));
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
}
