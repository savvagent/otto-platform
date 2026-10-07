//! Secret encryption.
//!
//! Nothing here invents a scheme. AES-256-GCM from RustCrypto, keyed by
//! `OTTO_ENCRYPTION_KEY`, is the single recoverable-secret primitive this
//! workspace shares.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;

use crate::error::{Error, Result};

/// Authenticated encryption for secrets that must be *recoverable* rather than
/// merely verifiable — IdP client secrets, tracker webhook/refresh secrets.
/// Everything else is hashed, not encrypted.
///
/// The key comes from `OTTO_ENCRYPTION_KEY` in the environment (or KMS) and never
/// from the database, so a database dump alone yields no usable secret.
#[derive(Clone)]
pub struct Cipher {
    inner: Aes256Gcm,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(<key redacted>)")
    }
}

/// Ciphertext plus the nonce it was sealed under. Storage-agnostic on
/// purpose: a caller is free to persist the two fields separately or combine
/// them into one column — otto-factory's tracker tables does the latter, encoding
/// `nonce || ciphertext` as base64 into a single TEXT column, because the new
/// tracker tables have no reason to carry a second column for a 12-byte value.
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Cipher {
    /// Build from a base64 32-byte key. Accepts standard or URL-safe base64,
    /// because operators paste whatever `openssl rand -base64 32` produced.
    pub fn from_base64_key(encoded: &str) -> Result<Self> {
        let raw = B64
            .decode(encoded.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.trim()))
            .map_err(|_| Error::Config("OTTO_ENCRYPTION_KEY is not valid base64".into()))?;

        if raw.len() != 32 {
            return Err(Error::Config(format!(
                "OTTO_ENCRYPTION_KEY must decode to 32 bytes, got {}",
                raw.len()
            )));
        }

        let key = Key::<Aes256Gcm>::from_slice(&raw);
        Ok(Self {
            inner: Aes256Gcm::new(key),
        })
    }

    /// Seal a secret. A fresh random 96-bit nonce every time — reusing a nonce
    /// under GCM is catastrophic, so it is never derived from anything and
    /// never reused across calls.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .inner
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::Crypto("failed to seal secret".into()))?;

        Ok(Sealed {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    pub fn open(&self, sealed: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(Error::Crypto("stored nonce has the wrong length".into()));
        }
        self.inner
            .decrypt(Nonce::from_slice(nonce), sealed)
            .map_err(|_| {
                Error::Crypto("failed to open secret — wrong key or tampered ciphertext".into())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_round_trip() {
        let key = B64.encode([7u8; 32]);
        let c = Cipher::from_base64_key(&key).unwrap();
        let sealed = c.seal(b"totp-shared-secret").unwrap();
        assert_ne!(sealed.ciphertext, b"totp-shared-secret");
        assert_eq!(
            c.open(&sealed.ciphertext, &sealed.nonce).unwrap(),
            b"totp-shared-secret"
        );
    }

    /// GCM nonces must never repeat under one key.
    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let key = B64.encode([7u8; 32]);
        let c = Cipher::from_base64_key(&key).unwrap();
        let a = c.seal(b"same plaintext").unwrap();
        let b = c.seal(b"same plaintext").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce reused across seals");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = B64.encode([7u8; 32]);
        let c = Cipher::from_base64_key(&key).unwrap();
        let mut sealed = c.seal(b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(c.open(&sealed.ciphertext, &sealed.nonce).is_err());
    }

    #[test]
    fn wrong_key_cannot_open() {
        let a = Cipher::from_base64_key(&B64.encode([1u8; 32])).unwrap();
        let b = Cipher::from_base64_key(&B64.encode([2u8; 32])).unwrap();
        let sealed = a.seal(b"secret").unwrap();
        assert!(b.open(&sealed.ciphertext, &sealed.nonce).is_err());
    }

    #[test]
    fn key_must_be_32_bytes() {
        assert!(Cipher::from_base64_key(&B64.encode([0u8; 16])).is_err());
        assert!(Cipher::from_base64_key("not base64!!").is_err());
    }
}
