//! Binds a consent form to the request it was rendered for.
//!
//! The consent page round-trips the authorization request in hidden fields,
//! and `authorize_decision` re-validates them. Re-validation proves that the
//! request is *legal*, not that it is the one the person *saw*: a form edited
//! to ask for `things:read things:write` after the page showed `things:read`
//! re-validates fine. The seal closes that gap. It carries what the server
//! resolved at render time (client, the redirect URI `validate_authorize`
//! accepted, the resolved resource URI, the signed-in user, the resolved
//! scopes and an expiry). The POST must match it, field for field, before
//! any branch, `deny` included.
//!
//! **Why the at-rest key is reused.** [`Cipher`] is AES-256-GCM, keyed by
//! `OTTO_ENCRYPTION_KEY`, and it exists to keep secrets at rest. Here the same
//! AEAD is used for what it also provides, which is authentication: a value
//! that opens under the key was produced by this server and has not been
//! altered. The plaintext is nothing secret (it is the page's own request), a
//! fresh random nonce is drawn for every seal, and the 10-minute expiry
//! bounds replay to the same client, user, resource and redirect URI, which
//! grants nothing that page did not already offer. No new key, crate or
//! table.

#![cfg_attr(not(test), allow(dead_code))] // Wired in by authorize_decision; removed once used.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use otto_tenant::crypto::Cipher;
use otto_tenant::ids::UserId;
use serde::{Deserialize, Serialize};

/// The seal's format version. Bump it on any change to [`RequestSeal`].
pub(crate) const SEAL_VERSION: u8 = 1;
/// How long a rendered consent page stays submittable.
pub(crate) const SEAL_TTL_SECONDS: i64 = 600;
const NONCE_LEN: usize = 12;

/// What the consent page was rendered for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RequestSeal {
    pub(crate) v: u8,
    pub(crate) client_id: String,
    /// The exact string `validate_authorize` accepted.
    pub(crate) redirect_uri: String,
    /// The resolved RFC 8707 resource URI, not the client's raw parameter.
    pub(crate) resource: String,
    pub(crate) user_id: UserId,
    /// `Authorization::scopes`: what the client requested, or the resource
    /// server's defaults when it requested nothing.
    pub(crate) scopes: Vec<String>,
    /// Unix seconds.
    pub(crate) exp: i64,
}

/// What a consent POST resolved to, which the seal must match.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expected<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) redirect_uri: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) user_id: UserId,
    pub(crate) scopes: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealError {
    Missing,
    Malformed,
    Expired,
    /// Names the first field that differs.
    Mismatch(&'static str),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Missing => f.write_str(
                "the consent form is missing its request seal; start again from the app",
            ),
            SealError::Malformed => f.write_str(
                "the consent form's request seal is not valid; start again from the app",
            ),
            SealError::Expired => f.write_str("this page has expired; start again from the app"),
            SealError::Mismatch(field) => write!(
                f,
                "the consent form does not match the request it was shown for ({field}); \
                 start again from the app"
            ),
        }
    }
}

impl RequestSeal {
    pub(crate) fn new(
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        user_id: UserId,
        scopes: &[String],
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            v: SEAL_VERSION,
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            resource: resource.to_string(),
            user_id,
            scopes: scopes.to_vec(),
            exp: now.timestamp() + SEAL_TTL_SECONDS,
        }
    }

    /// `URL_SAFE_NO_PAD(nonce || ciphertext)`, ready for a hidden field.
    pub(crate) fn seal(&self, cipher: &Cipher) -> otto_tenant::Result<String> {
        let plaintext = serde_json::to_vec(self)
            .map_err(|e| otto_tenant::Error::Crypto(format!("encode request seal: {e}")))?;
        let sealed = cipher.seal(&plaintext)?;
        let mut out = sealed.nonce;
        out.extend_from_slice(&sealed.ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    /// Every failure to decode, authenticate or parse is `Malformed`. Which
    /// one it was is no business of whoever forged it.
    pub(crate) fn open(cipher: &Cipher, encoded: &str) -> Result<Self, SealError> {
        let raw = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| SealError::Malformed)?;
        if raw.len() <= NONCE_LEN {
            return Err(SealError::Malformed);
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let plaintext = cipher
            .open(ciphertext, nonce)
            .map_err(|_| SealError::Malformed)?;
        let seal: Self = serde_json::from_slice(&plaintext).map_err(|_| SealError::Malformed)?;
        if seal.v != SEAL_VERSION {
            return Err(SealError::Malformed);
        }
        Ok(seal)
    }

    pub(crate) fn verify(
        &self,
        expected: &Expected<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), SealError> {
        if now.timestamp() >= self.exp {
            return Err(SealError::Expired);
        }
        if self.client_id != expected.client_id {
            return Err(SealError::Mismatch("client_id"));
        }
        if self.redirect_uri != expected.redirect_uri {
            return Err(SealError::Mismatch("redirect_uri"));
        }
        if self.resource != expected.resource {
            return Err(SealError::Mismatch("resource"));
        }
        if self.user_id != expected.user_id {
            return Err(SealError::Mismatch("user_id"));
        }
        if as_set(&self.scopes) != as_set(expected.scopes) {
            return Err(SealError::Mismatch("scopes"));
        }
        Ok(())
    }
}

fn as_set(scopes: &[String]) -> std::collections::BTreeSet<&str> {
    scopes.iter().map(String::as_str).collect()
}

/// Open `presented` and verify it against what the POST resolved to.
pub(crate) fn check(
    cipher: &Cipher,
    presented: Option<&str>,
    expected: &Expected<'_>,
    now: DateTime<Utc>,
) -> Result<(), SealError> {
    let presented = presented
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(SealError::Missing)?;
    RequestSeal::open(cipher, presented)?.verify(expected, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use otto_tenant::ids::UserId;

    fn cipher(byte: u8) -> Cipher {
        Cipher::from_base64_key(&URL_SAFE_NO_PAD.encode([byte; 32])).unwrap()
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    struct Fixture {
        user: UserId,
        scopes: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                user: UserId::new(),
                scopes: scopes(&["things:read", "things:write"]),
            }
        }
        fn seal_at(&self, now: DateTime<Utc>) -> RequestSeal {
            RequestSeal::new(
                "otto_client_a",
                "http://127.0.0.1:1455/callback",
                "https://things.otto.test/mcp",
                self.user,
                &self.scopes,
                now,
            )
        }
        fn expected(&self) -> Expected<'_> {
            Expected {
                client_id: "otto_client_a",
                redirect_uri: "http://127.0.0.1:1455/callback",
                resource: "https://things.otto.test/mcp",
                user_id: self.user,
                scopes: &self.scopes,
            }
        }
    }

    #[test]
    fn a_seal_round_trips_and_verifies() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let sealed = f.seal_at(now).seal(&c).unwrap();
        assert!(!sealed.is_empty());
        assert!(
            sealed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "URL-safe base64 without padding, so it survives a form field: {sealed}"
        );
        let opened = RequestSeal::open(&c, &sealed).unwrap();
        assert_eq!(opened, f.seal_at(now));
        check(&c, Some(&sealed), &f.expected(), now).unwrap();
    }

    #[test]
    fn two_seals_of_the_same_request_differ() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        assert_ne!(
            f.seal_at(now).seal(&c).unwrap(),
            f.seal_at(now).seal(&c).unwrap()
        );
    }

    #[test]
    fn a_single_flipped_byte_is_refused() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let mut raw = URL_SAFE_NO_PAD
            .decode(f.seal_at(now).seal(&c).unwrap())
            .unwrap();
        for i in [0, 12, raw.len() - 1] {
            raw[i] ^= 0x01;
            let tampered = URL_SAFE_NO_PAD.encode(&raw);
            assert_eq!(
                check(&c, Some(&tampered), &f.expected(), now),
                Err(SealError::Malformed),
                "byte {i}"
            );
            raw[i] ^= 0x01;
        }
    }

    #[test]
    fn garbage_missing_and_foreign_keys_are_refused() {
        let f = Fixture::new();
        let now = Utc::now();
        assert_eq!(
            check(&cipher(7), None, &f.expected(), now),
            Err(SealError::Missing)
        );
        assert_eq!(
            check(&cipher(7), Some("  "), &f.expected(), now),
            Err(SealError::Missing)
        );
        let long = "A".repeat(400);
        for garbage in ["AAAA", "not base64!", long.as_str()] {
            assert_eq!(
                check(&cipher(7), Some(garbage), &f.expected(), now),
                Err(SealError::Malformed),
                "{garbage:?}"
            );
        }
        let sealed_elsewhere = f.seal_at(now).seal(&cipher(8)).unwrap();
        assert_eq!(
            check(&cipher(7), Some(&sealed_elsewhere), &f.expected(), now),
            Err(SealError::Malformed),
            "a seal from another key must not open"
        );
    }

    /// A page rendered more than the TTL ago is refused, and one rendered just
    /// inside the TTL is not. Tested here because an integration test cannot
    /// reach this crate-private helper to mint an old seal.
    #[test]
    fn an_expired_seal_is_refused() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let rendered = now - chrono::Duration::seconds(SEAL_TTL_SECONDS + 1);
        let sealed = f.seal_at(rendered).seal(&c).unwrap();
        assert_eq!(
            check(&c, Some(&sealed), &f.expected(), now),
            Err(SealError::Expired)
        );
        // Still fine one second before the deadline.
        let fresh = now - chrono::Duration::seconds(SEAL_TTL_SECONDS - 1);
        let sealed = f.seal_at(fresh).seal(&c).unwrap();
        check(&c, Some(&sealed), &f.expected(), now).unwrap();
    }

    #[test]
    fn every_bound_field_must_match() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let sealed = f.seal_at(now).seal(&c).unwrap();
        let other_user = UserId::new();
        let wider = scopes(&["things:read", "things:write", "org:admin"]);
        let narrower = scopes(&["things:read"]);

        let cases: Vec<(&str, Expected<'_>)> = vec![
            (
                "client_id",
                Expected {
                    client_id: "otto_client_b",
                    ..f.expected()
                },
            ),
            (
                "redirect_uri",
                Expected {
                    redirect_uri: "http://127.0.0.1:1455/other",
                    ..f.expected()
                },
            ),
            (
                "resource",
                Expected {
                    resource: "https://widgets.otto.test/mcp",
                    ..f.expected()
                },
            ),
            (
                "user_id",
                Expected {
                    user_id: other_user,
                    ..f.expected()
                },
            ),
            (
                "scopes",
                Expected {
                    scopes: &wider,
                    ..f.expected()
                },
            ),
            (
                "scopes",
                Expected {
                    scopes: &narrower,
                    ..f.expected()
                },
            ),
        ];
        for (field, expected) in cases {
            assert_eq!(
                check(&c, Some(&sealed), &expected, now),
                Err(SealError::Mismatch(field)),
                "{field}"
            );
        }
    }

    #[test]
    fn scopes_compare_as_a_set() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let sealed = f.seal_at(now).seal(&c).unwrap();
        let reordered = scopes(&["things:write", "things:read", "things:read"]);
        check(
            &c,
            Some(&sealed),
            &Expected {
                scopes: &reordered,
                ..f.expected()
            },
            now,
        )
        .unwrap();
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let mut future = f.seal_at(now);
        future.v = SEAL_VERSION + 1;
        let sealed = future.seal(&c).unwrap();
        assert_eq!(
            check(&c, Some(&sealed), &f.expected(), now),
            Err(SealError::Malformed)
        );
    }
}
