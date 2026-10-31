//! Binds a consent form to the request it was rendered for.
//!
//! The consent page round-trips the authorization request in hidden fields,
//! and `authorize_decision` re-validates them. Re-validation proves that the
//! request is *legal*, not that it is the one the person *saw*: a form edited
//! to ask for `things:read things:write` after the page showed `things:read`
//! re-validates fine. The seal closes that gap. It carries what the server
//! resolved at render time (client, the redirect URI `validate_authorize`
//! accepted, each resolved resource URI with its resolved scopes, in order,
//! the signed-in user, the PKCE `code_challenge` and its method, the client's
//! `state`, and an expiry). A request for one resource seals a list of one. The POST must match it, field for field, before any
//! branch, `deny` included.
//!
//! **The key.** The seal is AES-256-GCM under a subkey dedicated to it,
//! derived from `SAVVAGENT_ENCRYPTION_KEY` with [`Cipher::derive`] and
//! [`KEY_LABEL`]. The AEAD is used for authentication: a value that opens
//! under the subkey was produced by this server for this purpose and has not
//! been altered. A separate key means a seal can never be opened as a secret
//! at rest or the other way round, and rendering consent pages does not
//! spend the at-rest key's nonce budget. Deriving it needs no new secret or
//! setting. The plaintext is nothing secret (it is the page's own request),
//! a fresh random nonce is drawn for every seal, and the 10-minute expiry
//! bounds replay to the same client, user, resource, redirect URI, PKCE
//! challenge and `state`, which grants nothing that page did not already
//! offer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use savvagent_tenant::crypto::Cipher;
use savvagent_tenant::ids::UserId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The label the seal's subkey is derived under (see [`Cipher::derive`]).
/// Changing it invalidates every page currently open.
pub(crate) const KEY_LABEL: &str = "otto-web/consent-request-seal";
/// The seal's format version. Bump it on any change to [`RequestSeal`].
pub(crate) const SEAL_VERSION: u8 = 3;
/// How long a rendered consent page stays submittable.
pub(crate) const SEAL_TTL_SECONDS: i64 = 600;
const NONCE_LEN: usize = 12;
/// Longest encoded seal accepted. A real one is a few hundred characters per
/// resource, and a request names at most
/// [`savvagent_auth::oauth::MAX_RESOURCES_PER_REQUEST`]; the cap keeps a forged
/// multi-megabyte field from reaching the decoder at all.
const MAX_ENCODED_LEN: usize = 16 * 1024;

/// What the consent page was rendered for.
///
/// `code_challenge` and `state` are client-supplied and have no upper length
/// limit at `/oauth/authorize` (a `state` can be a JWT). Carrying them verbatim
/// would let a long one push the seal past [`MAX_ENCODED_LEN`], and its consent
/// page could never be submitted. They are only ever compared, never read
/// back, so the seal holds a fixed-size SHA-256 digest of each instead (see
/// [`digest`]), which keeps its size bounded whatever the client sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RequestSeal {
    pub(crate) v: u8,
    pub(crate) client_id: String,
    /// The exact string `validate_authorize` accepted.
    pub(crate) redirect_uri: String,
    /// One entry per resource the page offered, in page order.
    pub(crate) grants: Vec<SealedGrant>,
    pub(crate) user_id: UserId,
    /// Digest of the PKCE challenge the code will be bound to.
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String,
    /// Digest of the client's `state`, with a blank one read as absent (see
    /// [`normalize_state`]).
    pub(crate) state: Option<String>,
    /// Unix seconds.
    pub(crate) exp: i64,
}

/// One resource a page offered, and the scopes it offered for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedGrant {
    /// The resolved RFC 8707 resource URI, not the client's raw parameter.
    pub(crate) resource: String,
    /// `Authorization::scopes`: what the client requested, or the resource
    /// server's defaults when it requested nothing.
    pub(crate) scopes: Vec<String>,
}

/// A resolved, validated request: what a page is sealed for, and what a
/// consent POST must match.
#[derive(Debug, Clone)]
pub(crate) struct Expected<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) redirect_uri: &'a str,
    /// `(resource, scopes)` for each resource, in page order.
    pub(crate) grants: Vec<(&'a str, &'a [String])>,
    pub(crate) user_id: UserId,
    pub(crate) code_challenge: &'a str,
    pub(crate) code_challenge_method: &'a str,
    pub(crate) state: Option<&'a str>,
}

/// A blank `state` is the same as none. The page renders an absent `state` as
/// an empty hidden field, and the POST reads an empty field as absent, so a
/// request that arrived with `state=` must seal the same way it comes back.
fn normalize_state(state: Option<&str>) -> Option<&str> {
    state.filter(|s| !s.trim().is_empty())
}

/// `URL_SAFE_NO_PAD(sha256(value))`: what the seal stores in place of a
/// client-supplied value of unbounded length.
fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealError {
    Missing,
    Malformed,
    Expired,
    /// Names the first field that differs. For the log only: the page says
    /// nothing about which field it was.
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
            SealError::Mismatch(_) => f.write_str(
                "the consent form does not match the request it was shown for; \
                 start again from the app",
            ),
        }
    }
}

impl RequestSeal {
    pub(crate) fn new(request: &Expected<'_>, now: DateTime<Utc>) -> Self {
        Self {
            v: SEAL_VERSION,
            client_id: request.client_id.to_string(),
            redirect_uri: request.redirect_uri.to_string(),
            grants: request
                .grants
                .iter()
                .map(|(resource, scopes)| SealedGrant {
                    resource: resource.to_string(),
                    scopes: scopes.to_vec(),
                })
                .collect(),
            user_id: request.user_id,
            code_challenge: digest(request.code_challenge),
            code_challenge_method: request.code_challenge_method.to_string(),
            state: normalize_state(request.state).map(digest),
            exp: now.timestamp() + SEAL_TTL_SECONDS,
        }
    }

    /// `URL_SAFE_NO_PAD(nonce || ciphertext)`, ready for a hidden field.
    pub(crate) fn seal(&self, cipher: &Cipher) -> savvagent_tenant::Result<String> {
        let plaintext = serde_json::to_vec(self)
            .map_err(|e| savvagent_tenant::Error::Crypto(format!("encode request seal: {e}")))?;
        let sealed = cipher.seal(&plaintext)?;
        let mut out = sealed.nonce;
        out.extend_from_slice(&sealed.ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    /// Every failure to decode, authenticate or parse is `Malformed`. Which
    /// one it was is no business of whoever forged it.
    pub(crate) fn open(cipher: &Cipher, encoded: &str) -> Result<Self, SealError> {
        if encoded.len() > MAX_ENCODED_LEN {
            return Err(SealError::Malformed);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
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
        if self.grants.len() != expected.grants.len()
            || self
                .grants
                .iter()
                .zip(&expected.grants)
                .any(|(sealed, (resource, _))| sealed.resource != *resource)
        {
            return Err(SealError::Mismatch("resource"));
        }
        if self.user_id != expected.user_id {
            return Err(SealError::Mismatch("user_id"));
        }
        if self
            .grants
            .iter()
            .zip(&expected.grants)
            .any(|(sealed, (_, scopes))| as_set(&sealed.scopes) != as_set(scopes))
        {
            return Err(SealError::Mismatch("scopes"));
        }
        if self.code_challenge != digest(expected.code_challenge) {
            return Err(SealError::Mismatch("code_challenge"));
        }
        if self.code_challenge_method != expected.code_challenge_method {
            return Err(SealError::Mismatch("code_challenge_method"));
        }
        if self.state != normalize_state(expected.state).map(digest) {
            return Err(SealError::Mismatch("state"));
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
    use savvagent_tenant::ids::UserId;

    fn cipher(byte: u8) -> Cipher {
        Cipher::from_base64_key(&URL_SAFE_NO_PAD.encode([byte; 32])).unwrap()
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
            RequestSeal::new(&self.expected(), now)
        }
        fn expected(&self) -> Expected<'_> {
            Expected {
                client_id: "sav_client_a",
                redirect_uri: "http://127.0.0.1:1455/callback",
                grants: vec![("https://things.otto.test/mcp", &self.scopes[..])],
                user_id: self.user,
                code_challenge: CHALLENGE,
                code_challenge_method: "S256",
                state: Some("opaque-state"),
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
        let huge = "A".repeat(MAX_ENCODED_LEN + 1);
        for garbage in ["AAAA", "not base64!", long.as_str(), huge.as_str()] {
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
        // Expired at the deadline itself, not a second after it.
        let at_deadline = now - chrono::Duration::seconds(SEAL_TTL_SECONDS);
        let sealed = f.seal_at(at_deadline).seal(&c).unwrap();
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
                    client_id: "sav_client_b",
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
                    grants: vec![("https://widgets.otto.test/mcp", &f.scopes[..])],
                    ..f.expected()
                },
            ),
            (
                "resource",
                Expected {
                    grants: vec![
                        ("https://things.otto.test/mcp", &f.scopes[..]),
                        ("https://widgets.otto.test/mcp", &f.scopes[..]),
                    ],
                    ..f.expected()
                },
            ),
            (
                "resource",
                Expected {
                    grants: vec![],
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
                    grants: vec![("https://things.otto.test/mcp", &wider[..])],
                    ..f.expected()
                },
            ),
            (
                "scopes",
                Expected {
                    grants: vec![("https://things.otto.test/mcp", &narrower[..])],
                    ..f.expected()
                },
            ),
            (
                "code_challenge",
                Expected {
                    code_challenge: "attackers-own-challenge-attackers-own-challenge",
                    ..f.expected()
                },
            ),
            (
                "code_challenge_method",
                Expected {
                    code_challenge_method: "plain",
                    ..f.expected()
                },
            ),
            (
                "state",
                Expected {
                    state: Some("another-state"),
                    ..f.expected()
                },
            ),
            (
                "state",
                Expected {
                    state: None,
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

    /// A page rendered for `state=` comes back with the field empty, which
    /// the POST reads as no state at all. Both are "no state".
    #[test]
    fn a_blank_state_is_the_same_as_none() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        for rendered in [None, Some(""), Some("  ")] {
            let sealed = RequestSeal::new(
                &Expected {
                    state: rendered,
                    ..f.expected()
                },
                now,
            )
            .seal(&c)
            .unwrap();
            for submitted in [None, Some("")] {
                check(
                    &c,
                    Some(&sealed),
                    &Expected {
                        state: submitted,
                        ..f.expected()
                    },
                    now,
                )
                .unwrap_or_else(|e| panic!("{rendered:?} -> {submitted:?}: {e:?}"));
            }
        }
    }

    /// The page never names the field that differed; the log does.
    #[test]
    fn a_mismatch_reads_the_same_whichever_field_it_was() {
        let shown: std::collections::BTreeSet<String> =
            ["client_id", "scopes", "state", "code_challenge"]
                .into_iter()
                .map(|field| SealError::Mismatch(field).to_string())
                .collect();
        assert_eq!(shown.len(), 1, "{shown:?}");
        let text = shown.into_iter().next().unwrap();
        for field in ["client_id", "scopes", "state", "code_challenge"] {
            assert!(!text.contains(field), "{text}");
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
                grants: vec![("https://things.otto.test/mcp", &reordered[..])],
                ..f.expected()
            },
            now,
        )
        .unwrap();
    }

    /// `state` and `code_challenge` have no upper length limit at
    /// `/oauth/authorize`, so the seal holds digests of them: a client with a
    /// JWT-sized `state` must still get a page whose form can be submitted.
    #[test]
    fn a_long_state_and_challenge_still_fit_in_a_submittable_seal() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let state = "s".repeat(8 * 1024);
        let challenge = "c".repeat(8 * 1024);
        let expected = Expected {
            state: Some(&state),
            code_challenge: &challenge,
            ..f.expected()
        };
        let sealed = RequestSeal::new(&expected, now).seal(&c).unwrap();
        assert!(
            sealed.len() <= MAX_ENCODED_LEN,
            "{} > {MAX_ENCODED_LEN}",
            sealed.len()
        );
        check(&c, Some(&sealed), &expected, now).unwrap();
        let other = "s".repeat(8 * 1024 - 1) + "t";
        assert_eq!(
            check(
                &c,
                Some(&sealed),
                &Expected {
                    state: Some(&other),
                    ..expected.clone()
                },
                now
            ),
            Err(SealError::Mismatch("state"))
        );
        let other = "c".repeat(8 * 1024 - 1) + "d";
        assert_eq!(
            check(
                &c,
                Some(&sealed),
                &Expected {
                    code_challenge: &other,
                    ..expected.clone()
                },
                now
            ),
            Err(SealError::Mismatch("code_challenge"))
        );
    }

    /// Several resources: each keeps its own scopes, and the order is bound.
    #[test]
    fn several_resources_bind_each_ones_scopes_and_their_order() {
        let f = Fixture::new();
        let c = cipher(7);
        let now = Utc::now();
        let widgets = scopes(&["widgets:read"]);
        let expected = Expected {
            grants: vec![
                ("https://things.otto.test/mcp", &f.scopes[..]),
                ("https://widgets.otto.test/mcp", &widgets[..]),
            ],
            ..f.expected()
        };
        let sealed = RequestSeal::new(&expected, now).seal(&c).unwrap();
        check(&c, Some(&sealed), &expected, now).unwrap();
        // The scopes moved to the other resource.
        let swapped = Expected {
            grants: vec![
                ("https://things.otto.test/mcp", &widgets[..]),
                ("https://widgets.otto.test/mcp", &f.scopes[..]),
            ],
            ..expected.clone()
        };
        assert_eq!(
            check(&c, Some(&sealed), &swapped, now),
            Err(SealError::Mismatch("scopes"))
        );
        let reordered = Expected {
            grants: vec![
                ("https://widgets.otto.test/mcp", &widgets[..]),
                ("https://things.otto.test/mcp", &f.scopes[..]),
            ],
            ..expected.clone()
        };
        assert_eq!(
            check(&c, Some(&sealed), &reordered, now),
            Err(SealError::Mismatch("resource"))
        );
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
