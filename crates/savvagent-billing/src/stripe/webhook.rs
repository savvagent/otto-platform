//! Stripe webhook signature verification.
//!
//! Stripe signs each delivery with a `Stripe-Signature` header:
//!
//! ```text
//! Stripe-Signature: t=1492774577,v1=5257a869e7...,v1=...,v0=...
//! ```
//!
//! Each `v1` is the lowercase hex HMAC-SHA256, keyed by the endpoint's signing
//! secret, of `"{t}.{payload}"` over the raw request body. During a secret
//! rotation there are several `v1` values; any one matching is enough. Other
//! schemes (`v0`) are ignored.
//!
//! ```
//! use savvagent_billing::stripe::{sign_webhook, verify_webhook_at, WebhookSecret};
//!
//! let secret = WebhookSecret::new("whsec_test").unwrap();
//! let body = br#"{"id":"evt_1","type":"setup_intent.succeeded","created":1760000000,
//!     "data":{"object":{"id":"seti_1"}}}"#;
//! let header = sign_webhook(&secret, 1_760_000_000, body);
//!
//! let event = verify_webhook_at(&secret, &header, body, 1_760_000_100).unwrap();
//! assert_eq!(event.event_type, "setup_intent.succeeded");
//! assert_eq!(event.data.object["id"], "seti_1");
//! ```

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use super::secret::WebhookSecret;

/// The HTTP header carrying the signature.
pub const SIGNATURE_HEADER: &str = "Stripe-Signature";

/// How far the signed timestamp may be from the receiver's clock, either way.
pub const TOLERANCE_SECS: i64 = 300;

/// The most `v1` signatures examined; later ones are ignored. A rotation needs
/// two, and an attacker-supplied header must not buy unbounded HMAC work.
pub const MAX_SIGNATURES: usize = 8;

/// The longest `Stripe-Signature` header accepted.
pub const MAX_SIGNATURE_HEADER_BYTES: usize = 4096;

/// The largest payload [`verify_webhook_at`] will HMAC or parse. Checked
/// first, before any other work. This bounds the work done here only: the
/// HTTP layer receiving the webhook must also cap the request body (at this
/// size or less), or it buffers an unbounded body before this check runs.
pub const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// A verified Stripe event. `data.object` is left as JSON: its shape depends
/// on `type`, and the handler for each type decodes what it needs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WebhookEvent {
    /// `evt_...`, stable across redeliveries. Dedupe on this.
    pub id: String,
    /// e.g. `checkout.session.completed`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Unix seconds.
    pub created: i64,
    pub data: EventData,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct EventData {
    pub object: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebhookError {
    #[error("malformed {SIGNATURE_HEADER} header: {0}")]
    MalformedHeader(&'static str),
    #[error("no {SIGNATURE_HEADER} v1 signature matches")]
    BadSignature,
    #[error("{SIGNATURE_HEADER} timestamp is {age_secs}s from now, outside the {TOLERANCE_SECS}s tolerance")]
    Stale { age_secs: i64 },
    #[error("webhook payload is not a Stripe event: {0}")]
    InvalidPayload(String),
    #[error("webhook payload exceeds {MAX_WEBHOOK_PAYLOAD_BYTES} bytes")]
    PayloadTooLarge,
}

/// An HMAC over `"{t}.{payload}"`, not yet finalized.
fn keyed(secret: &WebhookSecret, t: i64, payload: &[u8]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret.expose().as_bytes())
        .expect("HMAC accepts any key length");
    m.update(t.to_string().as_bytes());
    m.update(b".");
    m.update(payload);
    m
}

/// A `Stripe-Signature` header for `payload` signed at `t`, as Stripe would
/// send it. For tests and local tooling.
pub fn sign_webhook(secret: &WebhookSecret, t: i64, payload: &[u8]) -> String {
    let tag = keyed(secret, t, payload).finalize().into_bytes();
    format!("t={t},v1={}", to_hex(&tag))
}

/// Verify a delivery against the current time and parse its envelope.
///
/// `payload` must be the raw request body, byte for byte.
pub fn verify_webhook(
    secret: &WebhookSecret,
    header: &str,
    payload: &[u8],
) -> Result<WebhookEvent, WebhookError> {
    verify_webhook_at(secret, header, payload, Utc::now().timestamp())
}

/// As [`verify_webhook`], with an explicit clock (Unix seconds).
///
/// The MAC is checked before the timestamp, so an unauthenticated caller
/// learns nothing about the clock. Comparison is constant-time. A payload over
/// [`MAX_WEBHOOK_PAYLOAD_BYTES`] is refused before anything else; the HTTP
/// layer must cap the request body as well.
pub fn verify_webhook_at(
    secret: &WebhookSecret,
    header: &str,
    payload: &[u8],
    now: i64,
) -> Result<WebhookEvent, WebhookError> {
    if payload.len() > MAX_WEBHOOK_PAYLOAD_BYTES {
        return Err(WebhookError::PayloadTooLarge);
    }
    if header.len() > MAX_SIGNATURE_HEADER_BYTES {
        return Err(WebhookError::MalformedHeader("too long"));
    }
    let mut t: Option<i64> = None;
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            return Err(WebhookError::MalformedHeader("element without '='"));
        };
        match k {
            "t" => {
                if t.is_some() {
                    return Err(WebhookError::MalformedHeader("more than one t"));
                }
                t = Some(
                    v.parse()
                        .map_err(|_| WebhookError::MalformedHeader("t is not an integer"))?,
                );
            }
            "v1" => {
                let sig =
                    from_hex(v).ok_or(WebhookError::MalformedHeader("v1 is not 64 hex digits"))?;
                if candidates.len() < MAX_SIGNATURES {
                    candidates.push(sig);
                }
            }
            _ => {}
        }
    }
    let t = t.ok_or(WebhookError::MalformedHeader("missing t"))?;
    if candidates.is_empty() {
        return Err(WebhookError::MalformedHeader("no v1 signature"));
    }

    // `verify_slice` is constant-time. Every candidate is checked, so timing
    // does not reveal which one matched.
    let matched = candidates.iter().fold(false, |acc, sig| {
        keyed(secret, t, payload).verify_slice(sig).is_ok() | acc
    });
    if !matched {
        return Err(WebhookError::BadSignature);
    }
    let age_secs = now.saturating_sub(t);
    if age_secs.unsigned_abs() > TOLERANCE_SECS.unsigned_abs() {
        return Err(WebhookError::Stale { age_secs });
    }
    serde_json::from_slice(payload).map_err(|e| WebhookError::InvalidPayload(e.to_string()))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0xf)] as char);
    }
    s
}

/// Decode exactly 32 bytes of lowercase or uppercase hex.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Some((nib(*hi)? << 4) | nib(*lo)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;
    const BODY: &[u8] = br#"{"id":"evt_123","object":"event","type":"checkout.session.completed","created":1759999990,"livemode":false,"data":{"object":{"id":"cs_1","object":"checkout.session","metadata":{"org_id":"o1"}}}}"#;

    fn secret() -> WebhookSecret {
        WebhookSecret::new("whsec_test_secret").unwrap()
    }

    fn sig(t: i64, body: &[u8]) -> String {
        sign_webhook(&secret(), t, body)
            .split_once(",v1=")
            .unwrap()
            .1
            .to_owned()
    }

    /// A known-answer vector computed independently (Python `hmac`), so the
    /// signing helper is not only checked against itself.
    #[test]
    fn known_answer() {
        let s = WebhookSecret::new("whsec_test_secret").unwrap();
        assert_eq!(
            sign_webhook(&s, 1_700_000_000, b"{}"),
            "t=1700000000,v1=ceb8863f7208fa249a6cd8f951e993c7563412aca65866f6272283debe143ab3"
        );
    }

    #[test]
    fn valid() {
        let header = sign_webhook(&secret(), NOW - 10, BODY);
        let ev = verify_webhook_at(&secret(), &header, BODY, NOW).unwrap();
        assert_eq!(ev.id, "evt_123");
        assert_eq!(ev.event_type, "checkout.session.completed");
        assert_eq!(ev.created, 1_759_999_990);
        assert_eq!(ev.data.object["metadata"]["org_id"], "o1");
    }

    #[test]
    fn valid_with_spaces_and_other_schemes() {
        let header = format!("t={} , v0=deadbeef, v1={}", NOW, sig(NOW, BODY));
        assert!(verify_webhook_at(&secret(), &header, BODY, NOW).is_ok());
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let header = format!("t={NOW},v1={}", sig(NOW, BODY).to_uppercase());
        assert!(verify_webhook_at(&secret(), &header, BODY, NOW).is_ok());
    }

    #[test]
    fn bad_signature() {
        let other = WebhookSecret::new("whsec_other").unwrap();
        let header = sign_webhook(&other, NOW, BODY);
        assert_eq!(
            verify_webhook_at(&secret(), &header, BODY, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn tampered_payload() {
        let header = sign_webhook(&secret(), NOW, BODY);
        let mut body = BODY.to_vec();
        body[10] ^= 1;
        assert_eq!(
            verify_webhook_at(&secret(), &header, &body, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn tampered_timestamp() {
        let header = format!("t={},v1={}", NOW + 1, sig(NOW, BODY));
        assert_eq!(
            verify_webhook_at(&secret(), &header, BODY, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn stale_past_and_future() {
        let old = sign_webhook(&secret(), NOW - 301, BODY);
        assert_eq!(
            verify_webhook_at(&secret(), &old, BODY, NOW),
            Err(WebhookError::Stale { age_secs: 301 })
        );
        let future = sign_webhook(&secret(), NOW + 301, BODY);
        assert_eq!(
            verify_webhook_at(&secret(), &future, BODY, NOW),
            Err(WebhookError::Stale { age_secs: -301 })
        );
        // The edges are inside the tolerance.
        for t in [NOW - 300, NOW + 300] {
            let h = sign_webhook(&secret(), t, BODY);
            assert!(verify_webhook_at(&secret(), &h, BODY, NOW).is_ok());
        }
    }

    #[test]
    fn stale_is_reported_only_after_the_mac() {
        let other = WebhookSecret::new("whsec_other").unwrap();
        let header = sign_webhook(&other, NOW - 10_000, BODY);
        assert_eq!(
            verify_webhook_at(&secret(), &header, BODY, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn multiple_v1_any_one_matches() {
        let bad = "0".repeat(64);
        let good = sig(NOW, BODY);
        for header in [
            format!("t={NOW},v1={bad},v1={good}"),
            format!("t={NOW},v1={good},v1={bad}"),
            format!("t={NOW},v1={bad},v1={bad},v1={good}"),
        ] {
            assert!(
                verify_webhook_at(&secret(), &header, BODY, NOW).is_ok(),
                "{header}"
            );
        }
        let header = format!("t={NOW},v1={bad},v1={bad}");
        assert_eq!(
            verify_webhook_at(&secret(), &header, BODY, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn signatures_past_the_cap_are_ignored() {
        let bad = "0".repeat(64);
        let mut header = format!("t={NOW}");
        for _ in 0..MAX_SIGNATURES {
            header.push_str(&format!(",v1={bad}"));
        }
        header.push_str(&format!(",v1={}", sig(NOW, BODY)));
        assert_eq!(
            verify_webhook_at(&secret(), &header, BODY, NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn malformed_headers() {
        let good = sig(NOW, BODY);
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "element without '='"),
            ("garbage".into(), "element without '='"),
            (format!("v1={good}"), "missing t"),
            (format!("t=,v1={good}"), "t is not an integer"),
            (format!("t=abc,v1={good}"), "t is not an integer"),
            (format!("t={NOW},t={NOW},v1={good}"), "more than one t"),
            (format!("t={NOW}"), "no v1 signature"),
            (format!("t={NOW},v0={good}"), "no v1 signature"),
            (format!("t={NOW},v1=zz"), "v1 is not 64 hex digits"),
            (
                format!("t={NOW},v1={}", "g".repeat(64)),
                "v1 is not 64 hex digits",
            ),
            (format!("t={NOW},v1={good},"), "element without '='"),
            (
                format!(
                    "t={NOW},v1={good},x={}",
                    "a".repeat(MAX_SIGNATURE_HEADER_BYTES)
                ),
                "too long",
            ),
        ];
        for (header, why) in cases {
            assert_eq!(
                verify_webhook_at(&secret(), &header, BODY, NOW),
                Err(WebhookError::MalformedHeader(why)),
                "{header}"
            );
        }
    }

    #[test]
    fn signed_but_not_an_event() {
        for body in [
            &b"not json"[..],
            br#"{"id":"evt_1"}"#,
            br#"{"id":"evt_1","type":"x","created":1,"data":{}}"#,
        ] {
            let header = sign_webhook(&secret(), NOW, body);
            assert!(matches!(
                verify_webhook_at(&secret(), &header, body, NOW),
                Err(WebhookError::InvalidPayload(_))
            ));
        }
    }

    #[test]
    fn payload_size_cap() {
        // A validly signed event padded to exactly the cap is accepted...
        let pad = |n: usize| {
            let head = br#"{"id":"evt_1","type":"x","created":1,"data":{"object":{}},"pad":""#;
            let tail = br#""}"#;
            let mut b = head.to_vec();
            b.resize(n - tail.len(), b'x');
            b.extend_from_slice(tail);
            b
        };
        let at = pad(MAX_WEBHOOK_PAYLOAD_BYTES);
        let header = sign_webhook(&secret(), NOW, &at);
        assert!(verify_webhook_at(&secret(), &header, &at, NOW).is_ok());
        // ...and one byte more is refused, even with a valid signature.
        let over = pad(MAX_WEBHOOK_PAYLOAD_BYTES + 1);
        let header = sign_webhook(&secret(), NOW, &over);
        assert_eq!(
            verify_webhook_at(&secret(), &header, &over, NOW),
            Err(WebhookError::PayloadTooLarge)
        );
        // Checked first: a malformed header does not change the answer.
        assert_eq!(
            verify_webhook_at(&secret(), "garbage", &over, NOW),
            Err(WebhookError::PayloadTooLarge)
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes: Vec<u8> = (0..32).map(|i| i * 8 + 3).collect();
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes));
    }
}
