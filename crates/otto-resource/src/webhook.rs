//! Lifecycle webhooks: signing, verification, and the typed event payloads.
//!
//! The platform POSTs one JSON body per event to the `webhook_url` registered
//! for the resource server, with an `Otto-Signature` header:
//!
//! ```text
//! Otto-Signature: t=1760000000,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd
//! ```
//!
//! `v1` is the lowercase hex HMAC-SHA256, keyed by the resource server's
//! webhook signing secret, of `"{t}.{body}"`, where `t` is the Unix time the
//! delivery attempt was signed at and `body` is the raw request body. Binding
//! the timestamp into the MAC lets [`verify`] reject a captured request that
//! is replayed later. Every retry is signed afresh, but carries the same
//! event `id`, so a receiver that has to be exactly-once dedupes on that.
//!
//! Deliveries are at-least-once and not ordered across events. Handlers must
//! be idempotent: deleting an org's rows twice is the same as once.
//!
//! ```
//! use otto_resource::webhook::{self, LifecycleEvent};
//!
//! let secret = "otto_whsec_example";
//! let body = br#"{"id":"6f1c0f0e-3b1a-4c55-9a53-0d5a9b2f7d11","type":"org.deleted",
//!     "created_at":"2026-10-07T12:00:00Z",
//!     "data":{"org_id":"0b0f3b7e-6a5e-4d4e-8f55-1f2b5d0c9a10"}}"#;
//! let header = webhook::sign(secret, 1_760_000_000, body);
//!
//! let event = webhook::verify_at(secret, &header, body, 1_760_000_030, webhook::DEFAULT_TOLERANCE_SECS)
//!     .unwrap();
//! assert!(matches!(event.event, LifecycleEvent::OrgDeleted { .. }));
//! ```

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

/// The HTTP header carrying the signature.
pub const SIGNATURE_HEADER: &str = "Otto-Signature";

/// How far a signature's timestamp may differ from the receiver's clock.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// The most `v1` signatures [`verify_at`] looks at; later ones are ignored.
pub const MAX_SIGNATURES: usize = 4;

type HmacSha256 = Hmac<Sha256>;

/// What happened. `#[non_exhaustive]`, with [`Self::Unknown`] for event types
/// a newer platform adds: acknowledge those with a 2xx rather than failing the
/// delivery, which would only make the platform retry it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    /// The org was deleted. Remove everything keyed by it.
    OrgDeleted { org_id: Uuid },
    /// A team was deleted. Remove or reassign what was scoped to it.
    TeamDeleted { org_id: Uuid, team_id: Uuid },
    /// A user left (or was removed from) an org.
    MemberRemoved { org_id: Uuid, user_id: Uuid },
    /// An event type this crate version does not know.
    Unknown { kind: String },
}

/// A verified webhook delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEvent {
    /// Stable across retries of the same event. Dedupe on this.
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub event: LifecycleEvent,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebhookError {
    #[error("missing or malformed {SIGNATURE_HEADER} header")]
    MalformedHeader,
    #[error("signature does not match")]
    BadSignature,
    #[error("signature timestamp is outside the allowed tolerance")]
    Stale,
    #[error("webhook body is not a valid event: {0}")]
    BadBody(String),
}

/// The `Otto-Signature` header value for `body`, signed at `timestamp`.
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let tag = keyed(secret, timestamp, body).finalize().into_bytes();
    format!("t={timestamp},v1={}", hex::encode(tag))
}

/// An HMAC over `"{timestamp}.{body}"`, not yet finalized.
fn keyed(secret: &str, timestamp: i64, body: &[u8]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    m.update(timestamp.to_string().as_bytes());
    m.update(b".");
    m.update(body);
    m
}

/// Verify a delivery against the current time and
/// [`DEFAULT_TOLERANCE_SECS`], and parse it.
///
/// `body` must be the raw request bytes, exactly as received: re-serializing
/// parsed JSON changes the bytes and breaks the signature.
pub fn verify(secret: &str, header: &str, body: &[u8]) -> Result<WebhookEvent, WebhookError> {
    verify_at(
        secret,
        header,
        body,
        Utc::now().timestamp(),
        DEFAULT_TOLERANCE_SECS,
    )
}

/// As [`verify`], with an explicit clock and tolerance.
///
/// The header may carry several `v1` values (during a secret rotation); any
/// one matching is enough. Comparison is constant-time.
pub fn verify_at(
    secret: &str,
    header: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<WebhookEvent, WebhookError> {
    let mut timestamp: Option<i64> = None;
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => timestamp = v.parse().ok(),
            // Capped: a rotation needs two, and an attacker-supplied header
            // must not buy unbounded HMAC work.
            Some(("v1", v)) if candidates.len() < MAX_SIGNATURES => {
                if let Ok(bytes) = hex::decode(v) {
                    candidates.push(bytes);
                }
            }
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or(WebhookError::MalformedHeader)?;
    if candidates.is_empty() {
        return Err(WebhookError::MalformedHeader);
    }

    let matched = candidates
        .iter()
        .any(|sig| keyed(secret, timestamp, body).verify_slice(sig).is_ok());
    if !matched {
        return Err(WebhookError::BadSignature);
    }
    // After the MAC check, so an unauthenticated caller learns nothing about
    // the clock from the error.
    if (now - timestamp).abs() > tolerance_secs {
        return Err(WebhookError::Stale);
    }
    parse(body)
}

#[derive(Deserialize)]
struct Envelope {
    id: Uuid,
    #[serde(rename = "type")]
    kind: String,
    created_at: DateTime<Utc>,
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct OrgData {
    org_id: Uuid,
}
#[derive(Deserialize)]
struct TeamData {
    org_id: Uuid,
    team_id: Uuid,
}
#[derive(Deserialize)]
struct MemberData {
    org_id: Uuid,
    user_id: Uuid,
}

/// Parse a webhook body without checking any signature. Use [`verify`] for
/// anything received over the network.
pub fn parse(body: &[u8]) -> Result<WebhookEvent, WebhookError> {
    let bad = |e: serde_json::Error| WebhookError::BadBody(e.to_string());
    let env: Envelope = serde_json::from_slice(body).map_err(bad)?;
    let event = match env.kind.as_str() {
        "org.deleted" => {
            let d: OrgData = serde_json::from_value(env.data).map_err(bad)?;
            LifecycleEvent::OrgDeleted { org_id: d.org_id }
        }
        "team.deleted" => {
            let d: TeamData = serde_json::from_value(env.data).map_err(bad)?;
            LifecycleEvent::TeamDeleted {
                org_id: d.org_id,
                team_id: d.team_id,
            }
        }
        "member.removed" => {
            let d: MemberData = serde_json::from_value(env.data).map_err(bad)?;
            LifecycleEvent::MemberRemoved {
                org_id: d.org_id,
                user_id: d.user_id,
            }
        }
        other => LifecycleEvent::Unknown {
            kind: other.to_owned(),
        },
    };
    Ok(WebhookEvent {
        id: env.id,
        created_at: env.created_at,
        event,
    })
}

/// Build the JSON body the platform sends. Public so the platform and this
/// crate share one definition of the envelope.
pub fn body(id: Uuid, kind: &str, created_at: DateTime<Utc>, data: &serde_json::Value) -> Vec<u8> {
    #[derive(Serialize)]
    struct Out<'a> {
        id: Uuid,
        #[serde(rename = "type")]
        kind: &'a str,
        created_at: DateTime<Utc>,
        data: &'a serde_json::Value,
    }
    serde_json::to_vec(&Out {
        id,
        kind,
        created_at,
        data,
    })
    .expect("a JSON value always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "otto_whsec_test";

    fn sample() -> (Uuid, Vec<u8>) {
        let id = Uuid::new_v4();
        let data = serde_json::json!({ "org_id": Uuid::new_v4(), "team_id": Uuid::new_v4() });
        (id, body(id, "team.deleted", Utc::now(), &data))
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let (id, body) = sample();
        let header = sign(SECRET, 1000, &body);
        let ev = verify_at(SECRET, &header, &body, 1010, 300).unwrap();
        assert_eq!(ev.id, id);
        assert!(matches!(ev.event, LifecycleEvent::TeamDeleted { .. }));
    }

    #[test]
    fn wrong_secret_and_tampered_body_are_refused() {
        let (_, body) = sample();
        let header = sign(SECRET, 1000, &body);
        assert_eq!(
            verify_at("otto_whsec_other", &header, &body, 1000, 300).unwrap_err(),
            WebhookError::BadSignature
        );
        let mut tampered = body.clone();
        tampered.push(b' ');
        assert_eq!(
            verify_at(SECRET, &header, &tampered, 1000, 300).unwrap_err(),
            WebhookError::BadSignature
        );
    }

    #[test]
    fn a_timestamp_cannot_be_swapped_without_breaking_the_mac() {
        let (_, body) = sample();
        let header = sign(SECRET, 1000, &body);
        let forged = header.replacen("t=1000", "t=5000", 1);
        assert_eq!(
            verify_at(SECRET, &forged, &body, 5000, 300).unwrap_err(),
            WebhookError::BadSignature
        );
    }

    #[test]
    fn stale_signatures_are_refused() {
        let (_, body) = sample();
        let header = sign(SECRET, 1000, &body);
        assert_eq!(
            verify_at(SECRET, &header, &body, 1301, 300).unwrap_err(),
            WebhookError::Stale
        );
        assert!(verify_at(SECRET, &header, &body, 1300, 300).is_ok());
    }

    #[test]
    fn rotation_header_with_two_signatures_accepts_either() {
        let (_, body) = sample();
        let old = sign("otto_whsec_old", 1000, &body);
        let new = sign(SECRET, 1000, &body);
        let v1 = |h: &str| h.split_once("v1=").unwrap().1.to_owned();
        let both = format!("t=1000,v1={},v1={}", v1(&old), v1(&new));
        assert!(verify_at(SECRET, &both, &body, 1000, 300).is_ok());
        assert!(verify_at("otto_whsec_old", &both, &body, 1000, 300).is_ok());
    }

    #[test]
    fn only_the_first_few_signatures_are_considered() {
        let (_, body) = sample();
        let junk = format!("v1={},", hex::encode([0u8; 32]));
        let good = sign(SECRET, 1000, &body);
        let good = good.split_once("v1=").unwrap().1.to_owned();

        let within = format!("t=1000,{}v1={good}", junk.repeat(MAX_SIGNATURES - 1));
        assert!(verify_at(SECRET, &within, &body, 1000, 300).is_ok());

        let beyond = format!("t=1000,{}v1={good}", junk.repeat(MAX_SIGNATURES));
        assert_eq!(
            verify_at(SECRET, &beyond, &body, 1000, 300).unwrap_err(),
            WebhookError::BadSignature
        );
    }

    #[test]
    fn malformed_headers_are_refused() {
        let (_, body) = sample();
        for h in [
            "",
            "garbage",
            "t=abc,v1=00",
            "t=1000",
            "v1=00",
            "t=1000,v1=zz",
        ] {
            assert_eq!(
                verify_at(SECRET, h, &body, 1000, 300).unwrap_err(),
                WebhookError::MalformedHeader,
                "{h:?}"
            );
        }
    }

    #[test]
    fn unknown_event_types_parse_as_unknown() {
        let b = body(
            Uuid::new_v4(),
            "plan.changed",
            Utc::now(),
            &serde_json::json!({}),
        );
        let ev = parse(&b).unwrap();
        assert_eq!(
            ev.event,
            LifecycleEvent::Unknown {
                kind: "plan.changed".into()
            }
        );
    }

    #[test]
    fn known_type_with_missing_fields_is_a_bad_body() {
        let b = body(
            Uuid::new_v4(),
            "org.deleted",
            Utc::now(),
            &serde_json::json!({}),
        );
        assert!(matches!(parse(&b), Err(WebhookError::BadBody(_))));
    }
}
