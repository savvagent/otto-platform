//! Secrets and idempotency keys as validated newtypes.
//!
//! The two secret types never print their contents: `Debug` and `Display`
//! both render `<redacted>`, so a key that ends up in a log line or an error
//! chain by accident leaks nothing. The raw value is reachable only inside
//! this module tree.

use std::fmt;

use super::error::StripeError;

/// The longest secret or idempotency key accepted. Stripe's own keys are well
/// under this; the cap keeps a misconfigured value from being sent as a header.
const MAX_LEN: usize = 255;

/// Header-safe: visible ASCII, no spaces.
fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

/// A Stripe secret (`sk_...`) or restricted (`rk_...`) API key.
///
/// ```
/// use savvagent_billing::stripe::SecretKey;
///
/// let key = SecretKey::new("sk_test_123").unwrap();
/// assert_eq!(format!("{key}"), "<redacted>");
/// assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
/// assert!(SecretKey::new("pk_test_123").is_err());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(String);

impl SecretKey {
    /// Accepts a secret or restricted key. A publishable key (`pk_`) or a
    /// value that could not be sent as a header is refused, without echoing it.
    pub fn new(key: impl Into<String>) -> Result<Self, StripeError> {
        let key = key.into();
        if !header_safe(&key) || !(key.starts_with("sk_") || key.starts_with("rk_")) {
            return Err(StripeError::InvalidRequest(
                "Stripe secret key must be an sk_ or rk_ key of visible ASCII".into(),
            ));
        }
        Ok(Self(key))
    }

    /// Whether the key is a live-mode or a test-mode key, from its prefix
    /// (`sk_live_`, `rk_live_`, `sk_test_`, `rk_test_`). `None` for a key of
    /// neither shape. The mode is not a secret; the key is never shown.
    ///
    /// ```
    /// use savvagent_billing::stripe::{KeyMode, SecretKey};
    ///
    /// assert_eq!(SecretKey::new("rk_live_abc").unwrap().mode(), Some(KeyMode::Live));
    /// assert_eq!(SecretKey::new("sk_test_abc").unwrap().mode(), Some(KeyMode::Test));
    /// assert_eq!(SecretKey::new("sk_abc").unwrap().mode(), None);
    /// ```
    pub fn mode(&self) -> Option<KeyMode> {
        let rest = self
            .0
            .strip_prefix("sk_")
            .or_else(|| self.0.strip_prefix("rk_"))?;
        if rest.starts_with("live_") {
            Some(KeyMode::Live)
        } else if rest.starts_with("test_") {
            Some(KeyMode::Test)
        } else {
            None
        }
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

/// Which of a Stripe account's two worlds a key acts in. Objects made in one
/// (customers, prices, subscriptions) do not exist in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyMode {
    Live,
    Test,
}

impl KeyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
        }
    }

    /// The inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "live" => Some(Self::Live),
            "test" => Some(Self::Test),
            _ => None,
        }
    }
}

impl fmt::Display for KeyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A webhook endpoint signing secret (`whsec_...`).
///
/// ```
/// use savvagent_billing::stripe::WebhookSecret;
///
/// let s = WebhookSecret::new("whsec_abc").unwrap();
/// assert_eq!(format!("{s:?}"), "WebhookSecret(<redacted>)");
/// assert!(WebhookSecret::new("abc").is_err());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(String);

impl WebhookSecret {
    pub fn new(secret: impl Into<String>) -> Result<Self, StripeError> {
        let secret = secret.into();
        if !header_safe(&secret) || !secret.starts_with("whsec_") {
            return Err(StripeError::InvalidRequest(
                "Stripe webhook secret must be a whsec_ value of visible ASCII".into(),
            ));
        }
        Ok(Self(secret))
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

impl fmt::Display for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The `Idempotency-Key` sent with a POST. Every POST method on
/// [`super::Client`] requires one, so none can be sent without it.
///
/// Derive it from something stable (a ledger row id, an event id) when the
/// call may be retried, so the retry is recognized; use [`Self::random`] only
/// for a call that is never retried.
///
/// ```
/// use savvagent_billing::stripe::IdempotencyKey;
///
/// let k = IdempotencyKey::new("sync-meter:factory/jobs").unwrap();
/// assert_eq!(k.as_str(), "sync-meter:factory/jobs");
/// assert!(IdempotencyKey::new("").is_err());
/// assert_ne!(IdempotencyKey::random(), IdempotencyKey::random());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// 1 to 255 characters of visible ASCII.
    pub fn new(key: impl Into<String>) -> Result<Self, StripeError> {
        let key = key.into();
        if !header_safe(&key) {
            return Err(StripeError::InvalidRequest(
                "idempotency key must be 1 to 255 characters of visible ASCII".into(),
            ));
        }
        Ok(Self(key))
    }

    /// A fresh random (UUIDv4) key.
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_validation() {
        assert!(SecretKey::new("sk_live_abc").is_ok());
        assert!(SecretKey::new("rk_live_abc").is_ok());
        assert!(SecretKey::new("").is_err());
        assert!(SecretKey::new("pk_live_abc").is_err());
        assert!(SecretKey::new("sk_live abc").is_err());
        assert!(SecretKey::new("sk_live_\nabc").is_err());
        assert!(SecretKey::new(format!("sk_{}", "a".repeat(300))).is_err());
    }

    #[test]
    fn a_keys_mode_is_read_from_its_prefix() {
        for (key, mode) in [
            ("sk_live_a", Some(KeyMode::Live)),
            ("rk_live_a", Some(KeyMode::Live)),
            ("sk_test_a", Some(KeyMode::Test)),
            ("rk_test_a", Some(KeyMode::Test)),
            ("sk_a", None),
            ("sk_livex", None),
        ] {
            assert_eq!(SecretKey::new(key).unwrap().mode(), mode, "{key}");
        }
        for m in [KeyMode::Live, KeyMode::Test] {
            assert_eq!(KeyMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(KeyMode::parse("LIVE"), None);
    }

    #[test]
    fn rejection_does_not_echo_the_key() {
        let err = SecretKey::new("pk_live_supersecret").unwrap_err();
        assert!(!format!("{err} {err:?}").contains("supersecret"));
    }

    #[test]
    fn secrets_are_redacted() {
        let k = SecretKey::new("sk_test_supersecret").unwrap();
        let w = WebhookSecret::new("whsec_supersecret").unwrap();
        for s in [
            format!("{k}"),
            format!("{k:?}"),
            format!("{k:#?}"),
            format!("{w}"),
            format!("{w:?}"),
            format!("{w:#?}"),
        ] {
            assert!(!s.contains("supersecret"), "{s}");
        }
    }

    #[test]
    fn idempotency_key_validation() {
        assert!(IdempotencyKey::new("a").is_ok());
        assert!(IdempotencyKey::new("a".repeat(255)).is_ok());
        assert!(IdempotencyKey::new("a".repeat(256)).is_err());
        assert!(IdempotencyKey::new("a b").is_err());
        assert!(IdempotencyKey::new("a\r\nX-Evil: 1").is_err());
    }
}
