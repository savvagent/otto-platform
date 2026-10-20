//! The HTTP core: base URL, headers, form encoding, response decoding.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::error::{ApiError, StripeError};
use super::secret::{IdempotencyKey, SecretKey};

/// The Stripe API version every request is pinned to. Responses are decoded
/// against this version's shapes; bump it deliberately, never implicitly.
pub const STRIPE_VERSION: &str = "2025-03-31.basil";

/// Production Stripe.
pub const DEFAULT_BASE_URL: &str = "https://api.stripe.com";

/// The largest response body read. Every response this client asks for is a
/// single small object; anything larger is refused rather than buffered.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A Stripe API client.
///
/// Cheap to clone (the connection pool is shared).
///
/// ```
/// use otto_billing::stripe::{Client, SecretKey};
///
/// let key = SecretKey::new("sk_test_123").unwrap();
/// let client = Client::with_base_url(key, "http://127.0.0.1:12111").unwrap();
/// assert!(!format!("{client:?}").contains("sk_test_123"));
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    /// Scheme, host and optional port, without a trailing slash.
    base: String,
    key: SecretKey,
}

impl Client {
    /// A client for production Stripe.
    pub fn new(key: SecretKey) -> Result<Self, StripeError> {
        Self::with_base_url(key, DEFAULT_BASE_URL)
    }

    /// A client for another base URL (`stripe-mock`, a test server). It must
    /// be http(s) with no query or fragment; a trailing `/` is ignored.
    pub fn with_base_url(key: SecretKey, base_url: &str) -> Result<Self, StripeError> {
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|e| StripeError::InvalidRequest(format!("base URL: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none()
        {
            return Err(StripeError::InvalidRequest(
                "base URL must be http(s)://host[:port][/path] with no query or fragment".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            // An API client has no reason to follow a redirect, and following
            // one could carry the Authorization header somewhere else.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("otto-billing/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(StripeError::Transport)?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_owned(),
            key,
        })
    }

    fn headers(&self) -> Result<HeaderMap, StripeError> {
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", self.key.expose()))
            // Unreachable: SecretKey is validated as visible ASCII. Mapped
            // rather than unwrapped, and without the value.
            .map_err(|_| StripeError::InvalidRequest("secret key is not header-safe".into()))?;
        auth.set_sensitive(true);
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, auth);
        h.insert("Stripe-Version", HeaderValue::from_static(STRIPE_VERSION));
        Ok(h)
    }

    /// POST a form to `path` (which starts with `/v1/`).
    pub(super) async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        form: Form,
        idempotency_key: &IdempotencyKey,
    ) -> Result<T, StripeError> {
        let body = form.encode()?;
        let idem = HeaderValue::from_str(idempotency_key.as_str()).map_err(|_| {
            StripeError::InvalidRequest("idempotency key is not header-safe".into())
        })?;
        let req = self
            .http
            .post(format!("{}{path}", self.base))
            .headers(self.headers()?)
            .header("Idempotency-Key", idem)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body);
        self.send(req).await
    }

    /// GET `path` (which starts with `/v1/`).
    pub(super) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, StripeError> {
        let req = self
            .http
            .get(format!("{}{path}", self.base))
            .headers(self.headers()?);
        self.send(req).await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, StripeError> {
        let resp = req.send().await.map_err(StripeError::Transport)?;
        let status = resp.status();
        let body = read_bounded(resp).await?;
        if status.is_success() {
            return serde_json::from_slice(&body)
                .map_err(|e| StripeError::Decode(format!("HTTP {}: {e}", status.as_u16())));
        }
        Err(StripeError::Api(self.api_error(status.as_u16(), &body)))
    }

    /// Build the typed error for a non-2xx response, scrubbing the key.
    fn api_error(&self, status: u16, body: &[u8]) -> ApiError {
        #[derive(Deserialize)]
        struct Body {
            error: Inner,
        }
        #[derive(Deserialize)]
        struct Inner {
            #[serde(rename = "type")]
            kind: Option<String>,
            code: Option<String>,
            message: Option<String>,
            param: Option<String>,
        }
        let key = self.key.expose();
        let scrub = |s: String| s.replace(key, "[redacted]");
        match serde_json::from_slice::<Body>(body) {
            Ok(Body { error }) => ApiError {
                status,
                kind: scrub(error.kind.unwrap_or_else(|| "unknown".into())),
                code: error.code.map(scrub),
                message: scrub(error.message.unwrap_or_default()),
                param: error.param.map(scrub),
            },
            // Not Stripe's error shape (a proxy page, an empty body). The raw
            // body is not copied in: it is unbounded in content and could
            // echo the request.
            Err(_) => ApiError {
                status,
                kind: "invalid_response".into(),
                code: None,
                message: format!("HTTP {status} with no Stripe error object in the body"),
                param: None,
            },
        }
    }
}

/// Read at most [`MAX_RESPONSE_BYTES`], failing rather than truncating.
async fn read_bounded(mut resp: reqwest::Response) -> Result<Vec<u8>, StripeError> {
    let too_big =
        || StripeError::Decode(format!("response body exceeds {MAX_RESPONSE_BYTES} bytes"));
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(StripeError::Transport)? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(too_big());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// An ordered list of form fields, using Stripe's bracket syntax for nesting
/// (`tiers[0][up_to]`). Order is preserved so the encoding is deterministic.
#[derive(Debug, Default)]
pub(super) struct Form(Vec<(String, String)>);

impl Form {
    pub(super) fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.push((key.into(), value.into()));
    }

    pub(super) fn push_opt(&mut self, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            self.push(key, v);
        }
    }

    fn encode(&self) -> Result<String, StripeError> {
        serde_urlencoded::to_string(&self.0)
            .map_err(|e| StripeError::InvalidRequest(format!("form encoding: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::new("sk_test_k").unwrap()
    }

    #[test]
    fn base_url_validation() {
        assert!(Client::with_base_url(key(), "http://127.0.0.1:1").is_ok());
        assert!(Client::with_base_url(key(), "https://api.stripe.com/").is_ok());
        assert!(Client::with_base_url(key(), "ftp://x").is_err());
        assert!(Client::with_base_url(key(), "https://x/?a=1").is_err());
        assert!(Client::with_base_url(key(), "https://x/#f").is_err());
        assert!(Client::with_base_url(key(), "not a url").is_err());
    }

    #[test]
    fn trailing_slash_is_dropped() {
        let c = Client::with_base_url(key(), "http://127.0.0.1:1/").unwrap();
        assert_eq!(c.base, "http://127.0.0.1:1");
    }

    #[test]
    fn form_encodes_brackets_and_order() {
        let mut f = Form::default();
        f.push("b", "2");
        f.push("tiers[0][up_to]", "inf");
        f.push("a", "x y&z");
        let enc = f.encode().unwrap();
        assert_eq!(enc, "b=2&tiers%5B0%5D%5Bup_to%5D=inf&a=x+y%26z");
    }
}
