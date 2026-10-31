//! The client's error type.

/// An error Stripe returned: the `error` object of a non-2xx response, plus
/// the HTTP status.
///
/// Any occurrence of the caller's secret key in these fields is replaced with
/// `[redacted]` before the value is built, so it is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status of the response.
    pub status: u16,
    /// Stripe's `error.type`, e.g. `card_error`, `invalid_request_error`.
    /// `invalid_response` when the body carried no parseable error object.
    pub kind: String,
    /// Stripe's `error.code`, e.g. `resource_missing`.
    pub code: Option<String>,
    /// Stripe's `error.message`.
    pub message: String,
    /// Stripe's `error.param`: the request parameter at fault, if any.
    pub param: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    /// Stripe answered with a non-2xx status.
    #[error("Stripe API error (HTTP {}, {}{}): {}", .0.status, .0.kind,
        .0.code.as_deref().map(|c| format!(", {c}")).unwrap_or_default(), .0.message)]
    Api(ApiError),
    /// The request never got a response (connect, TLS, timeout). Safe to retry
    /// with the same idempotency key.
    #[error("Stripe request failed: {0}")]
    Transport(#[source] reqwest::Error),
    /// A 2xx response whose body was too large or not the expected shape.
    #[error("Stripe response could not be decoded: {0}")]
    Decode(String),
    /// The request was refused locally, before anything was sent.
    #[error("invalid Stripe request: {0}")]
    InvalidRequest(String),
}

impl StripeError {
    /// The API error, if Stripe returned one.
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Self::Api(e) => Some(e),
            _ => None,
        }
    }
}
