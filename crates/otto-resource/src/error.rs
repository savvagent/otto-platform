//! Errors from calls to the platform.

/// A failed call to the platform's resource-server API.
///
/// "Not found" is not an error for lookups that can legitimately find nothing
/// (those return `Ok(None)`); it only appears where the caller named a
/// resource that must exist.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The platform rejected this resource server's credential (HTTP 401).
    /// Not retriable: the secret was rotated, the server was disabled, or the
    /// configuration is wrong.
    #[error("the platform rejected this resource server's credential")]
    Unauthorized,

    /// The named org does not exist (or was deleted).
    #[error("not found")]
    NotFound,

    /// Any other non-success status. `body` is the response text, truncated.
    #[error("platform returned HTTP {status}: {body}")]
    Status { status: u16, body: String },

    /// The request never produced a response: connect, TLS, timeout.
    #[error("could not reach the platform: {0}")]
    Transport(#[source] reqwest::Error),

    /// The platform answered 2xx with a body this crate cannot read, which
    /// means the two are on incompatible versions.
    #[error("unreadable response from the platform: {0}")]
    Decode(String),

    /// The client was given a base URL it cannot use.
    #[error("invalid platform URL: {0}")]
    InvalidUrl(String),
}

impl Error {
    /// Whether retrying the same call later could succeed: transport
    /// failures and 5xx/429 responses.
    pub fn is_retriable(&self) -> bool {
        match self {
            Error::Transport(_) => true,
            Error::Status { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
