//! Errors. None of these carries a token, a code, a verifier or a response
//! body: a message is built from fixed text, a URL, or the OAuth `error` code
//! and description a server sent, passed through [`server_text`] first, so
//! printing or logging one cannot leak a secret or drive the terminal.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The grant for this resource is gone, expired or revoked.
    #[error("not signed in for {resource}: run `ottoctl login --resource {resource}` again")]
    LoginRequired { resource: String },

    #[error("discovery failed: {0}")]
    Discovery(String),

    #[error("authorization failed: {0}")]
    Authorization(String),

    #[error("could not reach {0}")]
    Network(String),

    /// The request was sent but no usable answer came back, so it may have
    /// taken effect. A caller that issues a secret should say so.
    #[error(
        "{resource} may have received the request, but no usable response came back: {reason}"
    )]
    NoResponse { resource: String, reason: String },

    #[error("credential store: {0}")]
    Store(String),

    /// The resource refused a tool call because the token lacks a scope.
    /// `message` is the server's, cleaned; it usually names the scope.
    #[error("{resource} refused this sign-in: {message}")]
    InsufficientScope { resource: String, message: String },

    /// A tool call failed: a JSON-RPC error, or a result marked `isError`.
    #[error("{tool} failed: {message}")]
    Tool { tool: String, message: String },

    /// Writing a secret somewhere that is not safe for it was refused.
    #[error("{0}")]
    Refused(String),

    #[error("{0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn io(what: &str, e: &std::io::Error) -> Self {
        // `kind()` rather than the Display of `e`: some platform messages
        // embed the path, which is fine, but never the data being written.
        Error::Io(format!("{what}: {}", e.kind()))
    }
}

/// Text a server sent (an OAuth `error` or `error_description`), made safe to
/// print: control characters, which include terminal escape sequences, are
/// dropped, and the length is capped.
pub(crate) fn server_text(s: &str) -> String {
    const MAX_CHARS: usize = 200;
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    match cleaned.char_indices().nth(MAX_CHARS) {
        Some((cut, _)) => format!("{}…", &cleaned[..cut]),
        None => cleaned,
    }
}

/// `code` and `description` from a server, cleaned and joined.
pub(crate) fn server_error(code: &str, description: &str) -> String {
    format!("{} {}", server_text(code), server_text(description))
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_text_drops_escapes_and_caps_length() {
        assert_eq!(server_text("bad\u{1b}[31mred\u{7}\n"), "bad[31mred");
        let long = "x".repeat(500);
        assert_eq!(server_text(&long).chars().count(), 201);
    }
}
