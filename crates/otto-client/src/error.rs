//! Errors. None of these carries a token, a code, a verifier or a response
//! body: a message is built from fixed text, a URL, or the OAuth `error` code
//! and description a server sent, so printing or logging one cannot leak a
//! secret.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The grant for this resource is gone, expired or revoked.
    #[error("not signed in for {resource}: run `otto login --resource {resource}` again")]
    LoginRequired { resource: String },

    #[error("discovery failed: {0}")]
    Discovery(String),

    #[error("authorization failed: {0}")]
    Authorization(String),

    #[error("could not reach {0}")]
    Network(String),

    #[error("credential store: {0}")]
    Store(String),

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
