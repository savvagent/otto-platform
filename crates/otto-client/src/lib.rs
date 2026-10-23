//! Sign a terminal tool in to an otto resource the way an MCP client does, and
//! keep the token. Built for the `otto` command and for the `otto-<app>`
//! binaries it runs, which call [`Client::token`] to get a bearer token for
//! their own resource.
//!
//! - [`Client::login`]: discovery, dynamic registration (RFC 7591), authorization
//!   code with PKCE S256, loopback redirect. One grant per resource, because a
//!   token has one audience.
//! - [`Client::token`]: the cached token, refreshed when it is near expiry; a
//!   resource with no grant yet goes through login; a revoked grant is
//!   [`Error::LoginRequired`].
//! - [`Secret`]: for what an app returns that must not reach a model. It cannot
//!   be formatted, only delivered to the terminal or an owner-only file.

mod discovery;
mod error;
mod flow;
mod pkce;
mod secret;
mod store;

pub use error::{Error, Result};
pub use secret::{Secret, Sink};
pub use store::{Grant, Store};

use std::process::{Command, Stdio};
use std::time::Duration;

use url::Url;

/// Opens a URL for the person to look at. A trait so tests can stand in for a
/// browser.
pub trait Opener: Send + Sync {
    fn open(&self, url: &Url) -> Result<()>;
}

/// Launches the platform's default browser (`xdg-open` on Linux, `open` on macOS).
pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &Url) -> Result<()> {
        let program = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        Command::new(program)
            .arg(url.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| Error::io(&format!("launching {program}"), &e))
    }
}

pub struct Client {
    http: reqwest::Client,
    store: Store,
    opener: Box<dyn Opener>,
}

impl Client {
    pub fn new(store: Store, opener: Box<dyn Opener>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            // An OAuth endpoint that redirects is not one to follow with a
            // code, a verifier or a refresh token in the request.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("otto-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| Error::Io("could not build the HTTP client".into()))?;
        Ok(Client {
            http,
            store,
            opener,
        })
    }

    /// The default store and the system browser.
    pub fn with_defaults() -> Result<Self> {
        Self::new(Store::open_default()?, Box::new(SystemOpener))
    }

    /// Sign in to `resource`, replacing any grant it already has.
    pub async fn login(&self, resource: &str, scopes: &[String]) -> Result<()> {
        flow::login(
            &self.http,
            &self.store,
            self.opener.as_ref(),
            resource,
            scopes,
        )
        .await
    }

    /// A bearer token whose audience is exactly `resource`. Consent happens
    /// only if the resource has no grant yet.
    pub async fn token(&self, resource: &str) -> Result<Secret> {
        match flow::fresh_grant(&self.http, &self.store, resource).await? {
            Some(g) => Ok(Secret::new(g.access_token)),
            None => {
                self.login(resource, &[]).await?;
                flow::fresh_grant(&self.http, &self.store, resource)
                    .await?
                    .map(|g| Secret::new(g.access_token))
                    .ok_or_else(|| Error::LoginRequired {
                        resource: resource.to_owned(),
                    })
            }
        }
    }

    /// Whether `resource` already has a grant, without any network call.
    pub fn is_signed_in(&self, resource: &str) -> Result<bool> {
        Ok(self.store.grant(resource)?.is_some())
    }
}
