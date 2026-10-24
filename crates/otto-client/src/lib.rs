//! Sign a terminal tool in to an otto resource the way an MCP client does, and
//! keep the token. Built for the `ottoctl` command and for the `otto-<app>`
//! binaries it runs, which call [`Client::token`] to get a bearer token for
//! their own resource.
//!
//! - [`Client::login`]: discovery, dynamic registration (RFC 7591), authorization
//!   code with PKCE S256, loopback redirect. One grant per resource, because a
//!   token has one audience. A usable grant is reused unless `force` is set.
//! - [`Client::token`]: the cached token, refreshed when it is near expiry; a
//!   resource with no grant yet goes through login; a revoked grant is
//!   [`Error::LoginRequired`].
//! - [`Client::call_tool`]: call one of a resource's MCP tools with that
//!   token, taking the fields named as secret out of the result as [`Secret`]s.
//! - [`Secret`]: for what an app returns that must not reach a model. It cannot
//!   be formatted, only delivered to the terminal or an owner-only file.

mod discovery;
mod error;
mod flow;
mod mcp;
mod pkce;
mod private_fs;
mod secret;
mod store;

pub use error::{Error, Result};
pub use mcp::ToolOutput;
pub use secret::{Reservation, Secret, Sink};
pub use store::{Grant, Store};

/// What [`Client::login`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    /// A usable grant covering the requested scopes was already cached.
    AlreadySignedIn,
    /// The browser flow ran and a new grant was stored.
    SignedIn,
}

use std::process::{Command, Stdio};
use std::time::Duration;

use url::Url;

/// Opens a URL for the person to look at. A trait so tests can stand in for a
/// browser.
pub trait Opener: Send + Sync {
    fn open(&self, url: &Url) -> Result<()>;
}

/// Launches the platform's default browser: `xdg-open` on Linux, `open` on
/// macOS, and on Windows the URL protocol handler through `rundll32`, which
/// takes the URL as it is. (`cmd /c start` would read the `&` between query
/// parameters as a command separator.)
pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &Url) -> Result<()> {
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("rundll32.exe", &["url.dll,FileProtocolHandler"])
        } else if cfg!(target_os = "macos") {
            ("open", &[])
        } else {
            ("xdg-open", &[])
        };
        Command::new(program)
            .args(args)
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

    /// Sign in to `resource`. A cached grant that is usable (refreshing it if
    /// needed) and already covers `scopes` is kept, and no browser opens;
    /// `force` always runs the browser flow and replaces it.
    pub async fn login(
        &self,
        resource: &str,
        scopes: &[String],
        force: bool,
    ) -> Result<LoginOutcome> {
        flow::login(
            &self.http,
            &self.store,
            self.opener.as_ref(),
            resource,
            scopes,
            force,
        )
        .await
    }

    /// A bearer token whose audience is exactly `resource`. Consent happens
    /// only if the resource has no grant yet.
    pub async fn token(&self, resource: &str) -> Result<Secret> {
        match flow::fresh_grant(&self.http, &self.store, resource).await? {
            Some(g) => Ok(Secret::new(g.access_token)),
            None => {
                self.login(resource, &[], false).await?;
                flow::fresh_grant(&self.http, &self.store, resource)
                    .await?
                    .map(|g| Secret::new(g.access_token))
                    .ok_or_else(|| Error::LoginRequired {
                        resource: resource.to_owned(),
                    })
            }
        }
    }

    /// A bearer token for `resource` that carries every one of `scopes`.
    /// A cached grant that lacks one is replaced by signing in again, asking
    /// for its scopes as well as these, so what was granted before is kept.
    pub async fn token_with_scopes(&self, resource: &str, scopes: &[String]) -> Result<Secret> {
        if scopes.is_empty() {
            return self.token(resource).await;
        }
        let mut wanted: Vec<String> = match self.store.grant(resource)? {
            Some(g) => g.scope.split_whitespace().map(str::to_owned).collect(),
            None => Vec::new(),
        };
        for s in scopes {
            if !wanted.contains(s) {
                wanted.push(s.clone());
            }
        }
        self.login(resource, &wanted, false).await?;
        let grant = flow::fresh_grant(&self.http, &self.store, resource)
            .await?
            .ok_or_else(|| Error::LoginRequired {
                resource: resource.to_owned(),
            })?;
        // The server may grant less than was asked (a scope the person may
        // not hold). Say so now, rather than send a request it will refuse.
        let missing: Vec<&str> = scopes
            .iter()
            .map(String::as_str)
            .filter(|s| !grant.scope.split_whitespace().any(|g| g == *s))
            .collect();
        if !missing.is_empty() {
            return Err(Error::InsufficientScope {
                resource: resource.to_owned(),
                message: format!("the sign-in was not granted {}", missing.join(", ")),
            });
        }
        Ok(Secret::new(grant.access_token))
    }

    /// Call the MCP tool `tool` on `resource` with `arguments`, signed in
    /// with `scopes` (see [`Client::token_with_scopes`]). Each JSON pointer in
    /// `secret_fields` (e.g. `/keys/serverKey`) is removed from the result and
    /// returned through [`ToolOutput::secret`], so [`ToolOutput::value`] is
    /// safe to print.
    pub async fn call_tool(
        &self,
        resource: &str,
        scopes: &[String],
        tool: &str,
        arguments: serde_json::Value,
        secret_fields: &[&str],
    ) -> Result<ToolOutput> {
        let token = self.token_with_scopes(resource, scopes).await?;
        mcp::call_tool(&self.http, resource, &token, tool, arguments, secret_fields).await
    }

    /// Whether `resource` already has a grant, without any network call.
    pub fn is_signed_in(&self, resource: &str) -> Result<bool> {
        Ok(self.store.grant(resource)?.is_some())
    }
}
