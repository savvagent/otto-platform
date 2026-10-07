//! Everything the process cannot infer, read once from the environment.
//!
//! Two rules decide whether a setting gets a default, and they are the reason
//! this file is longer than a `serde` derive would be:
//!
//! 1. **A setting whose wrong value fails silently has no default.** A wrong
//!    `OTTO_PUBLIC_URL` does not crash: it mails links to an origin that does
//!    not exist, builds an OAuth issuer nothing trusts, and binds every passkey
//!    to the wrong relying party, and the first report arrives hours later from
//!    somebody who cannot sign in. Refusing to start is the cheap version of
//!    that failure.
//! 2. **A setting whose wrong value is merely inconvenient gets one.** The bind
//!    address and the log format are obvious within seconds of looking.
//!
//! Nothing here falls back quietly. A variable that is set but unparseable is
//! an error naming the variable and what it accepts, never a default — an
//! `OTTO_ENFORCE_QUOTAS=yes-please` that silently reads as "off" is how a
//! billing control gets reported switched off for a year.
//!
//! Every variable is `OTTO_*`, ported from otto-factory's `OF_*` set. The
//! factory-only settings (GitHub App, JIRA, the MCP resource URI, MCP host and
//! origin allow-lists) did not come with it: a resource server's configuration
//! belongs to that resource server. The console bundle directory did, as the
//! optional `OTTO_STATIC_DIR`.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

/// The whole deployment, resolved.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,

    /// Public origin a browser sees (`OTTO_PUBLIC_URL`), e.g.
    /// `https://otto.savvagent.com`. The OAuth issuer, the discovery document,
    /// every link handed to a human, and the WebAuthn relying party id (its
    /// host) are all built from it.
    pub public_url: String,

    /// 32 bytes, base64 (`OTTO_ENCRYPTION_KEY`). Encrypts secrets at rest —
    /// today the enterprise SSO connections' IdP client secrets.
    pub encryption_key: String,

    /// The header a trusted proxy writes the client address into
    /// (`OTTO_CLIENT_IP_HEADER`). See `otto_web::Config::client_ip_header` for
    /// why this must stay unset unless a proxy that *overwrites* it sits in
    /// front — on Fly.io, `fly-client-ip`.
    pub client_ip_header: Option<String>,

    /// Whether the resource servers are enforcing hard-stop plans
    /// (`OTTO_ENFORCE_QUOTAS`). Reporting only: this server enforces nothing,
    /// it tells the console what the resource servers are doing. See
    /// `otto_web::Config::enforce_quotas`.
    pub enforce_quotas: bool,

    /// The built console bundle (`OTTO_STATIC_DIR`), served with an
    /// `index.html` fallback for self-hosters who run no Cloudflare Worker.
    /// `None` serves no console at all, which is what the hosted deployment
    /// wants: there the Worker in `web/worker/` serves the bundle, and this
    /// process is the API only.
    pub static_dir: Option<PathBuf>,

    pub run_migrations: bool,
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line, for a log aggregator.
    Json,
    /// Human-readable, for a terminal.
    Text,
}

impl Config {
    /// Read the environment. Every failure names the variable it is about.
    pub fn from_env() -> Result<Self> {
        let public_url = required("OTTO_PUBLIC_URL")?
            .trim_end_matches('/')
            .to_string();
        validate_public_url(&public_url)?;

        Ok(Self {
            database_url: required("DATABASE_URL")?,
            bind: parse_var("OTTO_BIND", "0.0.0.0:8080", |v| {
                v.parse::<SocketAddr>()
                    .map_err(|e| anyhow!("{e}; expected host:port, e.g. 0.0.0.0:8080"))
            })?,
            encryption_key: required("OTTO_ENCRYPTION_KEY")?,
            client_ip_header: optional("OTTO_CLIENT_IP_HEADER")
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty()),
            enforce_quotas: parse_var("OTTO_ENFORCE_QUOTAS", "0", parse_bool)?,
            static_dir: optional("OTTO_STATIC_DIR").map(|v| PathBuf::from(v.trim())),
            run_migrations: parse_var("OTTO_RUN_MIGRATIONS", "1", parse_bool)?,
            log_format: parse_var("OTTO_LOG_FORMAT", "text", |v| match v {
                "json" => Ok(LogFormat::Json),
                "text" => Ok(LogFormat::Text),
                other => Err(anyhow!("expected json or text, got {other:?}")),
            })?,
            public_url,
        })
    }
}

/// Parsed rather than merely stored: an `OTTO_PUBLIC_URL` with no scheme
/// produces links a mail client will not linkify and a relying party id of the
/// empty string, both of which are much harder to diagnose later than a message
/// here.
fn validate_public_url(public_url: &str) -> Result<()> {
    let parsed = url::Url::parse(public_url)
        .with_context(|| format!("OTTO_PUBLIC_URL is not a URL: {public_url:?}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "OTTO_PUBLIC_URL must be http or https, got {:?}",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!("OTTO_PUBLIC_URL has no host: {public_url:?}"));
    }
    Ok(())
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn required(name: &str) -> Result<String> {
    optional(name).ok_or_else(|| anyhow!("{name} is required and not set"))
}

/// Parse an optional variable, defaulting only when it is absent.
///
/// A variable that is *present* and unparseable is an error. Falling back to
/// the default there would mean a typo in a value someone deliberately set is
/// indistinguishable from not setting it.
fn parse_var<T>(name: &str, default: &str, parse: impl Fn(&str) -> Result<T>) -> Result<T> {
    let raw = optional(name);
    let value = raw.as_deref().unwrap_or(default);
    parse(value.trim()).with_context(|| format!("{name}={value:?} is not valid"))
}

fn parse_bool(v: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(anyhow!(
            "expected a boolean (1/0, true/false, yes/no, on/off), got {other:?}"
        )),
    }
}

#[cfg(test)]
impl Config {
    /// A complete, valid `Config` for tests.
    ///
    /// One fixture rather than a literal per test: a new field then fails to
    /// compile here once, instead of being quietly defaulted in every test that
    /// happens to build a `Config` by hand.
    pub(crate) fn for_test() -> Self {
        Self {
            database_url: "postgres://x".into(),
            bind: "0.0.0.0:8080".parse().expect("test bind"),
            public_url: "https://otto.example.com".into(),
            // 32 zero bytes, base64.
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            client_ip_header: None,
            enforce_quotas: false,
            static_dir: None,
            run_migrations: true,
            log_format: LogFormat::Text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans_accept_the_spellings_people_actually_write() {
        for yes in ["1", "true", "TRUE", "yes", "On"] {
            assert!(parse_bool(yes).unwrap(), "{yes}");
        }
        for no in ["0", "false", "NO", "off"] {
            assert!(!parse_bool(no).unwrap(), "{no}");
        }
    }

    /// The whole point of `parse_bool` returning a `Result`.
    /// `OTTO_ENFORCE_QUOTAS` reading as "off" because somebody wrote `enabled`
    /// is a control that is reported switched off, and nothing says so.
    #[test]
    fn a_misspelled_boolean_is_an_error_and_not_a_default() {
        for bad in ["enabled", "y", "2", "please"] {
            assert!(parse_bool(bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn a_default_applies_only_when_the_variable_is_absent() {
        assert_eq!(
            parse_var("OTTO_TEST_ABSENT_VAR_XYZ", "7", |v| Ok(v.parse::<u8>()?)).unwrap(),
            7
        );
    }

    #[test]
    fn the_public_url_must_be_an_http_origin_with_a_host() {
        assert!(validate_public_url("https://otto.savvagent.com").is_ok());
        assert!(validate_public_url("http://localhost:8080").is_ok());
        for bad in ["otto.savvagent.com", "ftp://otto.savvagent.com", "https://"] {
            assert!(validate_public_url(bad).is_err(), "{bad} should be refused");
        }
    }
}
