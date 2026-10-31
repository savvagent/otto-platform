//! Everything the process cannot infer, read once from the environment.
//!
//! Two rules decide whether a setting gets a default, and they are the reason
//! this file is longer than a `serde` derive would be:
//!
//! 1. **A setting whose wrong value fails silently has no default.** A wrong
//!    `SAVVAGENT_PUBLIC_URL` does not crash: it mails links to an origin that does
//!    not exist, builds an OAuth issuer nothing trusts, and binds every passkey
//!    to the wrong relying party, and the first report arrives hours later from
//!    somebody who cannot sign in. Refusing to start is the cheap version of
//!    that failure.
//! 2. **A setting whose wrong value is merely inconvenient gets one.** The bind
//!    address and the log format are obvious within seconds of looking.
//!
//! Nothing here falls back quietly. A variable that is set but unparseable is
//! an error naming the variable and what it accepts, never a default — an
//! `SAVVAGENT_ENFORCE_QUOTAS=yes-please` that silently reads as "off" is how a
//! billing control gets reported switched off for a year.
//!
//! Every variable is `SAVVAGENT_*` (`OTTO_*` until the Savvagent rebrand; see
//! [`RETIRED`]), ported from otto-factory's `OF_*` set. The
//! factory-only settings (GitHub App, JIRA, the MCP resource URI, MCP host and
//! origin allow-lists) did not come with it: a resource server's configuration
//! belongs to that resource server. The console bundle directory did, as the
//! optional `SAVVAGENT_STATIC_DIR`.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use otto_billing::stripe::{SecretKey, WebhookSecret};

/// The whole deployment, resolved.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,

    /// Public origin a browser sees (`SAVVAGENT_PUBLIC_URL`), e.g.
    /// `https://savvagent.com`. The OAuth issuer, the discovery document,
    /// every link handed to a human, and the WebAuthn relying party id (its
    /// host) are all built from it.
    pub public_url: String,

    /// 32 bytes, base64 (`SAVVAGENT_ENCRYPTION_KEY`). Encrypts secrets at rest —
    /// today the enterprise SSO connections' IdP client secrets.
    pub encryption_key: String,

    /// The header a trusted proxy writes the client address into
    /// (`SAVVAGENT_CLIENT_IP_HEADER`). See `otto_web::Config::client_ip_header` for
    /// why this must stay unset unless a proxy that *overwrites* it sits in
    /// front — on Fly.io, `fly-client-ip`.
    pub client_ip_header: Option<String>,

    /// Whether the resource servers are enforcing hard-stop plans
    /// (`SAVVAGENT_ENFORCE_QUOTAS`). Reporting only: this server enforces nothing,
    /// it tells the console what the resource servers are doing. See
    /// `otto_web::Config::enforce_quotas`.
    pub enforce_quotas: bool,

    /// The built console bundle (`SAVVAGENT_STATIC_DIR`): prerendered pages as
    /// themselves and the SPA shell, `200.html`, for every other client route.
    /// The bundle must contain `200.html`; `app` refuses to build without it.
    /// The hosted deployment sets it (`fly.toml`);
    /// `None` serves no console at all, for a deployment that puts the optional
    /// Worker in `web/worker/` in front instead.
    pub static_dir: Option<PathBuf>,

    /// Hosts that only redirect (`SAVVAGENT_REDIRECT_HOSTS`): bare lowercase
    /// hostnames, empty by default. Every request whose `Host` is one of them
    /// is answered `308` to the same path and query under `public_url`,
    /// before anything else runs (see `lib.rs`). Never the public URL's own
    /// host, which `from_env` refuses.
    pub redirect_hosts: Vec<String>,

    pub run_migrations: bool,
    pub log_format: LogFormat,

    /// Outgoing notification email (`SAVVAGENT_SMTP_URL` and `SAVVAGENT_EMAIL_FROM`,
    /// both secrets, set together or not at all). `None` disables sending:
    /// the server says so at boot, the delivery loop does not run, and queued
    /// rows wait in `notification_outbox` until a deployment configures it.
    pub email: Option<EmailConfig>,

    /// Stripe billing (`STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`, both
    /// secrets, set together or not at all). `None` disables billing: the
    /// server says so at boot, `GET /api/orgs/{org}/billing` reports
    /// `billingEnabled: false`, and the setup route and the Stripe webhook
    /// answer `503 billing_disabled`. Production boots either way.
    pub stripe: Option<StripeConfig>,

    /// `SAVVAGENT_USAGE_HOLD_THRESHOLD`: the most of one meter an org may accrue in
    /// a billing month before usage ingest holds further events for operator
    /// review instead of billing them (`otto-platform-server usage held`).
    /// Default [`otto_billing::usage::DEFAULT_HOLD_THRESHOLD`].
    pub usage_hold_threshold: i64,
}

/// The Stripe secrets. Both types redact themselves, so `Debug` shows
/// neither.
#[derive(Debug, Clone)]
pub struct StripeConfig {
    /// A secret (`sk_...`) or, preferably, restricted (`rk_...`) API key.
    pub secret_key: SecretKey,
    /// The webhook endpoint's signing secret (`whsec_...`).
    pub webhook_secret: WebhookSecret,
}

/// Where and as whom notification email is sent. Both values are secrets
/// (the URL carries the SMTP credentials), so `Debug` shows neither.
#[derive(Clone)]
pub struct EmailConfig {
    /// `lettre`'s URL syntax, credentials in the userinfo:
    /// `smtps://user:pass@host:465` (implicit TLS) or
    /// `smtp://user:pass@host:587?tls=required` (STARTTLS, refused if the
    /// server does not offer it). A bare `smtp://` sends the password in clear,
    /// so it is accepted only to a loopback host (a local mail catcher).
    pub smtp_url: String,
    /// The `From:` mailbox, e.g. `otto <alerts@savvagent.com>`.
    pub from: String,
}

impl std::fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field("smtp_url", &"<redacted>")
            .field("from", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line, for a log aggregator.
    Json,
    /// Human-readable, for a terminal.
    Text,
}

/// Every variable this file reads, named once.
///
/// `SAVVAGENT_*` since the Savvagent rebrand (savvagent/otto-platform#131),
/// with no fallback to the `OTTO_*` names they replace: see [`RETIRED`].
pub mod var {
    pub const PUBLIC_URL: &str = "SAVVAGENT_PUBLIC_URL";
    pub const BIND: &str = "SAVVAGENT_BIND";
    pub const ENCRYPTION_KEY: &str = "SAVVAGENT_ENCRYPTION_KEY";
    pub const CLIENT_IP_HEADER: &str = "SAVVAGENT_CLIENT_IP_HEADER";
    pub const ENFORCE_QUOTAS: &str = "SAVVAGENT_ENFORCE_QUOTAS";
    pub const STATIC_DIR: &str = "SAVVAGENT_STATIC_DIR";
    /// New with the old-host redirect (savvagent/otto-platform#135): it has no
    /// `OTTO_*` predecessor, so it is not in [`RETIRED`](super::RETIRED).
    pub const REDIRECT_HOSTS: &str = "SAVVAGENT_REDIRECT_HOSTS";
    pub const RUN_MIGRATIONS: &str = "SAVVAGENT_RUN_MIGRATIONS";
    pub const LOG_FORMAT: &str = "SAVVAGENT_LOG_FORMAT";
    pub const SMTP_URL: &str = "SAVVAGENT_SMTP_URL";
    pub const EMAIL_FROM: &str = "SAVVAGENT_EMAIL_FROM";
    pub const USAGE_HOLD_THRESHOLD: &str = "SAVVAGENT_USAGE_HOLD_THRESHOLD";
}

/// The pre-rebrand names, each with the variable that replaced it.
///
/// None of them is read. A deployment that still sets one is refused at
/// startup, naming the replacement, rather than started without it: a
/// leftover `OTTO_SMTP_URL` would otherwise boot with email quietly off, and a
/// leftover `OTTO_STATIC_DIR` with no console, which is the silent failure
/// this file exists to prevent. Refusing is not a compatibility period: the
/// old value is never used, and the fix is renaming it.
pub const RETIRED: &[(&str, &str)] = &[
    ("OTTO_PUBLIC_URL", var::PUBLIC_URL),
    ("OTTO_BIND", var::BIND),
    ("OTTO_ENCRYPTION_KEY", var::ENCRYPTION_KEY),
    ("OTTO_CLIENT_IP_HEADER", var::CLIENT_IP_HEADER),
    ("OTTO_ENFORCE_QUOTAS", var::ENFORCE_QUOTAS),
    ("OTTO_STATIC_DIR", var::STATIC_DIR),
    ("OTTO_RUN_MIGRATIONS", var::RUN_MIGRATIONS),
    ("OTTO_LOG_FORMAT", var::LOG_FORMAT),
    ("OTTO_SMTP_URL", var::SMTP_URL),
    ("OTTO_EMAIL_FROM", var::EMAIL_FROM),
    ("OTTO_USAGE_HOLD_THRESHOLD", var::USAGE_HOLD_THRESHOLD),
];

/// How a variable is looked up: the process environment in production, a map
/// in tests, so the parsing can be tested without mutating a shared global.
type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

impl Config {
    /// Read the environment. Every failure names the variable it is about.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(&process_env)
    }

    /// [`Config::from_env`] over any source of variables.
    fn from_lookup(env: Lookup<'_>) -> Result<Self> {
        refuse_retired(env)?;

        let public_url = required(env, var::PUBLIC_URL)?
            .trim_end_matches('/')
            .to_string();
        validate_public_url(&public_url)?;

        Ok(Self {
            database_url: required(env, "DATABASE_URL")?,
            bind: parse_var(env, var::BIND, "0.0.0.0:8080", |v| {
                v.parse::<SocketAddr>()
                    .map_err(|e| anyhow!("{e}; expected host:port, e.g. 0.0.0.0:8080"))
            })?,
            encryption_key: required(env, var::ENCRYPTION_KEY)?,
            client_ip_header: optional(env, var::CLIENT_IP_HEADER)
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty()),
            enforce_quotas: parse_var(env, var::ENFORCE_QUOTAS, "0", parse_bool)?,
            static_dir: optional(env, var::STATIC_DIR).map(|v| PathBuf::from(v.trim())),
            redirect_hosts: parse_redirect_hosts(
                optional(env, var::REDIRECT_HOSTS).as_deref(),
                &public_url,
            )?,
            run_migrations: parse_var(env, var::RUN_MIGRATIONS, "1", parse_bool)?,
            log_format: parse_var(env, var::LOG_FORMAT, "text", |v| match v {
                "json" => Ok(LogFormat::Json),
                "text" => Ok(LogFormat::Text),
                other => Err(anyhow!("expected json or text, got {other:?}")),
            })?,
            email: parse_email(optional(env, var::SMTP_URL), optional(env, var::EMAIL_FROM))?,
            stripe: parse_stripe(
                optional(env, "STRIPE_SECRET_KEY"),
                optional(env, "STRIPE_WEBHOOK_SECRET"),
            )?,
            usage_hold_threshold: parse_var(
                env,
                var::USAGE_HOLD_THRESHOLD,
                &otto_billing::usage::DEFAULT_HOLD_THRESHOLD.to_string(),
                |v| match v.parse::<i64>() {
                    Ok(n) if n >= 1 => Ok(n),
                    _ => Err(anyhow!("expected a whole number of at least 1")),
                },
            )?,
            public_url,
        })
    }
}

/// Refuse to start while any [`RETIRED`] variable is set, naming each one and
/// its replacement. Never repeats a value: some of them are secrets.
fn refuse_retired(env: Lookup<'_>) -> Result<()> {
    let set: Vec<String> = RETIRED
        .iter()
        // `is_some`, not `optional`: a set-but-empty `OTTO_X=""` is refused too,
        // on purpose. A leftover is a leftover, and the fix is the same.
        .filter(|(old, _)| env(old).is_some())
        .map(|(old, new)| format!("{old} (now {new})"))
        .collect();
    if set.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{} still set, and no longer read: the OTTO_* variables were renamed SAVVAGENT_*. \
         Set each replacement to the same value and unset the old name",
        set.join(", ")
    ))
}

/// `SAVVAGENT_SMTP_URL` and `SAVVAGENT_EMAIL_FROM`: both, or neither.
///
/// Exactly one is a boot error rather than "email off": an operator who set
/// one of a pair meant to turn email on, and a deployment that quietly does
/// not send budget alerts is the failure this file exists to prevent.
///
/// No message here repeats either value. The URL holds the SMTP password, and
/// a boot error lands in the same log aggregator as everything else.
fn parse_email(smtp_url: Option<String>, from: Option<String>) -> Result<Option<EmailConfig>> {
    let (smtp_url, from) = match (smtp_url, from) {
        (None, None) => return Ok(None),
        (Some(u), Some(f)) => (u.trim().to_string(), f.trim().to_string()),
        (Some(_), None) => {
            return Err(anyhow!(
                "SAVVAGENT_SMTP_URL is set but SAVVAGENT_EMAIL_FROM is not; set both to send \
                 notification email, or neither to disable it"
            ))
        }
        (None, Some(_)) => {
            return Err(anyhow!(
                "SAVVAGENT_EMAIL_FROM is set but SAVVAGENT_SMTP_URL is not; set both to send \
                 notification email, or neither to disable it"
            ))
        }
    };
    validate_smtp_url(&smtp_url)?;
    from.parse::<lettre::message::Mailbox>().map_err(|e| {
        anyhow!(
            "SAVVAGENT_EMAIL_FROM is not a valid mailbox ({e}); expected an address such as \
             alerts@example.com or `Name <alerts@example.com>` (value not shown)"
        )
    })?;
    Ok(Some(EmailConfig { smtp_url, from }))
}

/// `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`: both, or neither.
///
/// Exactly one is a boot error rather than "billing off", for the reason
/// [`parse_email`] gives: an operator who set one meant billing on. With only
/// the key, cards would go on file and nothing would ever confirm them; with
/// only the webhook secret, nothing could be put on file at all.
///
/// No message repeats either value.
pub fn parse_stripe(
    secret_key: Option<String>,
    webhook_secret: Option<String>,
) -> Result<Option<StripeConfig>> {
    let (key, whsec) = match (secret_key, webhook_secret) {
        (None, None) => return Ok(None),
        (Some(k), Some(w)) => (k, w),
        (Some(_), None) => {
            return Err(anyhow!(
                "STRIPE_SECRET_KEY is set but STRIPE_WEBHOOK_SECRET is not; set both to \
                 enable billing, or neither to disable it"
            ))
        }
        (None, Some(_)) => {
            return Err(anyhow!(
                "STRIPE_WEBHOOK_SECRET is set but STRIPE_SECRET_KEY is not; set both to \
                 enable billing, or neither to disable it"
            ))
        }
    };
    Ok(Some(StripeConfig {
        secret_key: parse_stripe_key(Some(key))?,
        webhook_secret: WebhookSecret::new(whsec.trim()).map_err(|_| {
            anyhow!(
                "STRIPE_WEBHOOK_SECRET is not a Stripe webhook signing secret; expected \
                 whsec_... (value not shown)"
            )
        })?,
    }))
}

/// `STRIPE_SECRET_KEY` alone, for `stripe sync`, which needs no webhook
/// secret.
pub fn parse_stripe_key(secret_key: Option<String>) -> Result<SecretKey> {
    let key = secret_key.ok_or_else(|| anyhow!("STRIPE_SECRET_KEY is required and not set"))?;
    SecretKey::new(key.trim()).map_err(|_| {
        anyhow!(
            "STRIPE_SECRET_KEY is not a Stripe secret key; expected sk_... or (restricted) \
             rk_... (value not shown)"
        )
    })
}

/// [`parse_stripe_key`] from the environment.
pub fn stripe_key_from_env() -> Result<SecretKey> {
    parse_stripe_key(optional(&process_env, "STRIPE_SECRET_KEY"))
}

fn validate_smtp_url(raw: &str) -> Result<()> {
    const SHAPE: &str = "expected smtps://user:password@host:465 or \
                         smtp://user:password@host:587?tls=required \
                         (value not shown: it holds credentials)";
    let parsed = url::Url::parse(raw)
        .map_err(|e| anyhow!("SAVVAGENT_SMTP_URL is not a URL ({e}); {SHAPE}"))?;
    if !matches!(parsed.scheme(), "smtp" | "smtps") {
        return Err(anyhow!(
            "SAVVAGENT_SMTP_URL must use the smtp or smtps scheme, got {:?}; {SHAPE}",
            parsed.scheme()
        ));
    }
    let Some(host) = parsed.host().filter(|h| !h.to_string().is_empty()) else {
        return Err(anyhow!("SAVVAGENT_SMTP_URL has no host; {SHAPE}"));
    };
    // lettre reads `smtp://` with no `tls` parameter as plaintext, and
    // `tls=opportunistic` as "plaintext if STARTTLS is not offered", which an
    // attacker on the path can arrange. Either way the AUTH that follows
    // carries the password in clear.
    let tls_required = parsed.scheme() == "smtps"
        || parsed
            .query_pairs()
            .any(|(k, v)| k == "tls" && v == "required");
    // `smtp` is not a scheme the URL standard knows, so an IPv4 host arrives
    // as an opaque `Domain` string rather than `Host::Ipv4`.
    let loopback = match host {
        url::Host::Domain(d) => {
            d.eq_ignore_ascii_case("localhost")
                || d.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    if !tls_required && !loopback {
        return Err(anyhow!(
            "SAVVAGENT_SMTP_URL would send the SMTP password unencrypted; use smtps:// or add \
             ?tls=required. {SHAPE}"
        ));
    }
    // lettre has its own opinions (the `tls` query parameter, for one); ask it
    // too, so a URL it would refuse fails here and not on the first send.
    lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(raw)
        .map_err(|_| anyhow!("SAVVAGENT_SMTP_URL is not a URL the SMTP client accepts; {SHAPE}"))?;
    Ok(())
}

/// Parsed rather than merely stored: an `SAVVAGENT_PUBLIC_URL` with no scheme
/// produces links a mail client will not linkify and a relying party id of the
/// empty string, both of which are much harder to diagnose later than a message
/// here.
fn validate_public_url(public_url: &str) -> Result<()> {
    let parsed = url::Url::parse(public_url)
        .with_context(|| format!("SAVVAGENT_PUBLIC_URL is not a URL: {public_url:?}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "SAVVAGENT_PUBLIC_URL must be http or https, got {:?}",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!("SAVVAGENT_PUBLIC_URL has no host: {public_url:?}"));
    }
    Ok(())
}

/// `SAVVAGENT_REDIRECT_HOSTS`: comma-separated bare hostnames, lowercased and
/// de-duplicated. Absent or blank means none.
///
/// Each entry must be a plain DNS name: no scheme, port, path, userinfo or
/// trailing dot, because the redirect compares it to a request's `Host` with
/// the port already removed, and an entry that could never match would leave
/// the old host being served while the operator believes it redirects. An
/// entry equal to the public URL's host is refused: it would redirect to
/// itself forever. (This server has no allowed-host list to overlap with.)
fn parse_redirect_hosts(raw: Option<&str>, public_url: &str) -> Result<Vec<String>> {
    let name = var::REDIRECT_HOSTS;
    let public_host = url::Url::parse(public_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let mut hosts: Vec<String> = Vec::new();
    for entry in raw.unwrap_or_default().split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let host = entry.to_ascii_lowercase();
        if !is_bare_hostname(&host) {
            return Err(anyhow!(
                "{name} entries are bare hostnames (no scheme, port, path or trailing dot), \
                 got {entry:?}"
            ));
        }
        if public_host.as_deref() == Some(host.as_str()) {
            return Err(anyhow!(
                "{name} entry {host:?} is the {} host: it would redirect to itself",
                var::PUBLIC_URL
            ));
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

/// A dotted DNS name of letters, digits and inner hyphens, at most 253 bytes.
fn is_bare_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn optional(env: Lookup<'_>, name: &str) -> Option<String> {
    env(name).filter(|v| !v.trim().is_empty())
}

fn required(env: Lookup<'_>, name: &str) -> Result<String> {
    optional(env, name).ok_or_else(|| anyhow!("{name} is required and not set"))
}

/// Parse an optional variable, defaulting only when it is absent.
///
/// A variable that is *present* and unparseable is an error. Falling back to
/// the default there would mean a typo in a value someone deliberately set is
/// indistinguishable from not setting it.
fn parse_var<T>(
    env: Lookup<'_>,
    name: &str,
    default: &str,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<T> {
    let raw = optional(env, name);
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
            redirect_hosts: vec![],
            run_migrations: true,
            log_format: LogFormat::Text,
            email: None,
            stripe: None,
            usage_hold_threshold: otto_billing::usage::DEFAULT_HOLD_THRESHOLD,
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
    /// `SAVVAGENT_ENFORCE_QUOTAS` reading as "off" because somebody wrote `enabled`
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
            parse_var(&|_| None, "SAVVAGENT_TEST_ABSENT_VAR_XYZ", "7", |v| Ok(
                v.parse::<u8>()?
            ))
            .unwrap(),
            7
        );
    }

    /// A lookup over a fixed set of variables, recording every name asked for.
    fn vars<'a>(
        pairs: &'a [(&'a str, &'a str)],
        asked: &'a std::cell::RefCell<Vec<String>>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            asked.borrow_mut().push(name.to_string());
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn the_configuration_is_read_from_savvagent_variables() {
        let asked = std::cell::RefCell::new(Vec::new());
        let env = [
            ("DATABASE_URL", "postgres://db"),
            ("SAVVAGENT_PUBLIC_URL", "https://savvagent.com/"),
            ("SAVVAGENT_ENCRYPTION_KEY", KEY),
            ("SAVVAGENT_BIND", "127.0.0.1:9000"),
            ("SAVVAGENT_CLIENT_IP_HEADER", "Fly-Client-IP"),
            ("SAVVAGENT_ENFORCE_QUOTAS", "yes"),
            ("SAVVAGENT_STATIC_DIR", "/srv/console"),
            ("SAVVAGENT_REDIRECT_HOSTS", "Otto.Savvagent.com"),
            ("SAVVAGENT_RUN_MIGRATIONS", "off"),
            ("SAVVAGENT_LOG_FORMAT", "json"),
            ("SAVVAGENT_SMTP_URL", "smtps://u:p@smtp.example.com:465"),
            ("SAVVAGENT_EMAIL_FROM", "alerts@example.com"),
            ("SAVVAGENT_USAGE_HOLD_THRESHOLD", "42"),
        ];
        let config = Config::from_lookup(&vars(&env, &asked)).unwrap();
        assert_eq!(config.public_url, "https://savvagent.com");
        assert_eq!(config.encryption_key, KEY);
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.client_ip_header.as_deref(), Some("fly-client-ip"));
        assert!(config.enforce_quotas);
        assert_eq!(config.static_dir, Some(PathBuf::from("/srv/console")));
        assert_eq!(config.redirect_hosts, ["otto.savvagent.com"]);
        assert!(!config.run_migrations);
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(config.email.unwrap().from, "alerts@example.com");
        assert_eq!(config.usage_hold_threshold, 42);

        // Nothing outside SAVVAGENT_*, DATABASE_URL and the Stripe pair is
        // consulted, except to refuse the retired names.
        let retired: Vec<&str> = RETIRED.iter().map(|(old, _)| *old).collect();
        for name in asked.borrow().iter() {
            assert!(
                name.starts_with("SAVVAGENT_")
                    || name == "DATABASE_URL"
                    || name.starts_with("STRIPE_")
                    || retired.contains(&name.as_str()),
                "{name} is read"
            );
        }

        // And every `var::*` constant is asked for, so a constant nothing
        // reads (a setting renamed in `var` but no longer looked up) fails
        // here. The list comes from this file's own `mod var`, so a new
        // constant cannot be left out of the check.
        let asked = asked.borrow();
        let declared = declared_vars();
        // Every `SAVVAGENT_*` name replaced an `OTTO_*` one, except the
        // settings added since the rebrand.
        let added = [var::REDIRECT_HOSTS];
        assert_eq!(declared.len(), RETIRED.len() + added.len(), "{declared:?}");
        for (_, new) in RETIRED {
            assert!(declared.iter().any(|d| d == new), "{new} is not declared");
        }
        for name in &declared {
            assert!(asked.iter().any(|a| a == name), "{name} is never read");
        }
    }

    /// The names `mod var` declares, read from this file's source.
    fn declared_vars() -> Vec<String> {
        let src = include_str!("config.rs");
        let body = src
            .split_once("pub mod var {")
            .and_then(|(_, rest)| rest.split_once("\n}"))
            .expect("config.rs has a `pub mod var` block")
            .0;
        body.lines()
            .filter_map(|line| line.trim().strip_prefix("pub const "))
            .map(|decl| {
                let value = decl.split_once('=').expect("a const has a value").1;
                value
                    .trim()
                    .trim_end_matches(';')
                    .trim_matches('"')
                    .to_string()
            })
            .collect()
    }

    /// The `[env]` table of `fly.toml`, as `KEY = "value"` lines. Anything
    /// else in the table fails loudly rather than being skipped.
    fn fly_env(src: &str) -> Vec<(String, String)> {
        let mut in_env = false;
        let mut out = Vec::new();
        for line in src.lines().map(str::trim) {
            if line.starts_with('[') {
                in_env = line == "[env]";
                continue;
            }
            if !in_env || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("not KEY = \"value\" in fly.toml [env]: {line}"));
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or_else(|| panic!("not a plain string in fly.toml [env]: {line}"));
            out.push((key.trim().to_string(), value.to_string()));
        }
        out
    }

    /// `.env.example`'s assignments: the live ones, and the commented-out
    /// examples (`# KEY=value`) separately.
    fn dotenv(src: &str) -> (Vec<(String, String)>, Vec<String>) {
        let is_key = |k: &str| {
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        };
        let (mut live, mut commented) = (Vec::new(), Vec::new());
        for line in src.lines().map(str::trim) {
            let (text, is_comment) = match line.strip_prefix('#') {
                Some(rest) => (rest.trim(), true),
                None => (line, false),
            };
            let Some((key, value)) = text.split_once('=') else {
                assert!(
                    is_comment || text.is_empty(),
                    "unparsed .env.example line: {line}"
                );
                continue;
            };
            if is_comment {
                if is_key(key) {
                    commented.push(key.to_string());
                }
            } else {
                assert!(is_key(key), "not KEY=value in .env.example: {line}");
                live.push((key.to_string(), value.to_string()));
            }
        }
        (live, commented)
    }

    /// The secrets the cutover runbook (docs/deploy/fly.md) has staged, the
    /// optional pairs included when `all` is set.
    fn staged_secrets(all: bool) -> Vec<(&'static str, &'static str)> {
        let mut secrets = vec![
            (
                "DATABASE_URL",
                "postgres://otto:pw@otto-db.flycast:5432/otto_platform",
            ),
            ("SAVVAGENT_ENCRYPTION_KEY", KEY),
        ];
        if all {
            secrets.extend([
                ("SAVVAGENT_SMTP_URL", "smtps://u:p@smtp.example.com:465"),
                ("SAVVAGENT_EMAIL_FROM", "otto <alerts@savvagent.com>"),
                ("STRIPE_SECRET_KEY", "rk_live_example"),
                ("STRIPE_WEBHOOK_SECRET", "whsec_example"),
            ]);
        }
        secrets
    }

    /// `pairs` with each secret added where `pairs` has no non-empty value.
    fn with_secrets(
        pairs: &[(String, String)],
        secrets: &[(&str, &str)],
    ) -> std::collections::HashMap<String, String> {
        let mut map: std::collections::HashMap<String, String> = pairs.iter().cloned().collect();
        for (k, v) in secrets {
            let slot = map.entry(k.to_string()).or_default();
            if slot.trim().is_empty() {
                *slot = v.to_string();
            }
        }
        map
    }

    fn repo_file(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    /// What ships in `fly.toml`, plus the secrets the runbook stages, boots:
    /// no setting the server needs went missing in the rename, and no
    /// `OTTO_*` name is left for the boot check to refuse.
    #[test]
    fn fly_toml_with_the_staged_secrets_boots() {
        let env = fly_env(&repo_file("fly.toml"));
        assert!(!env.is_empty(), "fly.toml has no [env] table");
        for (key, _) in &env {
            assert!(!key.starts_with("OTTO_"), "fly.toml [env] still sets {key}");
        }
        for (secret, _) in staged_secrets(true) {
            assert!(
                env.iter().all(|(k, _)| k != secret),
                "{secret} is a secret and belongs in `fly secrets`, not fly.toml"
            );
        }
        for all in [false, true] {
            let map = with_secrets(&env, &staged_secrets(all));
            let config = Config::from_lookup(&|name| map.get(name).cloned())
                .unwrap_or_else(|e| panic!("fly.toml does not boot (all secrets: {all}): {e:#}"));
            assert_eq!(config.public_url, "https://savvagent.com");
            assert_eq!(config.static_dir, Some(PathBuf::from("/srv/console")));
            assert_eq!(config.client_ip_header.as_deref(), Some("fly-client-ip"));
            assert_eq!(config.redirect_hosts, ["otto.savvagent.com"]);
            assert_eq!(config.log_format, LogFormat::Json);
            assert_eq!(config.email.is_some(), all);
            assert_eq!(config.stripe.is_some(), all);
        }
    }

    /// `.env.example`, copied to `.env` with the encryption key filled in,
    /// boots, and neither its live settings nor its commented-out examples
    /// name an `OTTO_*` variable.
    #[test]
    fn env_example_with_the_secrets_filled_in_boots() {
        let (live, commented) = dotenv(&repo_file(".env.example"));
        assert!(!live.is_empty(), ".env.example sets nothing");
        for key in live.iter().map(|(k, _)| k).chain(&commented) {
            assert!(!key.starts_with("OTTO_"), ".env.example still names {key}");
        }
        let map = with_secrets(&live, &staged_secrets(false));
        let config = Config::from_lookup(&|name| map.get(name).cloned())
            .unwrap_or_else(|e| panic!(".env.example does not boot: {e:#}"));
        assert_eq!(config.public_url, "http://localhost:8080");
        assert!(config.email.is_none() && config.stripe.is_none());
    }

    #[test]
    fn the_old_otto_names_are_not_read() {
        let asked = std::cell::RefCell::new(Vec::new());
        let env = [
            ("DATABASE_URL", "postgres://db"),
            ("OTTO_PUBLIC_URL", "https://otto.savvagent.com"),
            ("OTTO_ENCRYPTION_KEY", KEY),
        ];
        let err = format!(
            "{:#}",
            Config::from_lookup(&vars(&env, &asked)).unwrap_err()
        );
        assert!(!err.contains(KEY), "a value was echoed: {err}");
        assert!(
            err.contains("OTTO_PUBLIC_URL (now SAVVAGENT_PUBLIC_URL)")
                && err.contains("OTTO_ENCRYPTION_KEY (now SAVVAGENT_ENCRYPTION_KEY)"),
            "{err}"
        );
    }

    /// A leftover old name is refused even beside a complete new set, so a
    /// half-done rename (say `OTTO_SMTP_URL` left behind, booting with email
    /// silently off) cannot start.
    #[test]
    fn a_leftover_otto_variable_is_refused_by_name_even_with_the_new_set_complete() {
        for (old, new) in RETIRED {
            assert_eq!(*new, old.replacen("OTTO_", "SAVVAGENT_", 1), "{old}");
            let asked = std::cell::RefCell::new(Vec::new());
            let env = [
                ("DATABASE_URL", "postgres://db"),
                ("SAVVAGENT_PUBLIC_URL", "https://savvagent.com"),
                ("SAVVAGENT_ENCRYPTION_KEY", KEY),
                (*old, "hunter2-leftover"),
            ];
            let err = format!(
                "{:#}",
                Config::from_lookup(&vars(&env, &asked)).unwrap_err()
            );
            assert!(err.contains(old) && err.contains(new), "{err}");
            assert!(!err.contains("hunter2"), "a value was echoed: {err}");
        }
    }

    #[test]
    fn a_missing_public_url_names_the_savvagent_variable() {
        let asked = std::cell::RefCell::new(Vec::new());
        let env = [
            ("DATABASE_URL", "postgres://db"),
            ("SAVVAGENT_ENCRYPTION_KEY", KEY),
        ];
        let err = Config::from_lookup(&vars(&env, &asked))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "SAVVAGENT_PUBLIC_URL is required and not set");
    }

    const URL: &str = "smtps://mailer:hunter2-secret@smtp.example.com:465";
    const FROM: &str = "otto <alerts@example.com>";

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn email_with_both_set_is_enabled() {
        let email = parse_email(s(URL), s(FROM)).unwrap().expect("enabled");
        assert_eq!(email.smtp_url, URL);
        assert_eq!(email.from, FROM);
        for url in [
            "smtp://u:p@smtp.example.com:587?tls=required",
            "smtp://localhost:1025",
            "smtp://u:p@127.0.0.1:2525",
        ] {
            assert!(
                parse_email(s(url), s("alerts@example.com"))
                    .unwrap()
                    .is_some(),
                "{url}"
            );
        }
    }

    #[test]
    fn email_with_neither_set_is_disabled_not_an_error() {
        assert!(parse_email(None, None).unwrap().is_none());
    }

    #[test]
    fn email_with_only_one_set_is_a_boot_error_naming_the_missing_one() {
        let err = parse_email(s(URL), None).unwrap_err().to_string();
        assert!(err.contains("SAVVAGENT_EMAIL_FROM is not"), "{err}");
        let err = parse_email(None, s(FROM)).unwrap_err().to_string();
        assert!(err.contains("SAVVAGENT_SMTP_URL is not"), "{err}");
    }

    #[test]
    fn malformed_email_settings_are_errors_that_never_echo_the_secret() {
        for (url, from) in [
            ("hunter2-secret", FROM),
            ("https://mailer:hunter2-secret@smtp.example.com", FROM),
            ("smtp://mailer:hunter2-secret@", FROM),
            ("smtp://mailer:hunter2-secret@smtp.example.com:587", FROM),
            (
                "smtp://mailer:hunter2-secret@smtp.example.com:587?tls=opportunistic",
                FROM,
            ),
            ("smtp://mailer:hunter2-secret@127.0.0.1?tls=sometimes", FROM),
            (URL, "not an address hunter2-secret"),
            (URL, "alerts@"),
        ] {
            let err = format!("{:#}", parse_email(s(url), s(from)).expect_err(url));
            assert!(!err.contains("hunter2"), "secret echoed: {err}");
            assert!(!err.contains("mailer"), "username echoed: {err}");
            let names = if from == FROM {
                "SAVVAGENT_SMTP_URL"
            } else {
                "SAVVAGENT_EMAIL_FROM"
            };
            assert!(err.contains(names), "{err} should name {names}");
        }
    }

    #[test]
    fn email_config_debug_hides_both_values() {
        let email = parse_email(s(URL), s(FROM)).unwrap().unwrap();
        let shown = format!("{email:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("alerts@"),
            "{shown}"
        );
    }

    const SK: &str = "rk_live_hunter2stripekey";
    const WH: &str = "whsec_hunter2webhooksecret";

    #[test]
    fn stripe_with_both_set_is_enabled_and_with_neither_disabled() {
        let stripe = parse_stripe(s(SK), s(WH)).unwrap().expect("enabled");
        let shown = format!("{stripe:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(parse_stripe(Some(" sk_test_x ".into()), s(WH))
            .unwrap()
            .is_some());
        assert!(parse_stripe(None, None).unwrap().is_none());
    }

    #[test]
    fn stripe_with_only_one_set_is_a_boot_error_naming_the_missing_one() {
        let err = parse_stripe(s(SK), None).unwrap_err().to_string();
        assert!(err.contains("STRIPE_WEBHOOK_SECRET is not"), "{err}");
        let err = parse_stripe(None, s(WH)).unwrap_err().to_string();
        assert!(err.contains("STRIPE_SECRET_KEY is not"), "{err}");
    }

    #[test]
    fn malformed_stripe_secrets_are_errors_that_never_echo_them() {
        for (key, whsec, names) in [
            ("pk_live_hunter2publishable", WH, "STRIPE_SECRET_KEY"),
            ("hunter2", WH, "STRIPE_SECRET_KEY"),
            ("sk_live_hunter2 with space", WH, "STRIPE_SECRET_KEY"),
            (SK, "hunter2-not-a-whsec", "STRIPE_WEBHOOK_SECRET"),
            (SK, "whsec_hunter2\nnewline", "STRIPE_WEBHOOK_SECRET"),
        ] {
            let err = format!("{:#}", parse_stripe(s(key), s(whsec)).expect_err(key));
            assert!(!err.contains("hunter2"), "secret echoed: {err}");
            assert!(err.contains(names), "{err} should name {names}");
        }
        let err = parse_stripe_key(None).unwrap_err().to_string();
        assert!(err.contains("STRIPE_SECRET_KEY"), "{err}");
    }

    #[test]
    fn the_public_url_must_be_an_http_origin_with_a_host() {
        assert!(validate_public_url("https://otto.savvagent.com").is_ok());
        assert!(validate_public_url("http://localhost:8080").is_ok());
        for bad in ["otto.savvagent.com", "ftp://otto.savvagent.com", "https://"] {
            assert!(validate_public_url(bad).is_err(), "{bad} should be refused");
        }
    }

    const PUBLIC: &str = "https://savvagent.com";

    #[test]
    fn redirect_hosts_are_empty_by_default_and_read_as_a_list() {
        for raw in [None, Some(""), Some(" , ")] {
            assert!(parse_redirect_hosts(raw, PUBLIC).unwrap().is_empty());
        }
        let hosts = parse_redirect_hosts(
            Some(" Otto.Savvagent.com , ,old.example,otto.savvagent.com"),
            PUBLIC,
        )
        .unwrap();
        assert_eq!(hosts, ["otto.savvagent.com", "old.example"]);
    }

    #[test]
    fn redirect_hosts_are_bare_hostnames() {
        for bad in [
            "https://otto.savvagent.com",
            "otto.savvagent.com/path",
            "user@otto.savvagent.com",
            "otto.savvagent.com:8080",
            "otto.savvagent.com.",
            "[::1]",
            "-otto.savvagent.com",
            "otto..savvagent.com",
            "otto savvagent.com",
            "otto.savvagent.com, https://x.example",
        ] {
            let err = parse_redirect_hosts(Some(bad), PUBLIC)
                .expect_err(bad)
                .to_string();
            assert!(err.contains("SAVVAGENT_REDIRECT_HOSTS"), "{bad:?}: {err}");
            assert!(err.contains("bare hostnames"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn a_redirect_host_cannot_be_the_public_url_host() {
        for (public, raw) in [
            (PUBLIC, "savvagent.com"),
            (PUBLIC, "otto.savvagent.com,SAVVAGENT.com"),
            ("https://savvagent.example:8443", "Savvagent.example"),
        ] {
            let err = parse_redirect_hosts(Some(raw), public)
                .expect_err(raw)
                .to_string();
            assert!(err.contains("redirect to itself"), "{raw:?}: {err}");
        }
    }

    /// The same checks, end to end through the environment.
    #[test]
    fn startup_refuses_a_bad_redirect_host() {
        let base = [
            ("DATABASE_URL", "postgres://db"),
            ("SAVVAGENT_PUBLIC_URL", PUBLIC),
            ("SAVVAGENT_ENCRYPTION_KEY", KEY),
        ];
        let load = |extra: (&str, &str)| {
            let mut env = base.to_vec();
            env.push(extra);
            let asked = std::cell::RefCell::new(Vec::new());
            let loaded = Config::from_lookup(&vars(&env, &asked));
            loaded.map_err(|e| format!("{e:#}"))
        };
        let err = load(("SAVVAGENT_REDIRECT_HOSTS", "savvagent.com")).unwrap_err();
        assert!(err.contains("redirect to itself"), "{err}");
        let err = load(("SAVVAGENT_REDIRECT_HOSTS", "otto.savvagent.com:443")).unwrap_err();
        assert!(err.contains("bare hostnames"), "{err}");
        let ok = load(("SAVVAGENT_REDIRECT_HOSTS", "otto.savvagent.com")).unwrap();
        assert_eq!(ok.redirect_hosts, ["otto.savvagent.com"]);
    }
}
