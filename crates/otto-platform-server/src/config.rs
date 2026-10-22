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
use otto_billing::stripe::{SecretKey, WebhookSecret};

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

    /// The built console bundle (`OTTO_STATIC_DIR`): prerendered pages as
    /// themselves and the SPA shell, `200.html`, for every other client route.
    /// The bundle must contain `200.html`; `app` refuses to build without it.
    /// The hosted deployment sets it (`fly.toml`);
    /// `None` serves no console at all, for a deployment that puts the optional
    /// Worker in `web/worker/` in front instead.
    pub static_dir: Option<PathBuf>,

    pub run_migrations: bool,
    pub log_format: LogFormat,

    /// Outgoing notification email (`OTTO_SMTP_URL` and `OTTO_EMAIL_FROM`,
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

    /// `OTTO_USAGE_HOLD_THRESHOLD`: the most of one meter an org may accrue in
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
            email: parse_email(optional("OTTO_SMTP_URL"), optional("OTTO_EMAIL_FROM"))?,
            stripe: parse_stripe(
                optional("STRIPE_SECRET_KEY"),
                optional("STRIPE_WEBHOOK_SECRET"),
            )?,
            usage_hold_threshold: parse_var(
                "OTTO_USAGE_HOLD_THRESHOLD",
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

/// `OTTO_SMTP_URL` and `OTTO_EMAIL_FROM`: both, or neither.
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
                "OTTO_SMTP_URL is set but OTTO_EMAIL_FROM is not; set both to send \
                 notification email, or neither to disable it"
            ))
        }
        (None, Some(_)) => {
            return Err(anyhow!(
                "OTTO_EMAIL_FROM is set but OTTO_SMTP_URL is not; set both to send \
                 notification email, or neither to disable it"
            ))
        }
    };
    validate_smtp_url(&smtp_url)?;
    from.parse::<lettre::message::Mailbox>().map_err(|e| {
        anyhow!(
            "OTTO_EMAIL_FROM is not a valid mailbox ({e}); expected an address such as \
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
    parse_stripe_key(optional("STRIPE_SECRET_KEY"))
}

fn validate_smtp_url(raw: &str) -> Result<()> {
    const SHAPE: &str = "expected smtps://user:password@host:465 or \
                         smtp://user:password@host:587?tls=required \
                         (value not shown: it holds credentials)";
    let parsed =
        url::Url::parse(raw).map_err(|e| anyhow!("OTTO_SMTP_URL is not a URL ({e}); {SHAPE}"))?;
    if !matches!(parsed.scheme(), "smtp" | "smtps") {
        return Err(anyhow!(
            "OTTO_SMTP_URL must use the smtp or smtps scheme, got {:?}; {SHAPE}",
            parsed.scheme()
        ));
    }
    let Some(host) = parsed.host().filter(|h| !h.to_string().is_empty()) else {
        return Err(anyhow!("OTTO_SMTP_URL has no host; {SHAPE}"));
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
            "OTTO_SMTP_URL would send the SMTP password unencrypted; use smtps:// or add \
             ?tls=required. {SHAPE}"
        ));
    }
    // lettre has its own opinions (the `tls` query parameter, for one); ask it
    // too, so a URL it would refuse fails here and not on the first send.
    lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(raw)
        .map_err(|_| anyhow!("OTTO_SMTP_URL is not a URL the SMTP client accepts; {SHAPE}"))?;
    Ok(())
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
        assert!(err.contains("OTTO_EMAIL_FROM is not"), "{err}");
        let err = parse_email(None, s(FROM)).unwrap_err().to_string();
        assert!(err.contains("OTTO_SMTP_URL is not"), "{err}");
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
                "OTTO_SMTP_URL"
            } else {
                "OTTO_EMAIL_FROM"
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
}
