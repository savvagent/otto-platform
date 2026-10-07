//! Everything a console handler needs, and the configuration it cannot infer.

use std::sync::Arc;

use otto_tenant::crypto::Cipher;
use otto_tenant::Db;

/// Deployment-dependent settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Public base URL of the console and the authorization server — the origin
    /// a browser sees (`OTTO_PUBLIC_URL`; `https://otto.savvagent.com` in
    /// production). Every link the product hands out is built from it: the
    /// OAuth issuer, the discovery document, the SSO callback, and the
    /// invitation URL an admin copies. A wrong value produces links that 404
    /// rather than links that leak — and, because it also fixes the WebAuthn
    /// relying party (see [`Config::rp_id`]), a changed host invalidates every
    /// registered passkey.
    ///
    /// There is deliberately no resource URI here. This server is the
    /// authorization server for *every* registered resource server, and which
    /// audience a token is for comes from the request and the
    /// `resource_servers` registry, not from configuration.
    pub public_url: String,

    /// The header a trusted proxy writes the client address into, lowercase,
    /// or `None` to use the peer address of the connection.
    ///
    /// **`None` by default, and it must stay `None` unless a proxy sits in
    /// front.** With no such proxy the header is whatever the caller typed, and
    /// an attacker rotating it walks straight through every per-IP throttle — a
    /// rate limiter keyed on a spoofable value is worse than no rate limiter,
    /// because it looks like one.
    ///
    /// **Which header is not a matter of taste.** Only a header the proxy
    /// *overwrites* is trustworthy. `X-Forwarded-For` is the conventional
    /// answer and the wrong one on any proxy that *appends* — Fly.io's does, so
    /// a caller sending `X-Forwarded-For: 1.2.3.4` arrives as
    /// `1.2.3.4, <real address>` and the left-most entry, the one every
    /// convention calls the client, is the one the attacker chose. There the
    /// right value is `fly-client-ip`, which the proxy writes itself and which
    /// carries exactly one address. Behind nginx or a load balancer configured
    /// to replace the header, `x-forwarded-for` is correct.
    pub client_ip_header: Option<String>,

    /// Whether the resource servers are currently enforcing hard-stop plans.
    ///
    /// **Reporting only.** Nothing in this crate gates on it: enforcement
    /// happens at the resource servers, which charge usage and refuse billable
    /// calls past the bucket. `/api/orgs/{org}/usage` echoes this value as
    /// `enforced`, and a console reporting `false` while a resource server is
    /// refusing calls is a caller reading its own dashboard and drawing the
    /// wrong conclusion about why its agent just got a `quota_exceeded` error —
    /// so it must be set to match the deployment's resource servers
    /// (`OTTO_ENFORCE_QUOTAS`).
    pub enforce_quotas: bool,
}

impl Config {
    pub fn new(public_url: impl Into<String>) -> Self {
        Self {
            public_url: public_url.into().trim_end_matches('/').to_string(),
            client_ip_header: None,
            enforce_quotas: false,
        }
    }

    /// The WebAuthn relying party id: the **host** of the public URL.
    ///
    /// Derived rather than configured separately, because the two must agree —
    /// a passkey is bound to this string, and an rp_id that is not a registrable
    /// suffix of the origin makes every ceremony fail with an error that reads
    /// like a browser bug. Deriving it means one value can be wrong instead of
    /// two, and `relying_party` refuses at startup rather than at first login.
    ///
    /// Never hard-coded: a staging deployment on another host gets its own
    /// relying party, and a passkey registered against one cannot be replayed
    /// against the other.
    ///
    /// **Changing the public URL's host invalidates every passkey ever
    /// registered.** Nothing here can soften that; it is what binding a
    /// credential to an origin means.
    pub fn rp_id(&self) -> Option<String> {
        self.public_url
            .split("://")
            .nth(1)?
            .split('/')
            .next()?
            .split(':')
            .next()
            .filter(|h| !h.is_empty())
            .map(str::to_string)
    }

    /// Join a path onto the public URL. Every link handed to a human goes
    /// through here so there is one place a trailing slash can be got wrong.
    pub fn url(&self, path: &str) -> String {
        format!("{}/{}", self.public_url, path.trim_start_matches('/'))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    /// The WebAuthn relying party.
    ///
    /// Built once at startup from `public_url`, because its `rp_id` is what
    /// every passkey is cryptographically bound to — deriving it per request
    /// would make a configuration change silently invalidate credentials
    /// instead of failing at boot.
    pub webauthn: Arc<otto_auth::passkeys::Webauthn>,
    /// Decrypts secrets at rest — currently the enterprise SSO connections'
    /// IdP client secrets. Held as an `Arc` because the key material is loaded
    /// once at startup and shared by every request.
    pub cipher: Arc<Cipher>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(
        db: Db,
        cipher: Cipher,
        webauthn: Arc<otto_auth::passkeys::Webauthn>,
        config: Config,
    ) -> Self {
        Self {
            db,
            webauthn,
            cipher: Arc::new(cipher),
            config: Arc::new(config),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No cipher.
        f.debug_struct("AppState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The client address, for rate limiting and the audit trail.
///
/// Returns `None` rather than a placeholder when nothing trustworthy is
/// available: `otto-auth`'s throttles take an `Option`, and a made-up value like
/// `"unknown"` would put every anonymous caller in one shared bucket, where the
/// first attacker to trip it locks out everybody else.
pub fn client_ip(parts: &http::request::Parts, config: &Config) -> Option<String> {
    if let Some(header) = config.client_ip_header.as_deref() {
        if let Some(value) = parts.headers.get(header) {
            // The left-most entry is the original client; everything after it
            // was appended by intermediaries. A single-address header like
            // `Fly-Client-IP` has no comma and falls through this unchanged.
            //
            // The header is caller-influenced whenever a misconfigured proxy
            // appends rather than overwrites it, so the value is parsed as an
            // `IpAddr` rather than stored verbatim — an unparseable value is
            // treated the same as a missing one, falling through to
            // `ConnectInfo` rather than letting an attacker put an arbitrary,
            // unbounded string into the audit trail.
            if let Some(ip) = value
                .to_str()
                .ok()
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            {
                return Some(ip.to_string());
            }
        }
    }

    parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder();
        for (name, value) in headers {
            b = b.header(*name, *value);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn config() -> Config {
        Config::new("https://console.test")
    }

    #[test]
    fn no_header_is_trusted_until_one_is_named() {
        let config = config();
        assert!(
            config.client_ip_header.is_none(),
            "the default must trust nothing"
        );
        assert_eq!(
            client_ip(
                &parts(&[
                    ("x-forwarded-for", "203.0.113.9"),
                    ("fly-client-ip", "203.0.113.9"),
                ]),
                &config
            ),
            None
        );
    }

    #[test]
    fn only_the_named_header_is_read() {
        let mut config = config();
        config.client_ip_header = Some("fly-client-ip".into());

        // The header the deployment named wins, and the one it did not name is
        // not a fallback: on Fly.io `X-Forwarded-For` is caller-influenced, so
        // reading it when `Fly-Client-IP` is missing would hand an attacker the
        // value on any request they can make the proxy drop it from.
        assert_eq!(
            client_ip(
                &parts(&[
                    ("x-forwarded-for", "198.51.100.7"),
                    ("fly-client-ip", "203.0.113.9"),
                ]),
                &config
            ),
            Some("203.0.113.9".into())
        );
        assert_eq!(
            client_ip(&parts(&[("x-forwarded-for", "198.51.100.7")]), &config),
            None
        );
    }

    #[test]
    fn the_left_most_forwarded_entry_is_the_client() {
        let mut config = config();
        config.client_ip_header = Some("x-forwarded-for".into());

        assert_eq!(
            client_ip(
                &parts(&[(
                    "x-forwarded-for",
                    "203.0.113.9, 70.41.3.18, 150.172.238.178"
                )]),
                &config
            ),
            Some("203.0.113.9".into())
        );
        assert_eq!(
            client_ip(&parts(&[("x-forwarded-for", "  ")]), &config),
            None
        );
        assert_eq!(client_ip(&parts(&[]), &config), None);
    }

    #[test]
    fn an_unparseable_header_value_is_not_stored() {
        let mut config = config();
        config.client_ip_header = Some("x-forwarded-for".into());

        // A misconfigured proxy that appends rather than overwrites the
        // header leaves the left-most entry caller-chosen. Garbage there
        // must never reach the audit trail as an unbounded string.
        assert_eq!(
            client_ip(
                &parts(&[("x-forwarded-for", "'; DROP TABLE audit_events; --")]),
                &config
            ),
            None
        );

        // It falls through to the real connection's address, the same as a
        // missing or empty header does, rather than trusting nothing at all.
        let mut request = http::Request::builder()
            .header("x-forwarded-for", "not-an-ip")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [198, 51, 100, 7],
                443,
            ))));
        assert_eq!(
            client_ip(&request.into_parts().0, &config),
            Some("198.51.100.7".into())
        );
    }

    #[test]
    fn urls_survive_a_trailing_slash_on_the_configured_base() {
        let config = Config::new("https://console.test/");
        assert_eq!(config.url("/verify"), "https://console.test/verify");
        assert_eq!(config.url("verify"), "https://console.test/verify");
    }
}
