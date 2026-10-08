//! The registry of resource servers this authorization server mints tokens
//! for (`resource_servers`, migration 0007).
//!
//! Each otto-* service is a resource server: it owns an RFC 8707 resource
//! indicator (the audience its tokens are bound to) and the scopes that mean
//! something to it. The AS used to serve exactly one audience with
//! otto-factory's scope list compiled in; now every authorize, code
//! redemption, refresh, and PAT is checked against the row for the resource it
//! names, so otto-flags can register its own scopes without otto-factory's
//! leaking into its tokens or consent screens.
//!
//! A service registers itself with [`register`], an idempotent upsert of its
//! name and scopes that it can run at every startup. Disabling a resource
//! server and issuing its introspection credential are operator actions and
//! are never touched by `register`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;
use serde::Serialize;

use crate::crypto::{self, Secret};
use crate::error::{AuthError, Result};

/// Prefix for a resource server's introspection credential.
pub const INTROSPECTION_SECRET_PREFIX: &str = "otto_rs_";

/// Prefix for the key a resource server verifies lifecycle webhooks with.
pub const WEBHOOK_SECRET_PREFIX: &str = "otto_whsec_";

/// Longest scope description accepted, in characters. A description is one
/// line on a consent screen, not documentation; a cap keeps a registry typo
/// (or a pasted README) from turning the screen into a wall of text.
pub const MAX_SCOPE_DESCRIPTION_CHARS: usize = 200;

/// What a resource server declares about itself.
#[derive(Debug, Clone, Copy)]
pub struct ResourceServerSpec<'a> {
    /// Its RFC 8707 resource indicator, e.g. `https://otto-factory.savvagent.com/mcp`.
    pub resource_uri: &'a str,
    /// Shown on the consent screen.
    pub name: &'a str,
    /// Every scope it understands.
    pub scopes: &'a [&'a str],
    /// Granted when a client asks for none. Must be a subset of `scopes`.
    pub default_scopes: &'a [&'a str],
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ResourceServer {
    pub resource_uri: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    /// Optional human-readable text for some of `scopes`, keyed by scope name,
    /// shown on the consent screen in place of the bare name. Every key is
    /// one of `scopes` (enforced by [`set_scope_descriptions`] and by a CHECK
    /// constraint). Single-language: the consent screen's own text is
    /// localized, these are shown exactly as registered.
    pub scope_descriptions: sqlx::types::Json<BTreeMap<String, String>>,
    pub disabled: bool,
    /// Where lifecycle webhooks are delivered, if configured. The signing
    /// secret is never part of this struct; see [`set_webhook`].
    pub webhook_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLS: &str = "resource_uri, name, scopes, default_scopes, scope_descriptions, disabled, \
                    webhook_url, created_at, updated_at";

impl ResourceServer {
    /// The registered description of `scope`, if it has one.
    pub fn scope_description(&self, scope: &str) -> Option<&str> {
        self.scope_descriptions.get(scope).map(String::as_str)
    }

    /// The scopes a request for `requested` on this resource server is
    /// granted: its defaults when nothing is requested, otherwise exactly what
    /// was asked for, provided every one is a scope this server defines.
    ///
    /// An unknown scope is rejected rather than dropped. Silently dropping a
    /// requested scope hands a client a token that does less than it
    /// believes, which fails later and confusingly.
    pub fn grant_scopes(&self, requested: &[String]) -> Result<Vec<String>> {
        if requested.is_empty() {
            return Ok(self.default_scopes.clone());
        }
        let mut granted: Vec<String> = Vec::with_capacity(requested.len());
        for s in requested {
            if !self.scopes.iter().any(|known| known == s) {
                return Err(AuthError::InvalidScope(format!(
                    "unknown scope {s:?} for {}; supported scopes are {}",
                    self.resource_uri,
                    self.scopes.join(" ")
                )));
            }
            if !granted.contains(s) {
                granted.push(s.clone());
            }
        }
        Ok(granted)
    }
}

/// Register a resource server, or update the name and scopes of one already
/// registered. Idempotent, so a service can call it at every startup with the
/// scopes compiled into it.
///
/// Leaves `disabled` and the introspection credential alone: re-registering
/// must never re-enable a server an operator disabled. It also keeps scope
/// descriptions (see [`set_scope_descriptions`]), dropping only those of
/// scopes the new list no longer contains, so a service that re-registers at
/// startup does not erase what an operator wrote.
pub async fn register(db: &Db, spec: ResourceServerSpec<'_>) -> Result<ResourceServer> {
    validate_resource_uri(spec.resource_uri)?;
    let name = spec.name.trim();
    if name.is_empty() {
        return Err(AuthError::InvalidRequest(
            "a resource server needs a name".into(),
        ));
    }
    let scopes = validate_scope_list("scopes", spec.scopes)?;
    if scopes.is_empty() {
        return Err(AuthError::InvalidRequest(
            "a resource server must define at least one scope".into(),
        ));
    }
    let default_scopes = validate_scope_list("default_scopes", spec.default_scopes)?;
    if let Some(stray) = default_scopes.iter().find(|d| !scopes.contains(d)) {
        return Err(AuthError::InvalidRequest(format!(
            "default scope {stray:?} is not one of the resource server's scopes"
        )));
    }

    let row = sqlx::query_as(&format!(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (resource_uri) DO UPDATE SET \
           name = EXCLUDED.name, \
           scopes = EXCLUDED.scopes, \
           default_scopes = EXCLUDED.default_scopes, \
           scope_descriptions = COALESCE(( \
             SELECT jsonb_object_agg(d.key, d.value) \
             FROM jsonb_each(resource_servers.scope_descriptions) d \
             WHERE d.key = ANY(EXCLUDED.scopes)), '{{}}'::jsonb), \
           updated_at = now() \
         RETURNING {COLS}"
    ))
    .bind(spec.resource_uri)
    .bind(name)
    .bind(&scopes)
    .bind(&default_scopes)
    .fetch_one(db.pool())
    .await?;
    Ok(row)
}

/// Replace the whole set of scope descriptions of a resource server; an empty
/// slice clears them. Replacing rather than merging keeps removal possible
/// without a second verb, and a caller that wants to change one description
/// reads [`ResourceServer::scope_descriptions`] first.
///
/// Every key must be a scope the server defines, and every description
/// non-empty after trimming, at most [`MAX_SCOPE_DESCRIPTION_CHARS`]
/// characters, and free of control characters (it is rendered on one line).
/// Markup is fine to store: the consent screen escapes it.
pub async fn set_scope_descriptions(
    db: &Db,
    resource_uri: &str,
    descriptions: &[(&str, &str)],
) -> Result<ResourceServer> {
    let rs = get(db, resource_uri).await?.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })?;
    let map = validate_scope_descriptions(&rs.scopes, descriptions)?;

    // Written against the scopes as they are now, not as read above: a
    // concurrent re-register that dropped a scope trips the CHECK instead of
    // leaving an orphan description.
    let row = sqlx::query_as(&format!(
        "UPDATE resource_servers SET scope_descriptions = $2, updated_at = now() \
         WHERE resource_uri = $1 RETURNING {COLS}"
    ))
    .bind(resource_uri)
    .bind(sqlx::types::Json(&map))
    .fetch_one(db.pool())
    .await?;
    Ok(row)
}

/// Look up a resource server that may currently be issued tokens.
///
/// An unknown resource and a disabled one are both
/// [`AuthError::InvalidTarget`] (RFC 8707 §2), and say which, because the
/// resource indicator is public and a client integrating against the AS needs
/// to know which mistake it made.
pub async fn get_active(db: &Db, resource_uri: &str) -> Result<ResourceServer> {
    let rs = get(db, resource_uri).await?.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })?;
    if rs.disabled {
        return Err(AuthError::InvalidTarget(format!(
            "{resource_uri:?} is disabled"
        )));
    }
    Ok(rs)
}

/// Look up a resource server, enabled or not.
pub async fn get(db: &Db, resource_uri: &str) -> Result<Option<ResourceServer>> {
    let row = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE resource_uri = $1"
    ))
    .bind(resource_uri)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// Every registered resource server, enabled or not, by URI.
pub async fn list(db: &Db) -> Result<Vec<ResourceServer>> {
    let rows = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers ORDER BY resource_uri"
    ))
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Enable or disable a resource server. Disabling stops new authorization
/// codes, token redemptions, refreshes, and PATs for it; tokens already
/// issued run to their expiry.
pub async fn set_disabled(db: &Db, resource_uri: &str, disabled: bool) -> Result<ResourceServer> {
    let row = sqlx::query_as(&format!(
        "UPDATE resource_servers SET disabled = $2, updated_at = now() \
         WHERE resource_uri = $1 RETURNING {COLS}"
    ))
    .bind(resource_uri)
    .bind(disabled)
    .fetch_optional(db.pool())
    .await?;
    row.ok_or_else(|| {
        AuthError::InvalidTarget(format!("{resource_uri:?} is not a registered resource"))
    })
}

/// Issue a new introspection credential for a resource server, replacing any
/// previous one. The plaintext is returned once and only its hash is stored.
pub async fn rotate_introspection_secret(db: &Db, resource_uri: &str) -> Result<String> {
    let secret = crypto::generate(INTROSPECTION_SECRET_PREFIX);
    let updated = sqlx::query(
        "UPDATE resource_servers SET introspection_secret_hash = $2, updated_at = now() \
         WHERE resource_uri = $1",
    )
    .bind(resource_uri)
    .bind(&secret.hash)
    .execute(db.pool())
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AuthError::InvalidTarget(format!(
            "{resource_uri:?} is not a registered resource"
        )));
    }
    Ok(secret.into_plaintext())
}

/// Authenticate a resource server calling the introspection endpoint.
///
/// Every failure, whether an unknown resource, no credential issued, a wrong
/// credential, or a disabled server, is the same [`AuthError::InvalidClient`],
/// so the endpoint cannot be used to probe which resources exist or hold a
/// credential.
pub async fn authenticate_introspection(
    db: &Db,
    resource_uri: &str,
    presented: &str,
) -> Result<ResourceServer> {
    let refused = || AuthError::InvalidClient("resource server authentication failed".into());

    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT introspection_secret_hash FROM resource_servers WHERE resource_uri = $1",
    )
    .bind(resource_uri)
    .fetch_optional(db.pool())
    .await?;

    let presented_hash = crypto::hash(presented.trim());
    let Some((Some(stored),)) = row else {
        return Err(refused());
    };
    if !crypto::verify(&stored, &presented_hash) {
        return Err(refused());
    }

    let rs = get(db, resource_uri).await?.ok_or_else(refused)?;
    if rs.disabled {
        return Err(refused());
    }
    Ok(rs)
}

/// Authenticate a resource server by its credential alone, for callers that
/// present `Authorization: Bearer <secret>` and so do not say who they are.
///
/// The credential is a 256-bit random value with a unique index on its hash
/// (migration 0007), so the secret identifies the server. The same single
/// refusal as [`authenticate_introspection`] covers every failure.
pub async fn authenticate_secret(db: &Db, presented: &str) -> Result<ResourceServer> {
    let hash = crypto::hash(presented.trim());
    let row: Option<ResourceServer> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM resource_servers WHERE introspection_secret_hash = $1 AND NOT disabled"
    ))
    .bind(&hash)
    .fetch_optional(db.pool())
    .await?;
    row.ok_or_else(|| AuthError::InvalidClient("resource server authentication failed".into()))
}

/// Configure (or, with `url: None`, clear) the lifecycle webhook of a resource
/// server. Setting one always issues a fresh signing secret, returned once as
/// plaintext; only its sealed form is stored. Re-running with the same URL is
/// how the secret is rotated.
///
/// The URL is admin-provisioned, so unlike the IdP URLs in [`crate::oidc`] it
/// is not run through the SSRF guard in [`crate::ssrf`], which would refuse
/// the private and loopback addresses resource servers legitimately sit on
/// (a Fly private network, a local test). It still has to be `https`, or
/// `http` on loopback, with no credentials or fragment, so a typo cannot send
/// signed event bodies over plaintext.
pub async fn set_webhook(
    db: &Db,
    cipher: &Cipher,
    resource_uri: &str,
    url: Option<&str>,
) -> Result<Option<String>> {
    let (url, secret) = match url {
        Some(u) => {
            validate_webhook_url(u)?;
            (Some(u), Some(crypto::generate(WEBHOOK_SECRET_PREFIX)))
        }
        None => (None, None),
    };
    let sealed = secret
        .as_ref()
        .map(|s| cipher.seal(s.expose().as_bytes()))
        .transpose()?;

    let updated = sqlx::query(
        "UPDATE resource_servers SET webhook_url = $2, webhook_secret_ciphertext = $3, \
                webhook_secret_nonce = $4, updated_at = now() \
         WHERE resource_uri = $1",
    )
    .bind(resource_uri)
    .bind(url)
    .bind(sealed.as_ref().map(|s| s.ciphertext.as_slice()))
    .bind(sealed.as_ref().map(|s| s.nonce.as_slice()))
    .execute(db.pool())
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AuthError::InvalidTarget(format!(
            "{resource_uri:?} is not a registered resource"
        )));
    }
    Ok(secret.map(Secret::into_plaintext))
}

fn validate_webhook_url(url: &str) -> Result<()> {
    let bad = |why: &str| AuthError::InvalidRequest(format!("webhook url {url:?} {why}"));
    let parsed = url::Url::parse(url).map_err(|_| bad("is not an absolute URL"))?;
    if parsed.fragment().is_some() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad("must not contain a fragment or credentials"));
    }
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    );
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(bad("must be https (http is allowed only on loopback)")),
    }
}

/// Every scope any enabled resource server defines, sorted and deduplicated,
/// for the AS metadata's `scopes_supported`.
pub fn all_scopes(servers: &[ResourceServer]) -> Vec<String> {
    let mut scopes: Vec<String> = servers
        .iter()
        .filter(|rs| !rs.disabled)
        .flat_map(|rs| rs.scopes.iter().cloned())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// A resource indicator must be an absolute URI without a fragment
/// (RFC 8707 §2). It must also be `https`, except on loopback for local
/// development, because it is the audience every token for it carries.
fn validate_resource_uri(uri: &str) -> Result<()> {
    let bad = |why: &str| AuthError::InvalidRequest(format!("resource_uri {uri:?} {why}"));
    let parsed = url::Url::parse(uri).map_err(|_| bad("is not an absolute URI"))?;
    if parsed.fragment().is_some() {
        return Err(bad("must not contain a fragment"));
    }
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    );
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("must be https (http is allowed only on loopback)")),
    }
    // Exact-match comparison is the whole audience check, so refuse a value
    // that would not round-trip: what a client sends must be what we stored.
    if parsed.as_str() != uri && parsed.as_str() != format!("{uri}/") {
        return Err(bad("is not in canonical form"));
    }
    Ok(())
}

fn validate_scope_descriptions(
    scopes: &[String],
    descriptions: &[(&str, &str)],
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (scope, text) in descriptions {
        if !scopes.iter().any(|s| s == scope) {
            return Err(AuthError::InvalidRequest(format!(
                "cannot describe {scope:?}: not one of the resource server's scopes ({})",
                scopes.join(" ")
            )));
        }
        let text = text.trim();
        if text.is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} is empty"
            )));
        }
        if text.chars().count() > MAX_SCOPE_DESCRIPTION_CHARS {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} is longer than {MAX_SCOPE_DESCRIPTION_CHARS} characters"
            )));
        }
        if text.chars().any(char::is_control) {
            return Err(AuthError::InvalidRequest(format!(
                "the description of {scope:?} contains control characters"
            )));
        }
        if out.insert((*scope).to_owned(), text.to_owned()).is_some() {
            return Err(AuthError::InvalidRequest(format!(
                "{scope:?} is described twice"
            )));
        }
    }
    Ok(out)
}

/// RFC 6749 §3.3 scope-token: one or more of %x21 / %x23-5B / %x5D-7E, so no
/// spaces, quotes, or backslashes. Duplicates are dropped, order kept.
fn validate_scope_list(field: &str, scopes: &[&str]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(scopes.len());
    for s in scopes {
        let ok = !s.is_empty()
            && s.bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b));
        if !ok {
            return Err(AuthError::InvalidRequest(format!(
                "{field} contains an invalid scope token {s:?}"
            )));
        }
        if !out.iter().any(|o| o == s) {
            out.push((*s).to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(scopes: &[&str], defaults: &[&str]) -> ResourceServer {
        ResourceServer {
            resource_uri: "https://svc.example/mcp".into(),
            name: "svc".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            default_scopes: defaults.iter().map(|s| s.to_string()).collect(),
            scope_descriptions: Default::default(),
            disabled: false,
            webhook_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn empty_request_gets_the_defaults() {
        let r = rs(&["read", "write"], &["read"]);
        assert_eq!(r.grant_scopes(&[]).unwrap(), vec!["read"]);
    }

    #[test]
    fn known_scopes_are_granted_once_each() {
        let r = rs(&["read", "write"], &["read"]);
        let granted = r
            .grant_scopes(&["write".into(), "read".into(), "write".into()])
            .unwrap();
        assert_eq!(granted, vec!["write", "read"]);
    }

    #[test]
    fn a_scope_from_another_resource_server_is_refused() {
        let r = rs(&["flags:read"], &["flags:read"]);
        let err = r.grant_scopes(&["jobs:write".into()]).unwrap_err();
        assert!(matches!(err, AuthError::InvalidScope(m) if m.contains("jobs:write")));
    }

    #[test]
    fn resource_uri_rules() {
        assert!(validate_resource_uri("https://otto-factory.savvagent.com/mcp").is_ok());
        assert!(validate_resource_uri("http://127.0.0.1:8080/mcp").is_ok());
        assert!(validate_resource_uri("http://localhost:8080/mcp").is_ok());

        for bad in [
            "otto-factory.savvagent.com/mcp",
            "http://otto-factory.savvagent.com/mcp",
            "https://otto-factory.savvagent.com/mcp#frag",
            "ftp://otto-factory.savvagent.com/mcp",
            "HTTPS://Otto-Factory.savvagent.com/mcp",
        ] {
            assert!(
                validate_resource_uri(bad).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn scope_token_rules() {
        assert_eq!(
            validate_scope_list("scopes", &["jobs:read", "org:admin", "jobs:read"]).unwrap(),
            vec!["jobs:read", "org:admin"]
        );
        for bad in ["", "has space", "quo\"te", "back\\slash"] {
            assert!(validate_scope_list("scopes", &[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn scope_description_rules() {
        let scopes: Vec<String> = vec!["a".into(), "b".into()];
        let ok = validate_scope_descriptions(&scopes, &[("a", "  Read things  ")]).unwrap();
        assert_eq!(ok["a"], "Read things");
        assert!(validate_scope_descriptions(&scopes, &[])
            .unwrap()
            .is_empty());

        let long = "x".repeat(MAX_SCOPE_DESCRIPTION_CHARS + 1);
        let at_cap = "x".repeat(MAX_SCOPE_DESCRIPTION_CHARS);
        assert!(validate_scope_descriptions(&scopes, &[("a", &at_cap)]).is_ok());
        for bad in [
            vec![("zzz", "unknown scope")],
            vec![("a", "   ")],
            vec![("a", long.as_str())],
            vec![("a", "two\nlines")],
            vec![("a", "one"), ("a", "two")],
        ] {
            assert!(
                matches!(
                    validate_scope_descriptions(&scopes, &bad),
                    Err(AuthError::InvalidRequest(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn all_scopes_skips_disabled_servers() {
        let mut a = rs(&["b", "a"], &[]);
        let mut b = rs(&["c", "a"], &[]);
        assert_eq!(all_scopes(&[a.clone(), b.clone()]), vec!["a", "b", "c"]);
        b.disabled = true;
        a.scopes.push("d".into());
        assert_eq!(all_scopes(&[a, b]), vec!["a", "b", "d"]);
    }
}
