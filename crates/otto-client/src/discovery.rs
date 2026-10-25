//! Find the authorization server for a resource, the way an MCP client does:
//! the resource's RFC 9728 protected-resource metadata names it, and its
//! RFC 8414 metadata gives the endpoints.

use serde::Deserialize;
use url::Url;

use crate::error::{server_text, Error, Result};

pub struct Discovered {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub registration_endpoint: Url,
    /// What the authorization server says it can grant, across all its
    /// resources. Empty if it does not say.
    pub server_scopes: Vec<String>,
    /// What the resource says it supports (RFC 9728). Empty if it does not say.
    pub resource_scopes: Vec<String>,
    /// How many resources one authorization request may name: the server's
    /// `otto_authorize_resources_max`, an otto extension, or 1 if it does not
    /// say.
    pub max_resources: usize,
}

#[derive(Deserialize)]
struct ResourceMeta {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

#[derive(Deserialize)]
struct ServerMeta {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    otto_authorize_resources_max: Option<usize>,
}

/// Credentials cross the wire to these URLs, so they must be https. Plain http
/// is allowed only for a loopback host, which keeps local development and the
/// test suite working.
pub(crate) fn require_secure(u: &Url) -> Result<()> {
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if u.scheme() == "https" || (u.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(Error::Discovery(format!(
            "{u} must be https (http is allowed only for localhost)"
        )))
    }
}

pub async fn discover(http: &reqwest::Client, resource: &str) -> Result<Discovered> {
    let resource_url =
        Url::parse(resource).map_err(|_| Error::Discovery(format!("{resource:?} is not a URL")))?;
    require_secure(&resource_url)?;

    let meta: ResourceMeta = fetch_resource_meta(http, &resource_url).await?;
    // The audience a token is minted for is this exact string. If the server
    // describes itself as something else, a token would not be accepted by it.
    if meta.resource != resource {
        return Err(Error::Discovery(format!(
            "{resource} describes itself as {}, which is a different resource",
            server_text(&meta.resource)
        )));
    }
    let resource_scopes = meta.scopes_supported;
    let issuer = meta
        .authorization_servers
        .into_iter()
        .next()
        .ok_or_else(|| Error::Discovery(format!("{resource} names no authorization server")))?;
    let issuer_url = Url::parse(&issuer)
        .map_err(|_| Error::Discovery(format!("authorization server {issuer:?} is not a URL")))?;
    require_secure(&issuer_url)?;

    let well_known = join_well_known(&issuer_url, "oauth-authorization-server")?;
    let server: ServerMeta = get_json(http, &well_known).await?;
    // RFC 8414 §3.3: the metadata must name the issuer it was fetched for, or
    // it may be another server's document.
    if server.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(Error::Discovery(format!(
            "{well_known} names issuer {}, not {issuer_url}",
            server_text(&server.issuer)
        )));
    }
    let endpoint = |name: &str, value: &str| -> Result<Url> {
        let u = Url::parse(value)
            .map_err(|_| Error::Discovery(format!("{name} {value:?} is not a URL")))?;
        require_secure(&u)?;
        Ok(u)
    };
    let registration = server.registration_endpoint.ok_or_else(|| {
        Error::Discovery(format!(
            "{issuer_url} does not support dynamic client registration"
        ))
    })?;
    Ok(Discovered {
        issuer: issuer.trim_end_matches('/').to_owned(),
        authorization_endpoint: endpoint("authorization_endpoint", &server.authorization_endpoint)?,
        token_endpoint: endpoint("token_endpoint", &server.token_endpoint)?,
        registration_endpoint: endpoint("registration_endpoint", &registration)?,
        server_scopes: server.scopes_supported,
        max_resources: server.otto_authorize_resources_max.unwrap_or(1),
        resource_scopes,
    })
}

/// RFC 9728 §3: the well-known segment goes between host and path. Servers
/// that serve it only at the origin root are accepted as a fallback.
async fn fetch_resource_meta(http: &reqwest::Client, resource: &Url) -> Result<ResourceMeta> {
    let path = resource.path().trim_end_matches('/');
    if !path.is_empty() {
        let inserted = join_well_known(resource, "oauth-protected-resource")?;
        if let Ok(m) = get_json(http, &inserted).await {
            return Ok(m);
        }
    }
    let mut root = resource.clone();
    root.set_path("");
    root.set_query(None);
    get_json(http, &join_well_known(&root, "oauth-protected-resource")?).await
}

fn join_well_known(base: &Url, name: &str) -> Result<Url> {
    let path = base.path().trim_end_matches('/');
    let mut u = base.clone();
    u.set_query(None);
    u.set_path(&format!("/.well-known/{name}{path}"));
    Ok(u)
}

async fn get_json<T: for<'de> Deserialize<'de>>(http: &reqwest::Client, url: &Url) -> Result<T> {
    let resp = http
        .get(url.clone())
        .send()
        .await
        .map_err(|_| Error::Network(url.to_string()))?;
    if !resp.status().is_success() {
        return Err(Error::Discovery(format!(
            "{url} returned {}",
            resp.status()
        )));
    }
    resp.json()
        .await
        .map_err(|_| Error::Discovery(format!("{url} did not return the expected JSON")))
}
