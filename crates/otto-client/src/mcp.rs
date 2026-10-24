//! Call a resource server's MCP tools from a terminal tool: one JSON-RPC
//! `tools/call` POST with the bearer token, no session. That is all a
//! stateless MCP server (such as otto-flags) needs; a server that insists on
//! the `initialize` handshake is not supported.
//!
//! A tool result can hold a secret the person must receive and a model must
//! not. The caller names those fields up front, as JSON pointers, and they are
//! taken out of the result before it is returned: [`ToolOutput::value`] is
//! safe to print, and each secret comes back only as a [`Secret`]. Only the
//! result's `structuredContent` is kept; its `content` text, which repeats it
//! secrets included, is dropped unread unless there is no structured result.
//! No error built here contains any part of a response body beyond the
//! server's own error message, cleaned by [`server_text`].

use std::collections::BTreeMap;

use reqwest::header::{ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use serde_json::{json, Map, Value};
use url::Url;

use crate::discovery::require_secure;
use crate::error::{server_text, Error, Result};
use crate::secret::Secret;

/// Far more than any tool result; a response this large is not one.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// A tool's structured result, with the fields named as secret removed.
pub struct ToolOutput {
    value: Value,
    secrets: BTreeMap<String, Secret>,
}

impl ToolOutput {
    /// The result without its secret fields. Safe to print or log.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The secret that was at `pointer`, if the result had a string there.
    pub fn secret(&self, pointer: &str) -> Option<&Secret> {
        self.secrets.get(pointer)
    }
}

impl std::fmt::Debug for ToolOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolOutput")
            .field("value", &self.value)
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

pub(crate) async fn call_tool(
    http: &reqwest::Client,
    resource: &str,
    token: &Secret,
    tool: &str,
    arguments: Value,
    secret_fields: &[&str],
) -> Result<ToolOutput> {
    let url =
        Url::parse(resource).map_err(|_| Error::Discovery(format!("{resource:?} is not a URL")))?;
    require_secure(&url)?;
    let failed = |message: String| Error::Tool {
        tool: tool.to_owned(),
        message,
    };

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool, "arguments": arguments },
    });
    let mut resp = http
        .post(url)
        .bearer_auth(token.expose())
        .header(ACCEPT, "application/json, text/event-stream")
        .json(&body)
        .send()
        .await
        .map_err(|_| Error::Network(resource.to_owned()))?;

    match resp.status() {
        StatusCode::UNAUTHORIZED => {
            return Err(Error::LoginRequired {
                resource: resource.to_owned(),
            })
        }
        StatusCode::FORBIDDEN => {
            let challenge = resp
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            return Err(if challenge.contains("insufficient_scope") {
                Error::InsufficientScope {
                    resource: resource.to_owned(),
                    message: server_text(challenge),
                }
            } else {
                failed(format!("{resource} returned {}", StatusCode::FORBIDDEN))
            });
        }
        s if !s.is_success() => return Err(failed(format!("{resource} returned {s}"))),
        _ => {}
    }

    let event_stream = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| Error::Network(resource.to_owned()))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(failed(format!("{resource} sent too large a response")));
        }
        bytes.extend_from_slice(&chunk);
    }
    let not_json = || failed(format!("{resource} did not return a JSON-RPC response"));
    let message = if event_stream {
        response_event(&bytes).ok_or_else(not_json)?
    } else {
        serde_json::from_slice::<Value>(&bytes).map_err(|_| not_json())?
    };

    if let Some(e) = message.get("error") {
        let text = server_text(e.get("message").and_then(Value::as_str).unwrap_or("error"));
        let code = e.pointer("/data/code").and_then(Value::as_str);
        return Err(if code == Some("insufficient_scope") {
            Error::InsufficientScope {
                resource: resource.to_owned(),
                message: text,
            }
        } else {
            failed(text)
        });
    }
    let result = message.get("result").ok_or_else(not_json)?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(failed(error_text(result)));
    }

    let mut value = match result.get("structuredContent") {
        Some(v) => v.clone(),
        // A server that sends only text content: the JSON in its first item.
        None => result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .and_then(|t| serde_json::from_str(t).ok())
            .ok_or_else(|| failed("returned no structured result".into()))?,
    };
    let mut secrets = BTreeMap::new();
    for pointer in secret_fields {
        match remove_at(&mut value, pointer) {
            Some(Value::String(s)) => {
                secrets.insert((*pointer).to_owned(), Secret::new(s));
            }
            None | Some(Value::Null) => {}
            Some(_) => return Err(failed(format!("{pointer} in the result is not a string"))),
        }
    }
    Ok(ToolOutput { value, secrets })
}

/// The JSON-RPC response in an event stream: the `data` of the event that
/// carries an `id` (others are notifications).
fn response_event(bytes: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.replace("\r\n", "\n")
        .split("\n\n")
        .filter_map(|event| {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|d| d.strip_prefix(' ').unwrap_or(d))
                .collect();
            serde_json::from_str::<Value>(&data.join("\n")).ok()
        })
        .find(|v| v.get("id").is_some())
}

/// The text items of an `isError` result, cleaned.
fn error_text(result: &Value) -> String {
    let text: Vec<&str> = result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect();
    if text.is_empty() {
        "the tool reported an error".into()
    } else {
        server_text(&text.join(" "))
    }
}

/// Remove and return what `pointer` (RFC 6901) names in `value`.
fn remove_at(value: &mut Value, pointer: &str) -> Option<Value> {
    let (parent, last) = pointer.rsplit_once('/')?;
    let key = last.replace("~1", "/").replace("~0", "~");
    match value.pointer_mut(parent)? {
        Value::Object(map) => Map::remove(map, &key),
        Value::Array(items) => {
            let i: usize = key.parse().ok()?;
            (i < items.len()).then(|| items.remove(i))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_at_takes_only_the_named_field() {
        let mut v = json!({"keys": {"serverKey": "srv_x", "clientKey": "sdk_y"}, "a/b": 1});
        assert_eq!(remove_at(&mut v, "/keys/serverKey"), Some(json!("srv_x")));
        assert_eq!(remove_at(&mut v, "/a~1b"), Some(json!(1)));
        assert_eq!(remove_at(&mut v, "/keys/missing"), None);
        assert_eq!(remove_at(&mut v, ""), None);
        assert_eq!(v, json!({"keys": {"clientKey": "sdk_y"}}));
    }

    #[test]
    fn the_response_is_the_event_with_an_id() {
        let stream = b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\r\n\r\n\
                       data: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1,\"result\":{}}\r\n\r\n";
        assert_eq!(
            response_event(stream),
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        );
        assert_eq!(response_event(b"data: not json\n\n"), None);
    }
}
