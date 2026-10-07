//! A tiny local mock HTTP server for `otto-auth`'s recorded-fixture OIDC tests
//! — no live network, matching the convention of otto-factory's trackers
//! crate.
//!
//! That crate's own harness (`TestServer`/`MockResponse`) is `pub(crate)`
//! inside it, exercised only by unit tests compiled into the library itself.
//! An integration test in `crates/otto-auth/tests/` links `otto-auth` as an
//! external crate and cannot reach across that boundary, so this is
//! `otto-auth`'s own small equivalent, structured the same way, reachable from
//! `tests/oidc.rs` via `mod support;`.
//!
//! Also holds the one fixture RSA keypair every OIDC test in this crate
//! signs/verifies `id_token`s against, and the small builders
//! ([`discovery_document`], [`jwks_document`], [`sign_id_token`]) that turn
//! it into the JSON shapes `otto_auth::oidc` expects to fetch.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are read via `TestServer::requests()` by callers that need them
pub(crate) struct CapturedRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl MockResponse {
    pub(crate) fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string(),
        }
    }

    pub(crate) fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: body.into(),
        }
    }
}

#[derive(Default)]
struct State {
    responses: VecDeque<MockResponse>,
    requests: Vec<CapturedRequest>,
}

pub(crate) struct TestServer {
    pub(crate) base_url: String,
    state: Arc<Mutex<State>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl TestServer {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        let base_url = format!("http://{}", addr);
        let state = Arc::new(Mutex::new(State::default()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let state_for_task = Arc::clone(&state);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let (mut stream, _) = match accepted {
                            Ok(value) => value,
                            Err(_) => break,
                        };
                        if handle_connection(&mut stream, &state_for_task).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            base_url,
            state,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    pub(crate) fn push(&self, response: MockResponse) {
        self.state
            .lock()
            .expect("test server state")
            .responses
            .push_back(response);
    }

    #[allow(dead_code)]
    pub(crate) fn requests(&self) -> Vec<CapturedRequest> {
        self.state
            .lock()
            .expect("test server state")
            .requests
            .clone()
    }

    #[allow(dead_code)]
    pub(crate) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn handle_connection(
    stream: &mut TcpStream,
    state: &Arc<Mutex<State>>,
) -> std::io::Result<()> {
    let request = read_request(stream).await?;
    let response = {
        let mut state = state.lock().expect("test server state");
        state.requests.push(request);
        state
            .responses
            .pop_front()
            .unwrap_or_else(|| MockResponse::text(500, "test server ran out of queued responses"))
    };
    write_response(stream, response).await
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    let mut buffer = Vec::new();
    let mut header_end = None;

    while header_end.is_none() {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        header_end = find_header_end(&buffer);
    }

    let header_end = header_end.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "request ended before headers",
        )
    })?;
    let header_bytes = &buffer[..header_end];
    let mut body = buffer[header_end + 4..].to_vec();
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request missing request line",
        )
    })?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let normalized_name = name.trim().to_ascii_lowercase();
            let trimmed_value = value.trim().to_string();
            if normalized_name == "content-length" {
                content_length = trimmed_value.parse().unwrap_or(0);
            }
            headers.insert(normalized_name, trimmed_value);
        }
    }

    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request ended before body completed",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn write_response(stream: &mut TcpStream, response: MockResponse) -> std::io::Result<()> {
    let reason = reason_phrase(response.status);
    let mut bytes = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    )
    .into_bytes();

    for (name, value) in response.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(response.body.as_bytes());
    stream.write_all(&bytes).await?;
    stream.shutdown().await
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

// ---- fixture RSA keypair, generated once for these tests only. Never used
// for anything but signing/verifying a test `id_token` in-process.

pub(crate) const TEST_KID: &str = "test-signing-key-1";

const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6BuSeN0yRbnrr
b6j1UJ8Lr91NL2Cgt0Cbr10Ig5PSL4L1LHuUjqmc+h9kJdtcih/jtw24xVcRYBzD
fZ0HlTEFDVnI2XYUljvunSjs5khe1SkdM17fXPP6v1e4yA3900TsRZJupOiJMuOK
vTE9Xx8ytmcn6/JFKtKenNRB0Og9ULMvZu3v004SZJd4fpriBOI+AppjAGlwez5v
wzN5GakcZ3XHd5zC9N6UWVXypykQ7ws0NHbHobsYqSm7pm9YT25u0D+Uzrf1FoDq
J8rJ5QjR3IrANidMn1rUxYylkHUqbtbxFKQxykbhh3/vbXNJyRpKf7fCuiewnHXA
KNZ1JewhAgMBAAECggEAU0R4mtVX4ZUZUj9F2qC+wEV1AnKdhvLf6ZACTahPx3pa
3RGPM3z0MP7IhFRpry9ofM5YRweWJIHn/h1A578BFSjXso6cSzTAGNuiEQA3DrPN
VnPDGKoLz4ZMZrqtgJtLs5KkrAAG0jrEHTr4SmdEmLeKzxTO+eTkJ/k9DUTMX3z2
+urJRm5AQU93FWnnUXMUafHSr6gRBIYBjgRnTQ7Aex/+FSyW9AbrSCb7oBlOwADv
NMnTUEduL97UUdk0xqFUBwDXhJYg4U2Rftb9p5mLPEN8pMk1QGelyPdyKVC7tY/7
C4m9vHjZAMLRKXRHfRDo8omuwhqm4EK8Edb3SEp+3QKBgQDraf8nG93y/vU+73Ao
EHQIkxsHq2RWD4VS+TBfY3EOQDGkzfkfdykkoktXpulQYInIMhblCQW0MRAaqHHz
ctqWGSvk9mB6apwqOEG5S8n2GLpPm5KdiqvPJMv/JUFFXbhAqw4jiVqy+8YKUJl0
8o4VNKW7ozDOdFO4UkWU5xzGRwKBgQDKS0+jAK22L/KgxtVZ/x/2PSVV8tB053Cn
CUwWH/Sr6dQeRCVTrDXZmM/05XtXS15QO1P2YX87t20KE8+xZtACCXMc6rSrjj5y
05RvCdrIzx5viUt1W5iKifEGiy8N9GNLGLfEZu11E/K2zGDGPfROgjBeXwC2rr09
Uum2e5AmVwKBgElyfZ/XCu1IbH2hOI3XbExMkS9YYuqS1xbnFhd8sAYxMwvnE2Wk
yNpcJEOJmNtx8yrZrdjxcq0gbZTTnxHEcLxJyC8cS0eGQYjOmnrUUYONfXte32R1
olrzcQ3+spmQvu62L6gYr4qOEOCg+u/IyVmGXnrnVE/lbUVhrcHiRVD7AoGAGqEN
S6TEOS5YnwdtgFpQJ8bmykibXjg1IRfdNzBfsd2m+ZD45OnPcORnw5INyXD3alJU
/CLbb832gZQYC/8/tHTv/Ud8HvUrjUwCxxciALsbA42sLDexfdMosjbSK+EWzQTk
8+qkqXvFwIBo4M+5ADitC08wNdwMtyzZ7RaY5CMCgYEA0JnuNngLwFa0csZDAQJR
FR14Febb3z1Oha/nnVcVWF3lSyCYXO7kfh7fZYhCFVOthDovUU9WuZJ5YFaXQOxF
hlX+mooE4RiEN2pIzc1+hbP87DvpA6frTrGPLjyXGAk7/XWjbYRJ/EhfDhPB/iuD
ynzJxIA2o6yQD6H9ChWSA+8=
-----END PRIVATE KEY-----
";

/// The same key's public modulus/exponent, base64url (no padding) — the
/// shape a JWKS document carries a public RSA key in.
/// Public, by construction — the modulus half of a JWKS entry is what any
/// caller (a legitimate verifier, or an attacker attempting alg confusion)
/// already has. `pub(crate)` so `tests/oidc.rs`'s alg-confusion test can
/// reuse it as the "attacker already knows this" HMAC secret guess.
pub(crate) const TEST_RSA_N: &str = "ugbknjdMkW5662-o9VCfC6_dTS9goLdAm69dCIOT0i-C9Sx7lI6pnPofZCXbXIof47cNuMVXEWAcw32dB5UxBQ1ZyNl2FJY77p0o7OZIXtUpHTNe31zz-r9XuMgN_dNE7EWSbqToiTLjir0xPV8fMrZnJ-vyRSrSnpzUQdDoPVCzL2bt79NOEmSXeH6a4gTiPgKaYwBpcHs-b8MzeRmpHGd1x3ecwvTelFlV8qcpEO8LNDR2x6G7GKkpu6ZvWE9ubtA_lM639RaA6ifKyeUI0dyKwDYnTJ9a1MWMpZB1Km7W8RSkMcpG4Yd_721zSckaSn-3wronsJx1wCjWdSXsIQ";
const TEST_RSA_E: &str = "AQAB";

/// A discovery document pointing every endpoint at `server`'s mock routes —
/// the same shape a real IdP's `/.well-known/openid-configuration` returns.
pub(crate) fn discovery_document(base_url: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": base_url,
        "authorization_endpoint": format!("{base_url}/authorize"),
        "token_endpoint": format!("{base_url}/token"),
        "jwks_uri": format!("{base_url}/jwks"),
    })
}

/// A JWKS document containing only the fixture key above, under `TEST_KID`.
pub(crate) fn jwks_document() -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": TEST_KID,
            "alg": "RS256",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E,
        }]
    })
}

/// Signs an arbitrary claim set as an RS256 `id_token` under the fixture
/// key, with `kid` in the header — tests build the claim set themselves so
/// they can produce a wrong issuer/audience/nonce/expiry on demand.
pub(crate) fn sign_id_token(claims: &serde_json::Value) -> String {
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
        .expect("fixture RSA key parses");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    jsonwebtoken::encode(&header, claims, &key).expect("signing a fixture id_token")
}
