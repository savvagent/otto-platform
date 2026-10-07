//! Delivery of lifecycle webhooks from the outbox (`lifecycle_events` and
//! `webhook_deliveries`, migration 0011; written by `otto_core::lifecycle` in
//! the transaction that causes each event).
//!
//! [`run`] is a polling loop: claim due rows, POST each to its resource
//! server's `webhook_url` signed with that server's secret, record the result.
//! A failure is retried with exponential backoff (10 s doubling to an hour)
//! for [`otto_core::lifecycle::MAX_ATTEMPTS`] attempts, then left in the table
//! marked failed with the last error, for an operator to read.
//!
//! Delivery is at-least-once, unordered across events, and idempotent on the
//! event id in the body (`otto_resource::webhook`). Claims carry a lease, so
//! running this task in every replica is safe.
//!
//! **The URL is not run through `otto_auth::ssrf`.** That guard exists for
//! URLs an *org admin* supplies (IdP endpoints) and refuses private and
//! loopback addresses. A resource server's webhook URL is provisioned by the
//! platform operator on the CLI, and those servers sit on exactly such
//! addresses (Fly's private network, a local test). `set_webhook` still
//! requires https, or http on loopback. Redirects are not followed, so a
//! compromised resource server cannot bounce a signed delivery elsewhere.

use std::time::Duration;

use futures::future::join_all;
use otto_core::lifecycle::{self, DueDelivery};
use otto_resource::webhook;
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;
use tokio::sync::watch;

const BATCH: i64 = 20;
const POLL: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SWEEP_EVERY: Duration = Duration::from_secs(3600);
/// Finished events are kept this long so an operator can still see them.
const KEEP_DAYS: i32 = 14;

/// Build the HTTP client deliveries use.
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("otto-platform/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Run until `shutdown` flips to `true`.
pub async fn run(db: Db, cipher: Cipher, mut shutdown: watch::Receiver<bool>) {
    let http = match http_client() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "webhook delivery disabled: could not build an HTTP client");
            return;
        }
    };
    tracing::info!("webhook delivery task started");
    let mut last_sweep = tokio::time::Instant::now();

    loop {
        match deliver_due(&db, &cipher, &http).await {
            // A full batch means there is probably more waiting.
            Ok(n) if n as i64 == BATCH => continue,
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "webhook delivery pass failed"),
        }

        if last_sweep.elapsed() >= SWEEP_EVERY {
            last_sweep = tokio::time::Instant::now();
            match lifecycle::sweep(&db, KEEP_DAYS).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(events = n, "swept finished lifecycle events"),
                Err(e) => tracing::warn!(error = %e, "lifecycle sweep failed"),
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => {
                tracing::info!("webhook delivery task stopping");
                return;
            }
        }
    }
}

/// One pass: claim up to a batch of due deliveries and attempt them
/// concurrently. Returns how many were attempted.
pub async fn deliver_due(
    db: &Db,
    cipher: &Cipher,
    http: &reqwest::Client,
) -> otto_core::Result<usize> {
    let due = lifecycle::claim_due(db, BATCH).await?;
    let n = due.len();
    join_all(due.iter().map(|d| deliver_one(db, cipher, http, d))).await;
    Ok(n)
}

async fn deliver_one(db: &Db, cipher: &Cipher, http: &reqwest::Client, d: &DueDelivery) {
    let outcome = attempt(cipher, http, d).await;
    let recorded = match &outcome {
        Ok(status) => lifecycle::mark_delivered(db, d.event_id, &d.resource_uri, *status).await,
        Err((status, error)) => {
            tracing::warn!(
                event_id = %d.event_id,
                resource = %d.resource_uri,
                attempt = d.attempts + 1,
                error = %error,
                "webhook delivery failed"
            );
            match lifecycle::mark_attempt_failed(db, d, *status, error).await {
                Ok(true) => {
                    tracing::error!(
                        event_id = %d.event_id,
                        resource = %d.resource_uri,
                        "webhook delivery abandoned after the retry budget"
                    );
                    Ok(())
                }
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            }
        }
    };
    // The delivery itself already happened (or not); a failure to write that
    // down means the lease lapses and the row is retried, which the receiver's
    // idempotency absorbs.
    if let Err(e) = recorded {
        tracing::error!(event_id = %d.event_id, error = %e, "could not record a webhook delivery result");
    }
}

/// POST one delivery. `Ok(status)` on a 2xx; `Err((status, reason))` otherwise.
async fn attempt(
    cipher: &Cipher,
    http: &reqwest::Client,
    d: &DueDelivery,
) -> Result<i32, (Option<i32>, String)> {
    let fail = |reason: &str| (None, reason.to_owned());

    if d.disabled {
        return Err(fail("resource server is disabled"));
    }
    let (Some(url), Some(ciphertext), Some(nonce)) =
        (&d.webhook_url, &d.secret_ciphertext, &d.secret_nonce)
    else {
        return Err(fail("resource server has no webhook configured"));
    };
    let secret = cipher
        .open(ciphertext, nonce)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| {
            fail("cannot open the webhook signing secret (wrong OTTO_ENCRYPTION_KEY?)")
        })?;

    let body = webhook::body(d.event_id, &d.kind, d.created_at, &d.data);
    // Signed per attempt, so a retry an hour later is inside the receiver's
    // replay window.
    let signature = webhook::sign(&secret, chrono::Utc::now().timestamp(), &body);

    let res = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(webhook::SIGNATURE_HEADER, signature)
        .header("Otto-Event-Id", d.event_id.to_string())
        .header("Otto-Event-Type", &d.kind)
        .body(body)
        .send()
        .await
        .map_err(|e| fail(&format!("request failed: {}", e.without_url())))?;

    let status = res.status();
    if status.is_success() {
        Ok(i32::from(status.as_u16()))
    } else {
        Err((Some(i32::from(status.as_u16())), format!("HTTP {status}")))
    }
}
