//! Delivery of notification email from the outbox (`notification_outbox`,
//! migration 0018; written by `otto_core::notifications::enqueue_email` in the
//! transaction that warrants each message).
//!
//! [`run`] is a polling loop shaped like [`crate::webhooks::run`]: claim due
//! rows across every org, send each through a [`Mailer`], record the result. A
//! failure is retried with exponential backoff (10 s doubling to an hour) for
//! [`otto_core::notifications::MAX_ATTEMPTS`] attempts, then left in the table
//! marked failed with the last error, for an operator to read. Claims carry a
//! lease, so running this task in every replica is safe. Delivery is
//! at-least-once: a send that succeeds but cannot be recorded is sent again
//! after the lease lapses.
//!
//! The binary starts this only when `OTTO_SMTP_URL` and `OTTO_EMAIL_FROM` are
//! both set. Otherwise rows stay queued, never dropped, and go out once a
//! deployment configures SMTP.
//!
//! **Secrets.** The SMTP URL carries the credentials. Nothing here logs it, and
//! every error that reaches a log line or `last_error` passes through
//! [`SmtpMailer`]'s redaction first, which removes the URL, the username, and
//! the password in both their raw and percent-decoded forms.

use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::future::join_all;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use otto_core::notifications::{self, DueEmail};
use otto_tenant::Db;
use percent_encoding::percent_decode_str;
use tokio::sync::watch;

use crate::config::EmailConfig;

const BATCH: i64 = 20;
const POLL: Duration = Duration::from_secs(5);
/// Per SMTP conversation. Well inside
/// [`otto_core::notifications::CLAIM_LEASE_SECONDS`], so a slow server cannot
/// let a claimed row be claimed again mid-send.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const SWEEP_EVERY: Duration = Duration::from_secs(3600);
/// Finished rows are kept this long so an operator can still see them.
const KEEP_DAYS: i32 = 14;
/// `last_error` is for a human; a server that answers with a novel is cut short.
const MAX_ERROR_LEN: usize = 500;

/// One message as the outbox holds it: plain text, one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingEmail {
    pub to: String,
    pub subject: String,
    pub body_text: String,
}

impl From<&DueEmail> for OutgoingEmail {
    fn from(d: &DueEmail) -> Self {
        Self {
            to: d.recipient.clone(),
            subject: d.subject.clone(),
            body_text: d.body_text.clone(),
        }
    }
}

/// Why a send failed, safe to log and store: it never contains the SMTP URL
/// or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendError {
    pub message: String,
    /// Retrying cannot help (the message itself cannot be built, e.g. an
    /// address the SMTP library refuses). The row is given up on at once.
    pub permanent: bool,
}

impl SendError {
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
        }
    }

    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
        }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Something that can send one email. [`SmtpMailer`] in production; tests use
/// a fake that records what it was given.
pub trait Mailer: Send + Sync {
    fn send(&self, email: &OutgoingEmail) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// SMTP over rustls, via `lettre`'s pooled async transport.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// Strings that must never appear in an error we hand out, longest first
    /// so a password containing the username is removed whole.
    secrets: Vec<String>,
}

impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailer").finish_non_exhaustive()
    }
}

impl SmtpMailer {
    /// Build the transport. Connects lazily: nothing touches the network until
    /// the first send. Errors name the variable, never its value.
    pub fn new(config: &EmailConfig) -> Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(&config.smtp_url)
            .map_err(|_| anyhow!("OTTO_SMTP_URL is not a URL the SMTP client accepts"))?
            .timeout(Some(SMTP_TIMEOUT))
            .build();
        let from = config
            .from
            .parse::<Mailbox>()
            .map_err(|_| anyhow!("OTTO_EMAIL_FROM is not a valid mailbox"))?;
        Ok(Self {
            transport,
            from,
            secrets: secrets_of(&config.smtp_url),
        })
    }

    fn redact(&self, text: &str) -> String {
        redact(text, &self.secrets)
    }
}

impl Mailer for SmtpMailer {
    async fn send(&self, email: &OutgoingEmail) -> Result<(), SendError> {
        let to = email
            .to
            .parse::<Mailbox>()
            .map_err(|e| SendError::permanent(format!("recipient refused by the mailer: {e}")))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(email.body_text.clone())
            .map_err(|e| SendError::permanent(format!("message could not be built: {e}")))?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|e| SendError::transient(self.redact(&format!("smtp: {e}"))))
    }
}

/// The URL itself, and its userinfo raw and percent-decoded. Empty strings are
/// dropped: replacing "" would mangle every message.
fn secrets_of(smtp_url: &str) -> Vec<String> {
    let mut out = vec![smtp_url.to_string()];
    if let Ok(u) = url::Url::parse(smtp_url) {
        for raw in [u.username(), u.password().unwrap_or("")] {
            out.push(raw.to_string());
            out.push(percent_decode_str(raw).decode_utf8_lossy().into_owned());
        }
    }
    out.retain(|s| !s.is_empty());
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

fn redact(text: &str, secrets: &[String]) -> String {
    let mut text = secrets
        .iter()
        .fold(text.to_string(), |t, s| t.replace(s.as_str(), "<redacted>"));
    if text.len() > MAX_ERROR_LEN {
        let mut cut = MAX_ERROR_LEN;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push('…');
    }
    text
}

/// Run until `shutdown` flips to `true`.
pub async fn run<M: Mailer>(db: Db, mailer: M, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("email delivery task started");
    let mut last_sweep = tokio::time::Instant::now();

    loop {
        match deliver_due(&db, &mailer).await {
            // A full batch means there is probably more waiting.
            Ok(n) if n as i64 == BATCH => continue,
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "email delivery pass failed"),
        }

        if last_sweep.elapsed() >= SWEEP_EVERY {
            last_sweep = tokio::time::Instant::now();
            match notifications::sweep(&db, KEEP_DAYS).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(emails = n, "swept finished notification email"),
                Err(e) => tracing::warn!(error = %e, "notification email sweep failed"),
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => {
                tracing::info!("email delivery task stopping");
                return;
            }
        }
    }
}

/// One pass: claim up to a batch of due emails and send them concurrently.
/// Returns how many were attempted.
pub async fn deliver_due<M: Mailer>(db: &Db, mailer: &M) -> otto_core::Result<usize> {
    let due = notifications::claim_due(db, BATCH).await?;
    let n = due.len();
    join_all(due.iter().map(|d| deliver_one(db, mailer, d))).await;
    Ok(n)
}

async fn deliver_one<M: Mailer>(db: &Db, mailer: &M, d: &DueEmail) {
    // The recipient is a person's address: logged by row id and org, not by
    // address.
    let recorded = match mailer.send(&OutgoingEmail::from(d)).await {
        Ok(()) => notifications::mark_sent(db, d.id).await,
        Err(e) => {
            tracing::warn!(
                email_id = %d.id,
                org_id = %d.org_id,
                attempt = d.attempts + 1,
                error = %e,
                "notification email failed"
            );
            match notifications::mark_attempt_failed(db, d, &e.message, e.permanent).await {
                Ok(true) => {
                    tracing::error!(
                        email_id = %d.id,
                        org_id = %d.org_id,
                        "notification email abandoned"
                    );
                    Ok(())
                }
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            }
        }
    };
    // The send already happened (or not); failing to write that down lets the
    // lease lapse and the row is tried again.
    if let Err(e) = recorded {
        tracing::error!(email_id = %d.id, error = %e, "could not record a notification email result");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_removes_the_url_and_both_halves_of_the_userinfo() {
        let url = "smtps://mailer%40corp:p%40ss%2Fw0rd@smtp.example.com:465";
        let secrets = secrets_of(url);
        let leaky =
            format!("connecting to {url} as mailer@corp with p@ss/w0rd (raw p%40ss%2Fw0rd) failed");
        let clean = redact(&leaky, &secrets);
        for s in [
            "p@ss/w0rd",
            "p%40ss%2Fw0rd",
            "mailer@corp",
            "mailer%40corp",
            url,
        ] {
            assert!(!clean.contains(s), "{s} survived: {clean}");
        }
        assert!(clean.contains("failed"), "{clean}");
    }

    #[test]
    fn redaction_caps_the_length_on_a_char_boundary() {
        let long = "é".repeat(MAX_ERROR_LEN);
        let out = redact(&long, &[]);
        assert!(out.len() <= MAX_ERROR_LEN + '…'.len_utf8());
        assert!(out.ends_with('…'));
    }

    /// A runtime because the pooled transport spawns its cleanup on drop.
    #[tokio::test]
    async fn the_mailer_debug_shows_nothing() {
        let mailer = SmtpMailer::new(&EmailConfig {
            smtp_url: "smtps://u:hunter2@smtp.example.com".into(),
            from: "alerts@example.com".into(),
        })
        .unwrap();
        assert!(!format!("{mailer:?}").contains("hunter2"));
    }
}
