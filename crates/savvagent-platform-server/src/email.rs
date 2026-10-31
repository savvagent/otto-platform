//! Delivery of notification email from the outbox (`notification_outbox`,
//! migration 0018; written by `savvagent_core::notifications::enqueue_email` in the
//! transaction that warrants each message).
//!
//! [`run`] is a polling loop shaped like [`crate::webhooks::run`]: claim due
//! rows across every org, send each through a [`Mailer`], record the result. A
//! failure is retried with exponential backoff (10 s doubling to an hour) for
//! [`savvagent_core::notifications::MAX_ATTEMPTS`] attempts (about a day), then
//! left in the table marked failed with the last error, for an operator to
//! read.
//!
//! A permanent refusal is given up at once only when its enhanced status code
//! (RFC 3463) pins it on this one message: a bad recipient mailbox (`5.1.x`
//! other than the sender codes `5.1.7`/`5.1.8`), the mailbox's state
//! (`5.2.x`), its size (`5.3.4`), or its content (`5.6.x`). Everything else
//! that is permanent to the server — rejected credentials, an unauthorised
//! `SAVVAGENT_EMAIL_FROM` (`5.7.x`), a refused greeting, any code we cannot read — is
//! retried like a transient failure and logged once at `error`, because it is
//! a fault in our configuration, the same for every message, and giving up
//! would discard every queued alert on the first try. See [`verdict`].
//!
//! Claims carry a lease, so running this task in every replica is safe.
//! Delivery is **at-least-once**: a message can go out twice if the server
//! accepted it but its reply did not arrive before [`SEND_DEADLINE`] (the send
//! is recorded as a timeout and retried), or if recording the result failed
//! and the lease lapsed. For a budget alert a duplicate is the cheap failure;
//! a lost one is not.
//!
//! The binary starts this only when `SAVVAGENT_SMTP_URL` and `SAVVAGENT_EMAIL_FROM` are
//! both set. Otherwise rows stay queued, never dropped, and go out once a
//! deployment configures SMTP.
//!
//! **Secrets.** The SMTP URL carries the credentials. Nothing here logs it, and
//! every error that reaches a log line or `last_error` passes through
//! [`SmtpMailer`]'s redaction first, which removes the URL, the username, and
//! the password in both their raw and percent-decoded forms.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use percent_encoding::percent_decode_str;
use savvagent_core::notifications::{self, DueEmail, FailureRecorded};
use savvagent_tenant::Db;
use tokio::sync::watch;

use crate::config::EmailConfig;

/// Rows claimed per pass. Small on purpose: every claimed row's lease starts
/// at the claim, so the whole pass must finish inside it (asserted below).
const BATCH: i64 = 8;
/// SMTP conversations in flight at once per pass. A provider throttles a
/// burst of parallel connections long before it minds a short queue.
const CONCURRENCY: usize = 4;
const POLL: Duration = Duration::from_secs(5);
/// lettre's own timeout bounds only the TCP connect; the TLS handshake and
/// every command and reply after it are unbounded in its async transport.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole send, connect to final reply. Without it a server that accepts
/// the connection and then says nothing stalls the pass for every org, lets
/// the claim lease lapse so another replica sends the same row, and hangs
/// shutdown.
pub const SEND_DEADLINE: Duration = Duration::from_secs(30);
/// The slowest possible pass (every send hitting [`SEND_DEADLINE`], in
/// `BATCH / CONCURRENCY` waves) takes at most half of
/// [`savvagent_core::notifications::CLAIM_LEASE_SECONDS`], so no row is claimed
/// again by another replica while its send is still running. The other half
/// is for recording the results (`mark_sent` / `mark_attempt_failed`, one
/// short transaction each), which happen after a row's send and must also land
/// before its lease runs out, or the row is sent again.
const _: () = assert!(
    (BATCH as u64).div_ceil(CONCURRENCY as u64) * SEND_DEADLINE.as_secs() * 2
        <= savvagent_core::notifications::CLAIM_LEASE_SECONDS as u64
);
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

    /// Never retried: the server refused this message or recipient for good.
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
    deadline: Duration,
    /// Set once a configuration fault (see [`Verdict::ConfigFault`]) has been
    /// logged at `error`, so wrong credentials or an unauthorised sender say
    /// so loudly once rather than once per queued message. Cleared by a
    /// successful send, so a later regression is reported again.
    config_fault_reported: AtomicBool,
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
            .map_err(|_| anyhow!("SAVVAGENT_SMTP_URL is not a URL the SMTP client accepts"))?
            .timeout(Some(CONNECT_TIMEOUT))
            .build();
        let from = config
            .from
            .parse::<Mailbox>()
            .map_err(|_| anyhow!("SAVVAGENT_EMAIL_FROM is not a valid mailbox"))?;
        Ok(Self {
            transport,
            from,
            secrets: secrets_of(&config.smtp_url),
            deadline: SEND_DEADLINE,
            config_fault_reported: AtomicBool::new(false),
        })
    }

    /// Shorten the send deadline, for tests that cannot wait half a minute.
    /// Clamped to [`SEND_DEADLINE`]: a longer one would break the lease
    /// arithmetic asserted beside it.
    pub fn with_send_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline.min(SEND_DEADLINE);
        self
    }

    /// `recipient` is scrubbed from the message too: servers often echo it
    /// (`5.1.1 <owner@acme.example>: user unknown`), and this message is logged.
    fn classify(&self, e: &lettre::transport::smtp::Error, recipient: &str) -> SendError {
        let message = scrub_recipient(&self.redact(&format!("smtp: {e}")), recipient);
        let basic = e.status().map(|c| c.to_string());
        let detail = std::error::Error::source(e).map(|s| s.to_string());
        match verdict(basic.as_deref(), e.is_permanent(), detail.as_deref()) {
            Verdict::Retry => SendError::transient(message),
            Verdict::GiveUp => SendError::permanent(message),
            Verdict::ConfigFault => {
                if !self.config_fault_reported.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        error = %message,
                        "the SMTP server refused us, not the message: check SAVVAGENT_SMTP_URL \
                         (credentials) and SAVVAGENT_EMAIL_FROM (an address the provider lets us \
                         send as). Every notification email stays queued until it is fixed"
                    );
                }
                SendError::transient(message)
            }
        }
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
        match tokio::time::timeout(self.deadline, self.transport.send(message)).await {
            Ok(Ok(_)) => {
                self.config_fault_reported.store(false, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(e)) => Err(self.classify(&e, &email.to)),
            Err(_) => Err(SendError::transient(format!(
                "smtp: no complete reply within {} s",
                self.deadline.as_secs_f32()
            ))),
        }
    }
}

/// What to do about one SMTP failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Transient: try again after the backoff.
    Retry,
    /// This message can never be delivered: give the row up now.
    GiveUp,
    /// The server refused *us* (credentials, sender, policy) or said something
    /// we cannot attribute to the message. Retried, so a fix within the retry
    /// window loses nothing, and logged once at `error`.
    ConfigFault,
}

/// Decide from the basic reply code (`basic`, e.g. `"550"`), whether lettre
/// calls it permanent, and the reply text (`detail`), whose first word is the
/// RFC 3463 enhanced status code when the server sends one. Conservative:
/// only a code that pins the failure on this message gives up.
fn verdict(basic: Option<&str>, permanent: bool, detail: Option<&str>) -> Verdict {
    // RFC 4954: authentication required / too weak / failed / needs encryption.
    if matches!(basic, Some("530" | "534" | "535" | "538")) {
        return Verdict::ConfigFault;
    }
    if !permanent {
        return Verdict::Retry;
    }
    let Some((subject, detail_code)) = detail.and_then(enhanced_code) else {
        return Verdict::ConfigFault;
    };
    match (subject, detail_code) {
        // Bad sender mailbox syntax / bad sender's system address: ours.
        (1, 7 | 8) => Verdict::ConfigFault,
        // Addressing (the recipient's mailbox), mailbox status, message too
        // big for the system, message content.
        (1, _) | (2, _) | (3, 4) | (6, _) => Verdict::GiveUp,
        // 5.7.x security or policy (an unauthorised sender, relaying denied),
        // and anything else: not this message's fault, as far as we can tell.
        _ => Verdict::ConfigFault,
    }
}

/// The subject and detail of a permanent (`5.x.y`) enhanced status code that
/// opens `text`, e.g. `"5.1.1 user unknown"` gives `(1, 1)`.
fn enhanced_code(text: &str) -> Option<(u16, u16)> {
    let word = text.split_whitespace().next()?;
    let mut parts = word.split('.');
    let (class, subject, detail) = (parts.next()?, parts.next()?, parts.next()?);
    let number = |p: &str| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit());
    if class != "5" || parts.next().is_some() || !number(subject) || !number(detail) {
        return None;
    }
    Some((subject.parse().ok()?, detail.parse().ok()?))
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

/// `text` with every occurrence of `recipient` (compared ignoring ASCII case,
/// as servers may echo it lower-cased) replaced by `<recipient>`. An address
/// is a person's, and errors are logged; the row id and org identify the
/// message instead.
fn scrub_recipient(text: &str, recipient: &str) -> String {
    if recipient.is_empty() {
        return text.to_string();
    }
    // ASCII lower-casing keeps every byte offset, so a match found in the
    // lowered copies is at the same offsets in the original.
    let hay = text.to_ascii_lowercase();
    let needle = recipient.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    for (at, _) in hay.match_indices(needle.as_str()) {
        if at < rest {
            continue;
        }
        out.push_str(&text[rest..at]);
        out.push_str("<recipient>");
        rest = at + needle.len();
    }
    out.push_str(&text[rest..]);
    out
}

/// Run until `shutdown` flips to `true`.
pub async fn run<M: Mailer>(db: Db, mailer: M, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("email delivery task started");
    let mut last_sweep = tokio::time::Instant::now();

    loop {
        match deliver_due(&db, &mailer).await {
            // A full batch means there is probably more waiting.
            // Unless asked to stop: under a backlog every pass is full, and
            // the shutdown check below would never be reached.
            Ok(n) if n as i64 == BATCH && !*shutdown.borrow() => continue,
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

/// One pass: claim up to a batch of due emails and send them, at most
/// [`CONCURRENCY`] at a time. Returns how many were attempted.
pub async fn deliver_due<M: Mailer>(db: &Db, mailer: &M) -> savvagent_core::Result<usize> {
    let due = notifications::claim_due(db, BATCH).await?;
    let n = due.len();
    // Collected first: a lazy `map` adapter inside the stream trips the
    // compiler's higher-ranked `Send` inference once this is `tokio::spawn`ed.
    let sends: Vec<_> = due.iter().map(|d| deliver_one(db, mailer, d)).collect();
    futures::stream::iter(sends)
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<()>>()
        .await;
    Ok(n)
}

async fn deliver_one<M: Mailer>(db: &Db, mailer: &M, d: &DueEmail) {
    // The recipient is a person's address: logged by row id and org, never by
    // address, and scrubbed from any error text a mailer hands back.
    let recorded = match mailer.send(&OutgoingEmail::from(d)).await {
        Ok(()) => match notifications::mark_sent(db, d).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::info!(
                    email_id = %d.id,
                    org_id = %d.org_id,
                    "notification email was already finished; a lapsed claim sent it again"
                );
                Ok(())
            }
            Err(e) => Err(e),
        },
        Err(e) => {
            let error = scrub_recipient(&e.message, &d.recipient);
            tracing::warn!(
                email_id = %d.id,
                org_id = %d.org_id,
                attempt = d.attempts + 1,
                error = %error,
                "notification email failed"
            );
            match notifications::mark_attempt_failed(db, d, &error, e.permanent).await {
                Ok(FailureRecorded::GaveUp) => {
                    tracing::error!(
                        email_id = %d.id,
                        org_id = %d.org_id,
                        "notification email abandoned"
                    );
                    Ok(())
                }
                Ok(FailureRecorded::Retrying) => Ok(()),
                Ok(FailureRecorded::Superseded) => {
                    tracing::warn!(
                        email_id = %d.id,
                        org_id = %d.org_id,
                        "notification email failure not recorded: the claim lapsed and \
                         another delivery task holds the row"
                    );
                    Ok(())
                }
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
    fn only_codes_that_blame_the_message_give_up() {
        use Verdict::*;
        for (basic, permanent, detail, want) in [
            (Some("550"), true, Some("5.1.1 <x@y>: user unknown"), GiveUp),
            (Some("550"), true, Some("5.1.10 null MX"), GiveUp),
            (Some("552"), true, Some("5.2.2 mailbox full"), GiveUp),
            (Some("552"), true, Some("5.3.4 message too big"), GiveUp),
            (Some("554"), true, Some("5.6.0 content rejected"), GiveUp),
            (
                Some("553"),
                true,
                Some("5.7.1 sender not authorised"),
                ConfigFault,
            ),
            (
                Some("550"),
                true,
                Some("5.7.1 relaying denied"),
                ConfigFault,
            ),
            (
                Some("553"),
                true,
                Some("5.1.7 bad sender address syntax"),
                ConfigFault,
            ),
            (
                Some("550"),
                true,
                Some("5.1.8 bad sender system"),
                ConfigFault,
            ),
            (
                Some("535"),
                true,
                Some("5.7.8 bad credentials"),
                ConfigFault,
            ),
            (
                Some("530"),
                true,
                Some("authentication required"),
                ConfigFault,
            ),
            (Some("554"), true, Some("no SMTP service here"), ConfigFault),
            (Some("550"), true, Some("no such user"), ConfigFault),
            (Some("550"), true, None, ConfigFault),
            (Some("550"), true, Some("5.5.1 bad command"), ConfigFault),
            (
                Some("550"),
                true,
                Some("4.1.1 confused server"),
                ConfigFault,
            ),
            (Some("451"), false, Some("4.3.0 try later"), Retry),
            (None, false, None, Retry),
        ] {
            assert_eq!(
                verdict(basic, permanent, detail),
                want,
                "{basic:?} {detail:?}"
            );
        }
    }

    #[test]
    fn the_recipient_is_scrubbed_in_any_ascii_case() {
        assert_eq!(
            scrub_recipient(
                "smtp: 550 5.1.1 <Owner@Acme.Example>: user unknown; owner@acme.example",
                "owner@acme.example"
            ),
            "smtp: 550 5.1.1 <<recipient>>: user unknown; <recipient>"
        );
        assert_eq!(
            scrub_recipient("josé@x.de bounced", "josé@x.de"),
            "<recipient> bounced"
        );
        assert_eq!(scrub_recipient("nothing here", "a@b.c"), "nothing here");
        assert_eq!(scrub_recipient("unchanged", ""), "unchanged");
    }

    #[test]
    fn enhanced_codes_are_read_strictly() {
        assert_eq!(enhanced_code("5.1.1 user unknown"), Some((1, 1)));
        assert_eq!(enhanced_code("5.7.1"), Some((7, 1)));
        for not in [
            "",
            "user 5.1.1",
            "5.1",
            "5.1.1.1 x",
            "5.a.1 x",
            "4.1.1 x",
            "5.1.1234 x",
        ] {
            assert_eq!(enhanced_code(not), None, "{not:?}");
        }
    }

    #[test]
    fn the_send_deadline_can_only_be_shortened() {
        let config = EmailConfig {
            smtp_url: "smtp://localhost:1025".into(),
            from: "alerts@example.com".into(),
        };
        let longer = SmtpMailer::new(&config)
            .unwrap()
            .with_send_deadline(SEND_DEADLINE * 10);
        assert_eq!(longer.deadline, SEND_DEADLINE);
        let shorter = SmtpMailer::new(&config)
            .unwrap()
            .with_send_deadline(Duration::from_millis(5));
        assert_eq!(shorter.deadline, Duration::from_millis(5));
    }

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
