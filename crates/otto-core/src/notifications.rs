//! The email notifications outbox (`notification_outbox`, migration 0018).
//!
//! [`enqueue_email`] is called from inside the tenant transaction whose change
//! deserves a message (a budget crossing a threshold, say), so the row and the
//! change commit or abort together: a rolled-back transaction sends nothing,
//! and a crash after commit cannot lose the message. Sending is not this
//! crate's concern — it knows nothing about SMTP. The claim/mark functions
//! below are the SQL a delivery task needs, and `otto-platform-server` owns the
//! task (`email::run`), as it does for [`crate::lifecycle`].
//!
//! Enqueueing is one `INSERT` and is meant to be cheap enough for a hot path
//! such as usage ingest. It fails only on input the caller chose (an address
//! that is not one, a subject with a line break) or on a genuine database
//! error. Whether SMTP is configured, reachable, or accepting mail never
//! affects it: with email disabled the rows simply wait.
//!
//! ```no_run
//! # async fn example(db: &otto_tenant::Db, org: otto_tenant::ids::OrgId) -> otto_core::Result<()> {
//! let mut tx = db.begin(org).await?;
//! // ... the change that warrants a message ...
//! otto_core::notifications::enqueue_email(
//!     &mut tx,
//!     "owner@acme.example",
//!     "otto-flags spend reached 80% of its budget",
//!     "Your org has used $40.00 of its $50.00 otto-flags budget this month.",
//! )
//! .await?;
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```

use otto_tenant::{Db, Tx, Unpinned};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Send attempts before a row is given up on and marked failed. With
/// [`crate::lifecycle::backoff_seconds`] (10 s doubling to an hour) the 31
/// waits between the 32 attempts add up to 84 310 s, about 23.4 hours: a
/// provider outage or a credentials fix within a day loses nothing.
/// `retry_window_is_about_a_day` computes it from the constants.
pub const MAX_ATTEMPTS: i32 = 32;

/// How long a claimed row is invisible to other delivery tasks. Comfortably
/// longer than the delivery task's SMTP timeout, so a slow send is not picked
/// up twice, short enough that a replica that died mid-send is covered soon.
pub const CLAIM_LEASE_SECONDS: i64 = 120;

/// RFC 5321's limit on a forward path. Also the migration's check constraint.
const MAX_RECIPIENT_LEN: usize = 254;
/// RFC 5322's line limit, which a one-line header must fit within even before
/// folding.
const MAX_SUBJECT_LEN: usize = 998;
/// Notification bodies are a few sentences. A cap keeps a bug that pastes a
/// whole report into one from filling the outbox.
const MAX_BODY_LEN: usize = 64 * 1024;

/// Queue a plain-text email to `recipient` in `tx`'s org. The caller commits.
///
/// Returns the row id. The recipient is validated here (see
/// [`validate_recipient`]) so a malformed address is refused at the call site
/// that produced it, not discovered hours later as a failed send.
pub async fn enqueue_email(
    tx: &mut Tx<'_>,
    recipient: &str,
    subject: &str,
    body_text: &str,
) -> Result<Uuid> {
    let recipient = recipient.trim();
    validate_recipient(recipient)?;
    validate_subject(subject)?;
    if body_text.len() > MAX_BODY_LEN {
        return Err(Error::Invalid(format!(
            "email body is {} bytes; the limit is {MAX_BODY_LEN}",
            body_text.len()
        )));
    }

    // Minted here rather than with RETURNING, following `lifecycle::enqueue`:
    // it keeps the statement a pure append.
    let id = Uuid::new_v4();
    let org = tx.org();
    sqlx::query(
        "INSERT INTO notification_outbox (id, org_id, recipient, subject, body_text) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(org.as_uuid())
    .bind(recipient)
    .bind(subject)
    .bind(body_text)
    .execute(tx.conn())
    .await?;
    Ok(id)
}

/// Whether `addr` is a deliverable `local@domain` address.
///
/// Deliberately narrower than RFC 5322: no display name, no quoted local part,
/// no comments, no address literals, and the domain must have at least one
/// dot. Every address this platform holds came from a sign-in or an invite, so
/// the narrow form loses nothing real and refuses everything that could smuggle
/// a second header or recipient into the message.
pub fn validate_recipient(addr: &str) -> Result<()> {
    let invalid = |why: &str| {
        Err(Error::Invalid(format!(
            "{addr:?} is not an email address: {why}"
        )))
    };

    if addr.len() < 3 || addr.len() > MAX_RECIPIENT_LEN {
        return invalid("it must be 3 to 254 characters");
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return invalid("it has no @");
    };
    if domain.contains('@') {
        return invalid("it has more than one @");
    }

    if local.is_empty() || local.len() > 64 {
        return invalid("the part before the @ must be 1 to 64 characters");
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return invalid("the part before the @ has a misplaced dot");
    }
    if !local.chars().all(is_local_char) {
        return invalid("the part before the @ has a character addresses cannot contain");
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return invalid("the domain has no dot");
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return invalid("the domain has an empty or overlong label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return invalid("a domain label starts or ends with a hyphen");
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return invalid("the domain has a character domains cannot contain");
        }
    }
    Ok(())
}

/// RFC 5322 `atext` plus the dot, and non-ASCII letters (RFC 6531). Excludes
/// whitespace, controls, and every special that means something in a header.
fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || "!#$%&'*+-/=?^_`{|}~.".contains(c)
        || (!c.is_ascii() && c.is_alphanumeric())
}

fn validate_subject(subject: &str) -> Result<()> {
    if subject.trim().is_empty() {
        return Err(Error::Invalid("email subject is empty".into()));
    }
    if subject.len() > MAX_SUBJECT_LEN {
        return Err(Error::Invalid(format!(
            "email subject is {} bytes; the limit is {MAX_SUBJECT_LEN}",
            subject.len()
        )));
    }
    if subject.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "email subject must be one line with no control characters".into(),
        ));
    }
    Ok(())
}

/// One queued email a delivery task should attempt.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DueEmail {
    pub id: Uuid,
    pub org_id: Uuid,
    pub recipient: String,
    pub subject: String,
    pub body_text: String,
    /// Attempts made before this one.
    pub attempts: i32,
}

/// An unpinned transaction opted in to the outbox's delivery policy
/// (migration 0018), which is what lets the delivery task see every org's rows
/// where the connecting role is subject to row-level security.
async fn delivery_tx(db: &Db) -> Result<Unpinned> {
    let mut tx = db.begin_unpinned().await?;
    sqlx::query("SELECT set_config('app.notification_delivery', 'on', true)")
        .execute(tx.conn())
        .await?;
    Ok(tx)
}

/// Claim up to `limit` due emails for this task, across every org.
///
/// Claiming pushes `next_attempt_at` out by [`CLAIM_LEASE_SECONDS`] in the
/// same statement that selects the rows (`FOR UPDATE SKIP LOCKED`), so several
/// replicas can run a delivery task against one table without ever sending the
/// same row twice at once. A task that dies after claiming lets the lease
/// lapse and the row becomes due again.
pub async fn claim_due(db: &Db, limit: i64) -> Result<Vec<DueEmail>> {
    let mut tx = delivery_tx(db).await?;
    let rows = sqlx::query_as(
        "WITH due AS ( \
           SELECT id FROM notification_outbox \
            WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now() \
            ORDER BY next_attempt_at \
            LIMIT $1 \
            FOR UPDATE SKIP LOCKED \
         ) \
         UPDATE notification_outbox n \
            SET next_attempt_at = now() + make_interval(secs => $2) \
           FROM due \
          WHERE n.id = due.id \
         RETURNING n.id, n.org_id, n.recipient, n.subject, n.body_text, n.attempts",
    )
    .bind(limit)
    .bind(CLAIM_LEASE_SECONDS as f64)
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Record a successful send.
pub async fn mark_sent(db: &Db, id: Uuid) -> Result<()> {
    let mut tx = delivery_tx(db).await?;
    sqlx::query(
        "UPDATE notification_outbox \
            SET sent_at = now(), attempts = attempts + 1, last_error = NULL \
          WHERE id = $1 AND sent_at IS NULL AND failed_at IS NULL",
    )
    .bind(id)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record a failed attempt and schedule the retry, or give up when
/// [`MAX_ATTEMPTS`] is spent or the failure is `permanent` (the server refused
/// this recipient or message for good, e.g. `550 no such user`; asking again
/// will not change its mind). A failure that is about the sender rather than
/// the message, such as rejected SMTP credentials, must not be `permanent`:
/// it would discard every queued email instead of waiting for the fix.
///
/// A row already sent or given up on is left alone.
///
/// `error` is stored as given and shown to operators: the caller is
/// responsible for it holding no secret. Returns `true` if the row was given
/// up on.
pub async fn mark_attempt_failed(
    db: &Db,
    email: &DueEmail,
    error: &str,
    permanent: bool,
) -> Result<bool> {
    let attempts = email.attempts + 1;
    let gave_up = permanent || attempts >= MAX_ATTEMPTS;
    let mut tx = delivery_tx(db).await?;
    sqlx::query(
        "UPDATE notification_outbox \
            SET attempts = $2, \
                last_error = $3, \
                next_attempt_at = now() + make_interval(secs => $4), \
                failed_at = CASE WHEN $5 THEN now() END \
          WHERE id = $1 AND sent_at IS NULL AND failed_at IS NULL",
    )
    .bind(email.id)
    .bind(attempts)
    .bind(error)
    .bind(crate::lifecycle::backoff_seconds(attempts) as f64)
    .bind(gave_up)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(gave_up)
}

/// Delete sent and failed rows older than `keep_days`. Queued rows are never
/// swept, however old: with email disabled they are waiting, not abandoned.
pub async fn sweep(db: &Db, keep_days: i32) -> Result<u64> {
    let mut tx = delivery_tx(db).await?;
    let n = sqlx::query(
        "DELETE FROM notification_outbox \
          WHERE created_at < now() - make_interval(days => $1) \
            AND (sent_at IS NOT NULL OR failed_at IS NOT NULL)",
    )
    .bind(keep_days)
    .execute(tx.conn())
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_window_is_about_a_day() {
        let window: i64 = (1..MAX_ATTEMPTS)
            .map(crate::lifecycle::backoff_seconds)
            .sum();
        assert_eq!(window, 84_310, "update MAX_ATTEMPTS' doc comment");
        assert!((20 * 3600..=26 * 3600).contains(&window), "{window} s");
    }

    #[test]
    fn ordinary_addresses_are_accepted() {
        for ok in [
            "owner@acme.example",
            "first.last+alerts@mail.acme.co.uk",
            "o'brien@example.com",
            "x@a-b.io",
            "josé@exämple.de",
        ] {
            assert!(validate_recipient(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn anything_that_could_smuggle_a_header_or_recipient_is_refused() {
        for bad in [
            "",
            "no-at-sign",
            "@acme.example",
            "owner@",
            "owner@localhost",
            "a@b@acme.example",
            "owner@acme..example",
            ".owner@acme.example",
            "own..er@acme.example",
            "owner@-acme.example",
            "Owner <owner@acme.example>",
            "owner@acme.example, other@evil.example",
            "owner@acme.example\r\nBcc: other@evil.example",
            "own er@acme.example",
            "\"quoted\"@acme.example",
            "owner@[127.0.0.1]",
        ] {
            assert!(
                validate_recipient(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
        let long = format!("{}@acme.example", "a".repeat(65));
        assert!(validate_recipient(&long).is_err());
    }

    #[test]
    fn subjects_are_one_nonempty_line() {
        assert!(validate_subject("Budget at 80%").is_ok());
        for bad in ["", "   ", "two\nlines", "carriage\rreturn", "tab\there"] {
            assert!(validate_subject(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_subject(&"s".repeat(MAX_SUBJECT_LEN + 1)).is_err());
    }
}
