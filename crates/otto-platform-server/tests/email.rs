//! Notification email delivery end to end against a real database: the
//! outbox, the delivery pass, a fake `Mailer`, and the real `SmtpMailer`
//! talking to a scripted SMTP server on loopback.

use std::sync::{Arc, Mutex};

use otto_core::notifications;
use otto_core::orgs::OrgsExt;
use otto_platform_server::email::{self, Mailer, OutgoingEmail, SendError, SmtpMailer};
use otto_platform_server::EmailConfig;
use otto_tenant::Db;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

const USER: &str = "mailer-user";
const PASSWORD: &str = "hunter2-secret";

/// Records what it is asked to send; fails every send with `fail` if set.
#[derive(Clone, Default)]
struct FakeMailer {
    sent: Arc<Mutex<Vec<OutgoingEmail>>>,
    fail: Option<SendError>,
}

impl Mailer for FakeMailer {
    async fn send(&self, email: &OutgoingEmail) -> Result<(), SendError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        self.sent.lock().unwrap().push(email.clone());
        Ok(())
    }
}

async fn queue(db: &Db, to: &str) -> Uuid {
    let org = db
        .create_org(
            &format!("o{}", &Uuid::new_v4().simple().to_string()[..8]),
            "Org",
        )
        .await
        .unwrap();
    let mut tx = db.begin(org.id).await.unwrap();
    let id = notifications::enqueue_email(
        &mut tx,
        to,
        "otto-flags spend reached 80% of its budget",
        "Your org has used $40.00 of its $50.00 budget.\nNothing has been stopped.",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    attempts: i32,
    sent: bool,
    failed: bool,
    last_error: Option<String>,
    retry_in: f64,
}

async fn row(db: &Db, id: Uuid) -> Row {
    sqlx::query_as(
        "SELECT attempts, sent_at IS NOT NULL AS sent, failed_at IS NOT NULL AS failed, \
                last_error, extract(epoch FROM next_attempt_at - now())::float8 AS retry_in \
           FROM notification_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn delivery_through_the_fake_transport_marks_the_row_sent(pool: PgPool) {
    let db = Db::from_pool(pool);
    let id = queue(&db, "owner@acme.example").await;
    let mailer = FakeMailer::default();

    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 1);

    let sent = mailer.sent.lock().unwrap().clone();
    assert_eq!(
        sent,
        vec![OutgoingEmail {
            to: "owner@acme.example".into(),
            subject: "otto-flags spend reached 80% of its budget".into(),
            body_text: "Your org has used $40.00 of its $50.00 budget.\nNothing has been stopped."
                .into(),
        }]
    );
    let r = row(&db, id).await;
    assert!(r.sent && !r.failed, "{r:?}");
    assert_eq!(r.attempts, 1);
    assert_eq!(r.last_error, None);

    // Sent is final: the next pass finds nothing.
    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 0);
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_failed_send_backs_off_and_records_the_error(pool: PgPool) {
    let db = Db::from_pool(pool);
    let id = queue(&db, "owner@acme.example").await;
    let mailer = FakeMailer {
        fail: Some(SendError::transient(
            "smtp: transient error (451): try later",
        )),
        ..FakeMailer::default()
    };

    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 1);
    let r = row(&db, id).await;
    assert!(!r.sent && !r.failed, "{r:?}");
    assert_eq!(r.attempts, 1);
    assert_eq!(
        r.last_error.as_deref(),
        Some("smtp: transient error (451): try later")
    );
    assert!(
        (5.0..=10.5).contains(&r.retry_in),
        "first retry in ~10 s: {r:?}"
    );
    // Not due again until the backoff elapses.
    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 0);

    // A second failure doubles the wait.
    sqlx::query("UPDATE notification_outbox SET next_attempt_at = now() WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await
        .unwrap();
    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert_eq!(r.attempts, 2);
    assert!(
        (15.0..=20.5).contains(&r.retry_in),
        "second retry in ~20 s: {r:?}"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_permanent_failure_is_given_up_at_once(pool: PgPool) {
    let db = Db::from_pool(pool);
    let id = queue(&db, "owner@acme.example").await;
    let mailer = FakeMailer {
        fail: Some(SendError::permanent("recipient refused by the mailer")),
        ..FakeMailer::default()
    };
    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert!(r.failed && !r.sent, "{r:?}");
}

/// How the scripted server behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Refuse it, echoing the credentials back the way a careless server might.
    RefuseAuthEchoingCredentials,
    /// Accept everything and capture the message.
    Accept,
    /// Authenticate, then refuse the recipient permanently (`550`).
    RefuseRecipient,
    /// Greet, then never answer anything: a stalled server.
    Silent,
}

/// A minimal SMTP server on loopback. Returns its port and the DATA it received.
async fn smtp_server(script: Script) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let store = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let store = store.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut lines = BufReader::new(r).lines();
                w.write_all(b"220 localhost ESMTP test\r\n").await.ok();
                while let Ok(Some(line)) = lines.next_line().await {
                    let verb = line
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    if script == Script::Silent {
                        // Hold the connection open and say nothing more.
                        std::future::pending::<()>().await;
                    }
                    let reply: String = match (verb.as_str(), script) {
                        ("RCPT", Script::RefuseRecipient) => {
                            "550 5.1.1 no such user here\r\n".into()
                        }
                        ("EHLO", _) => "250-localhost\r\n250 AUTH PLAIN LOGIN\r\n".into(),
                        ("AUTH", Script::RefuseAuthEchoingCredentials) => format!(
                            "535 5.7.8 bad credentials for smtp://{USER}:{PASSWORD}@127.0.0.1 \
                             (user {USER}, password {PASSWORD})\r\n"
                        ),
                        ("AUTH", _) => "235 2.7.0 ok\r\n".into(),
                        ("DATA", _) => {
                            w.write_all(b"354 go ahead\r\n").await.ok();
                            let mut body = String::new();
                            while let Ok(Some(l)) = lines.next_line().await {
                                if l == "." {
                                    break;
                                }
                                body.push_str(&l);
                                body.push('\n');
                            }
                            store.lock().unwrap().push(body);
                            "250 2.0.0 queued\r\n".into()
                        }
                        ("QUIT", _) => {
                            w.write_all(b"221 bye\r\n").await.ok();
                            return;
                        }
                        _ => "250 ok\r\n".into(),
                    };
                    if w.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, received)
}

fn smtp_config(port: u16) -> EmailConfig {
    EmailConfig {
        smtp_url: format!("smtp://{USER}:{PASSWORD}@127.0.0.1:{port}"),
        from: "otto <alerts@otto.example>".into(),
    }
}

fn assert_no_secrets(error: &str, port: u16) {
    for secret in [
        PASSWORD,
        USER,
        &format!("smtp://{USER}:{PASSWORD}@127.0.0.1:{port}"),
    ] {
        assert!(!error.contains(secret), "{secret:?} leaked into {error:?}");
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_failed_smtp_send_records_an_error_without_the_url_or_credentials(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (port, _) = smtp_server(Script::RefuseAuthEchoingCredentials).await;
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let id = queue(&db, "owner@acme.example").await;

    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 1);
    let r = row(&db, id).await;
    assert!(!r.sent && !r.failed, "{r:?}");
    assert_eq!(r.attempts, 1);
    let error = r.last_error.expect("an error is recorded");
    assert!(error.contains("535"), "the server's code is kept: {error}");
    // The server's echo reached the error and was scrubbed, so this test is
    // not passing merely because lettre dropped the response text.
    assert!(error.contains("<redacted>"), "{error}");
    assert_no_secrets(&error, port);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unreachable_smtp_server_records_an_error_without_the_url_or_credentials(pool: PgPool) {
    let db = Db::from_pool(pool);
    // A port nothing listens on.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let id = queue(&db, "owner@acme.example").await;

    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert_eq!(r.attempts, 1);
    assert!(!r.sent && !r.failed, "{r:?}");
    assert_no_secrets(&r.last_error.expect("an error is recorded"), port);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_smtp_mailer_sends_plain_text_and_marks_the_row_sent(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (port, received) = smtp_server(Script::Accept).await;
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let id = queue(&db, "owner@acme.example").await;

    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert!(r.sent, "{r:?}");

    let data = received.lock().unwrap().concat();
    assert!(data.contains("To: owner@acme.example"), "{data}");
    assert!(data.contains("From: otto <alerts@otto.example>"), "{data}");
    assert!(
        data.contains("Content-Type: text/plain; charset=utf-8"),
        "{data}"
    );
    assert!(data.contains("Nothing has been stopped."), "{data}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rejected_login_stays_queued_for_a_credentials_fix(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (port, _) = smtp_server(Script::RefuseAuthEchoingCredentials).await;
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let ids = [
        queue(&db, "a@acme.example").await,
        queue(&db, "b@acme.example").await,
    ];

    email::deliver_due(&db, &mailer).await.unwrap();
    for id in ids {
        let r = row(&db, id).await;
        // 535 is "permanent" to lettre, but it is about our credentials, not
        // the message: giving up would throw away every queued alert.
        assert!(!r.failed && !r.sent, "{r:?}");
        assert_eq!(r.attempts, 1);
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_permanently_refused_recipient_is_given_up_at_once(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (port, _) = smtp_server(Script::RefuseRecipient).await;
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let id = queue(&db, "gone@acme.example").await;

    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert!(r.failed && !r.sent, "{r:?}");
    assert_eq!(r.attempts, 1);
    let error = r.last_error.unwrap();
    assert!(error.contains("550"), "{error}");
    assert_no_secrets(&error, port);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_silent_server_cannot_stall_delivery(pool: PgPool) {
    let db = Db::from_pool(pool);
    let (port, _) = smtp_server(Script::Silent).await;
    let mailer = SmtpMailer::new(&smtp_config(port))
        .unwrap()
        .with_send_deadline(std::time::Duration::from_millis(500));
    let id = queue(&db, "owner@acme.example").await;

    let pass = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        email::deliver_due(&db, &mailer),
    )
    .await
    .expect("the pass hung on a silent server");
    assert_eq!(pass.unwrap(), 1);

    let r = row(&db, id).await;
    assert!(!r.sent && !r.failed, "a stall is worth retrying: {r:?}");
    assert_eq!(r.attempts, 1);
    let error = r.last_error.unwrap();
    assert!(error.contains("no complete reply"), "{error}");
    assert_no_secrets(&error, port);
}
