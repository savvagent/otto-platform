//! Notification email delivery end to end against a real database: the
//! outbox, the delivery pass, a fake `Mailer`, and the real `SmtpMailer`
//! talking to a scripted SMTP server on loopback.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// A server that echoes the recipient in its refusal (most do) must not get
/// the address into the logged and stored error.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_refusal_echoing_the_recipient_is_recorded_without_it(pool: PgPool) {
    let db = Db::from_pool(pool);
    let id = queue(&db, "Owner@Acme.Example").await;
    let mailer = FakeMailer {
        fail: Some(SendError::permanent(
            "smtp: permanent error (550): 5.1.1 <owner@acme.example>: user unknown",
        )),
        ..FakeMailer::default()
    };
    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert!(r.failed, "{r:?}");
    let error = r.last_error.unwrap();
    assert_eq!(
        error,
        "smtp: permanent error (550): 5.1.1 <<recipient>>: user unknown"
    );
}

/// How the scripted server behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Refuse it, echoing the credentials back the way a careless server might.
    RefuseAuthEchoingCredentials,
    /// Accept everything and capture the message.
    Accept,
    /// Authenticate, then answer RCPT TO with this reply.
    RefuseRecipient(&'static str),
    /// Authenticate, then answer MAIL FROM with this reply.
    RefuseSender(&'static str),
    /// Refuse service in the greeting itself.
    RefuseGreeting,
    /// Greet, then never answer anything: a stalled server.
    Silent,
    /// The first message's end-of-data reply arrives late (after the client's
    /// deadline) on the same connection; every later message is rejected at
    /// end of data with `554 5.6.0`.
    LateFirstReplyThenReject,
}

struct Server {
    port: u16,
    received: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
}

/// A minimal SMTP server on loopback. Returns its port and the DATA it received.
async fn smtp_server(script: Script) -> (u16, Arc<Mutex<Vec<String>>>) {
    let server = scripted_server(script).await;
    (server.port, server.received)
}

async fn scripted_server(script: Script) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let messages = Arc::new(AtomicUsize::new(0));
    let (store, conns) = (received.clone(), connections.clone());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            conns.fetch_add(1, Ordering::SeqCst);
            let store = store.clone();
            let messages = messages.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut lines = BufReader::new(r).lines();
                if script == Script::RefuseGreeting {
                    w.write_all(b"554 no SMTP service here\r\n").await.ok();
                    return;
                }
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
                        ("RCPT", Script::RefuseRecipient(reply)) => format!("{reply}\r\n"),
                        ("MAIL", Script::RefuseSender(reply)) => format!("{reply}\r\n"),
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
                            let nth = messages.fetch_add(1, Ordering::SeqCst);
                            match (script, nth) {
                                (Script::LateFirstReplyThenReject, 0) => {
                                    tokio::time::sleep(Duration::from_millis(1500)).await;
                                    "250 2.0.0 queued\r\n".into()
                                }
                                (Script::LateFirstReplyThenReject, _) => {
                                    "554 5.6.0 message content rejected\r\n".into()
                                }
                                _ => "250 2.0.0 queued\r\n".into(),
                            }
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
    Server {
        port,
        received,
        connections,
    }
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
    let (port, _) = smtp_server(Script::RefuseRecipient("550 5.1.1 no such user here")).await;
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

/// A send cancelled by the deadline must not leave its connection behind with
/// a reply still in flight: the next message would read that stale reply as
/// its own and record a rejection as sent.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_timed_out_send_never_shares_its_connection_with_the_next(pool: PgPool) {
    let db = Db::from_pool(pool);
    let server = scripted_server(Script::LateFirstReplyThenReject).await;
    let mailer = SmtpMailer::new(&smtp_config(server.port))
        .unwrap()
        .with_send_deadline(Duration::from_millis(500));

    let first = queue(&db, "first@acme.example").await;
    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, first).await;
    assert!(!r.sent && !r.failed, "the timed-out send is retried: {r:?}");
    assert!(r.last_error.unwrap().contains("no complete reply"));

    // Let the late "250 queued" for the first message arrive on its socket.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // The first row is backing off, so this pass sends only the second.
    let second = queue(&db, "second@acme.example").await;
    assert_eq!(email::deliver_due(&db, &mailer).await.unwrap(), 1);
    let r = row(&db, second).await;
    assert!(
        r.failed && !r.sent,
        "a 554 at end of data must be recorded as refused, not sent: {r:?}"
    );
    assert!(r.last_error.unwrap().contains("554"));
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        2,
        "each send opens its own connection"
    );
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_unknown_mailbox_is_permanent_but_a_refused_sender_is_not(pool: PgPool) {
    let db = Db::from_pool(pool);

    let (port, _) = smtp_server(Script::RefuseRecipient("550 5.1.1 <x>: user unknown")).await;
    let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
    let id = queue(&db, "gone@acme.example").await;
    email::deliver_due(&db, &mailer).await.unwrap();
    let r = row(&db, id).await;
    assert!(r.failed, "5.1.1 is the recipient's fault: {r:?}");

    // An unauthorised SAVVAGENT_EMAIL_FROM: our configuration, not the message.
    // Giving up would discard every queued alert on the first try.
    for (script, what) in [
        (
            Script::RefuseSender("553 5.7.1 sender not authorised"),
            "553 5.7.1",
        ),
        (
            Script::RefuseSender("550 5.7.1 relaying denied"),
            "550 5.7.1",
        ),
        (
            Script::RefuseSender("550 sender rejected"),
            "no enhanced code",
        ),
        (
            Script::RefuseRecipient("554 5.7.1 relay access denied"),
            "554 5.7.1 on RCPT",
        ),
        (Script::RefuseGreeting, "554 greeting"),
    ] {
        let (port, _) = smtp_server(script).await;
        let mailer = SmtpMailer::new(&smtp_config(port)).unwrap();
        let id = queue(&db, "owner@acme.example").await;
        email::deliver_due(&db, &mailer).await.unwrap();
        let r = row(&db, id).await;
        assert!(!r.failed && !r.sent, "{what} must stay queued: {r:?}");
        assert_eq!(r.attempts, 1, "{what}");
    }
}

/// A fake that takes its time, for a backlog that outlasts one pass.
#[derive(Clone)]
struct SlowMailer(Duration);

impl Mailer for SlowMailer {
    async fn send(&self, _: &OutgoingEmail) -> Result<(), SendError> {
        tokio::time::sleep(self.0).await;
        Ok(())
    }
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn shutdown_is_prompt_under_a_backlog(pool: PgPool) {
    let db = Db::from_pool(pool);
    let org = db.create_org("backlog", "Backlog").await.unwrap();
    let mut tx = db.begin(org.id).await.unwrap();
    for i in 0..80 {
        notifications::enqueue_email(&mut tx, &format!("u{i}@acme.example"), "s", "b")
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();

    // 80 rows at 8 a pass, 4 at a time, 300 ms each: about 6 s to drain.
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(email::run(
        db.clone(),
        SlowMailer(Duration::from_millis(300)),
        stop_rx,
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_millis(1500), task)
        .await
        .expect("shutdown waited for the backlog to drain")
        .unwrap();

    let sent: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE sent_at IS NOT NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(
        sent < 80,
        "the whole backlog went out before stopping: {sent}"
    );
}
