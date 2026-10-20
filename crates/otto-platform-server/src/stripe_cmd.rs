//! `otto-platform-server stripe sync` — make Stripe match the price book
//! (savvagent/otto-platform#61) — and the server's background loop that runs
//! the same sync on its own.
//!
//! ```text
//! otto-platform-server stripe sync
//! ```
//!
//! Needs `DATABASE_URL` and `STRIPE_SECRET_KEY` (no webhook secret). The
//! server already runs it at boot, every 15 minutes, and just after 00:00 UTC
//! on the first of each month ([`run_loop`]), whenever billing is enabled; the
//! command is for an operator who wants it now (after `pricebook set`, say)
//! and wants to read what it did. It:
//!
//! 1. creates a Stripe billing meter for every declared meter that has none
//!    (adopting an active Stripe meter with the same event name);
//! 2. creates a Stripe Price for every price-book version that has none
//!    (Stripe prices are immutable, so a version's price is created once);
//! 3. subscribes every org with an active card, no live subscription and
//!    billing not stopped (adopting the recorded subscription when Stripe
//!    says it is live, or a live one tagged with the org; a new one is
//!    backdated to the start of the month and the month's usage so far is
//!    queued for it), and puts every live subscription on a schedule that
//!    switches its prices at 00:00 UTC on the first of each month a new
//!    version takes effect;
//! 4. finalizes every invoice held as a draft (`invoice.created`) whose
//!    month's usage has all reached Stripe, or whose 72-hour hold is up.
//!
//! The server's loop also sweeps the webhook ledger (`stripe_events`) of
//! events past their retention, about once an hour.
//!
//! See `otto_billing::billing::sync`. Only one sync runs at a time across
//! every machine; a second is refused (`another stripe sync is running`).
//! Idempotent: a second run with nothing new prints `nothing to do`. It warns
//! when a subscription nears Stripe's 20 items, and exits non-zero after
//! printing every error (a meter whose key is too long to be a Stripe event
//! name, a Stripe refusal), having done everything else.

use std::io::Write;
use std::time::Duration;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use otto_billing::billing::{self, SyncReport};
use otto_billing::stripe::Client;
use otto_tenant::Db;
use tokio::sync::watch;

pub const USAGE: &str = "\
usage: otto-platform-server stripe <command>

commands:
  sync    create missing Stripe meters and prices from the price book, subscribe
          orgs with a card on file, schedule every subscription's price
          switches, and finalize held invoices whose usage has reached Stripe
          (needs STRIPE_SECRET_KEY)
  outbox  count queued, sent and lost metered usage events by status
          (needs only DATABASE_URL)
";

/// How often the background loop syncs.
pub const SYNC_EVERY: Duration = Duration::from_secs(15 * 60);

/// How long after 00:00 UTC on the first the loop runs an extra sync.
const AFTER_MONTH_START: Duration = Duration::from_secs(30);

/// How often the loop sweeps the webhook ledger.
pub const SWEEP_EVERY: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Sync,
}

/// Parse the arguments after `stripe`.
pub fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [cmd] if cmd == "sync" => Ok(Command::Sync),
        [cmd, ..] if cmd == "sync" => Err("sync takes no arguments".into()),
        [other, ..] => Err(format!("unknown command {other:?}")),
        [] => Err("missing command".into()),
    }
}

/// Run `cmd`, printing what it did to `out`.
pub async fn execute(
    db: &Db,
    client: &Client,
    cmd: Command,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match cmd {
        Command::Sync => {
            let report = billing::sync(db, client).await?;
            write_report(&report, out)?;
            if !report.errors.is_empty() {
                anyhow::bail!(
                    "stripe sync finished with {} error(s), listed above; everything else \
                     was done. Fix them and run it again",
                    report.errors.len()
                );
            }
            Ok(())
        }
    }
}

fn write_report(r: &SyncReport, out: &mut impl Write) -> std::io::Result<()> {
    for (meter, id) in &r.meters_created {
        writeln!(out, "created meter  {meter}  {id}")?;
    }
    for (meter, id) in &r.meters_adopted {
        writeln!(out, "adopted meter  {meter}  {id}")?;
    }
    for (meter, month, id) in &r.prices_created {
        writeln!(out, "created price  {meter}  from {month}  {id}")?;
    }
    for (org, id) in &r.subscriptions_created {
        writeln!(out, "subscribed     org {org}  {id}")?;
    }
    for (org, id) in &r.subscriptions_adopted {
        writeln!(out, "adopted        org {org}  {id}")?;
    }
    for (org, months) in &r.schedules_set {
        let months: Vec<String> = months.iter().map(ToString::to_string).collect();
        writeln!(
            out,
            "scheduled      org {org}  prices switch at the start of {}",
            months.join(", ")
        )?;
    }
    for org in &r.schedules_released {
        writeln!(out, "released       org {org}  no price switch pending")?;
    }
    for (org, meter) in &r.items_changed {
        writeln!(out, "corrected      org {org}  {meter}  this month's price")?;
    }
    for (org, units) in &r.usage_backfilled {
        writeln!(
            out,
            "backfilled     org {org}  {units} unit(s) of this month's usage queued"
        )?;
    }
    for (org, invoice, outcome) in &r.invoices_released {
        writeln!(out, "invoice        org {org}  {invoice}  {outcome}")?;
    }
    for w in &r.warnings {
        writeln!(out, "warning: {w}")?;
    }
    for e in &r.errors {
        writeln!(out, "error: {e}")?;
    }
    if r.is_noop() && r.errors.is_empty() {
        writeln!(out, "nothing to do: Stripe matches the price book")?;
    }
    Ok(())
}

/// How long the loop sleeps from `now`: [`SYNC_EVERY`], or less if a month
/// starts sooner, so a run lands just after 00:00 UTC on the first.
pub fn next_wait(now: DateTime<Utc>) -> Duration {
    let (y, m) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    let next_month = Utc
        .with_ymd_and_hms(y, m, 1, 0, 0, 0)
        .single()
        .map(|t| t + chrono::Duration::from_std(AFTER_MONTH_START).unwrap_or_default());
    let until = next_month
        .and_then(|t| (t - now).to_std().ok())
        .unwrap_or(SYNC_EVERY);
    until.clamp(Duration::from_secs(1), SYNC_EVERY)
}

/// Whether the loop should sweep the webhook ledger now, having last swept
/// at `last` (never: `None`).
pub fn sweep_due(last: Option<tokio::time::Instant>, now: tokio::time::Instant) -> bool {
    last.is_none_or(|last| now.duration_since(last) >= SWEEP_EVERY)
}

/// Forget webhook events past [`billing::EVENT_RETENTION_DAYS`]. A failure is
/// a warning: the ledger only grows until the next sweep.
async fn sweep_ledger(db: &Db) {
    match billing::sweep_events(db, billing::EVENT_RETENTION_DAYS).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(deleted = n, "swept old Stripe webhook events"),
        Err(e) => tracing::warn!(error = %e, "could not sweep old Stripe webhook events"),
    }
}

/// Run sync now and then on [`next_wait`]'s rhythm until `shutdown` flips to
/// `true`, sweeping the webhook ledger about once every [`SWEEP_EVERY`]. Only
/// when billing is enabled. Every machine runs it; the sync lease makes all
/// but one skip each round (the sweep is batched and skips locked rows, so
/// machines sweeping at once only share the work).
pub async fn run_loop(db: Db, client: Client, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("stripe sync task started");
    let mut last_sweep = None;
    loop {
        let now = tokio::time::Instant::now();
        if sweep_due(last_sweep, now) {
            sweep_ledger(&db).await;
            last_sweep = Some(now);
        }
        // Checked between orgs, so a shutdown mid-run gives every lease back.
        let stopping = shutdown.clone();
        let stop = move || *stopping.borrow();
        match billing::sync_until(&db, &client, &stop).await {
            Ok(report) => log_report(&report),
            Err(billing::Error::Busy(why)) => {
                tracing::debug!(%why, "stripe sync skipped: another machine is running it")
            }
            Err(e) => tracing::error!(error = %e, "stripe sync failed; retrying next round"),
        }
        tokio::select! {
            _ = tokio::time::sleep(next_wait(Utc::now())) => {}
            _ = shutdown.changed() => {
                tracing::info!("stripe sync task stopping");
                return;
            }
        }
    }
}

fn log_report(r: &SyncReport) {
    if !r.is_noop() {
        tracing::info!(
            meters = r.meters_created.len() + r.meters_adopted.len(),
            prices = r.prices_created.len(),
            subscriptions = r.subscriptions_created.len() + r.subscriptions_adopted.len(),
            schedules_set = r.schedules_set.len(),
            schedules_released = r.schedules_released.len(),
            items_corrected = r.items_changed.len(),
            usage_backfilled = r.usage_backfilled.len(),
            invoices_released = r.invoices_released.len(),
            "stripe sync changed Stripe"
        );
    }
    for w in &r.warnings {
        tracing::warn!("stripe sync: {w}");
    }
    for e in &r.errors {
        tracing::error!("stripe sync: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use otto_billing::billing::mock::MockStripe;
    use otto_billing::billing::{SetupParams, MAX_SUBSCRIPTION_ITEMS};
    use otto_billing::pricebook::{self, Month, Tier, Tiers};
    use otto_billing::stripe::{CreateMeter, CreateSubscription, IdempotencyKey};
    use otto_tenant::audit::Entry;
    use otto_tenant::ids::OrgId;
    use serde_json::{json, Value};
    use sqlx::PgPool;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses() {
        assert_eq!(parse(&args("sync")), Ok(Command::Sync));
        assert!(parse(&args("sync now")).is_err());
        assert!(parse(&args("push")).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn the_ledger_is_swept_at_once_and_then_hourly() {
        let t = tokio::time::Instant::now();
        assert!(sweep_due(None, t));
        assert!(!sweep_due(
            Some(t),
            t + SWEEP_EVERY - Duration::from_secs(1)
        ));
        assert!(sweep_due(Some(t), t + SWEEP_EVERY));
    }

    #[test]
    fn the_loop_wakes_every_15_minutes_and_just_after_each_month_starts() {
        let mid = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
        assert_eq!(next_wait(mid), SYNC_EVERY);
        let late = Utc.with_ymd_and_hms(2026, 10, 31, 23, 55, 0).unwrap();
        assert_eq!(next_wait(late), Duration::from_secs(5 * 60 + 30));
        let new_year = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 50).unwrap();
        assert_eq!(next_wait(new_year), Duration::from_secs(40));
        // Just after the first: the regular rhythm again.
        let first = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 31).unwrap();
        assert_eq!(next_wait(first), SYNC_EVERY);
    }

    async fn run(db: &Db, mock: &MockStripe) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let r = execute(db, &mock.client(), Command::Sync, &mut out).await;
        (r, String::from_utf8(out).unwrap())
    }

    async fn now_month(db: &Db) -> Month {
        let mut tx = db.begin_unpinned().await.unwrap();
        pricebook::current_month(tx.conn()).await.unwrap()
    }

    /// The earliest month `pricebook set` accepts now.
    async fn earliest(db: &Db) -> Month {
        let mut tx = db.begin_unpinned().await.unwrap();
        pricebook::store::earliest_month(tx.conn()).await.unwrap()
    }

    fn ts(month: Month) -> i64 {
        Utc.from_utc_datetime(&month.first_day().and_hms_opt(0, 0, 0).unwrap())
            .timestamp()
    }

    /// A service and its meters, as a resource server declares them.
    async fn declare(pool: &PgPool, service: &str, meters: &[&str]) {
        sqlx::query(
            "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
             VALUES ($1, $2, '{a}', '{}', $2) ON CONFLICT DO NOTHING",
        )
        .bind(format!("https://{service}.example/mcp"))
        .bind(service)
        .execute(pool)
        .await
        .unwrap();
        for m in meters {
            sqlx::query(
                "INSERT INTO meters (key, service, meter, display_name, unit) \
                 VALUES ($1, $2, $3, $3, 'unit')",
            )
            .bind(format!("{service}/{m}"))
            .bind(service)
            .bind(m)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// A flat price for `meter` from `month`, written directly (`pricebook
    /// set` refuses the current month and earlier). A fixture, not a rate.
    async fn price(pool: &PgPool, meter: &str, month: Month, ucents: i64) -> uuid::Uuid {
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO price_versions (meter, effective_month) VALUES ($1, $2) RETURNING id",
        )
        .bind(meter)
        .bind(month.first_day())
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
             VALUES ($1, 0, 100, 0), ($1, 1, NULL, $2)",
        )
        .bind(id)
        .bind(ucents)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn stripe_price_of(pool: &PgPool, version: uuid::Uuid) -> String {
        sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices WHERE price_version_id = $1")
            .bind(version)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn new_org(pool: &PgPool, slug: &str) -> OrgId {
        let org: uuid::Uuid =
            sqlx::query_scalar("INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id")
                .bind(slug)
                .fetch_one(pool)
                .await
                .unwrap();
        OrgId::from(org)
    }

    async fn setup(db: &Db, mock: &MockStripe, org: OrgId) {
        billing::start_setup(
            db,
            &mock.client(),
            SetupParams {
                org,
                org_name: "acme",
                owner_email: None,
                success_url: "https://otto.test/ok".into(),
                cancel_url: "https://otto.test/no".into(),
            },
            Entry::new(billing::actions::SETUP_STARTED),
        )
        .await
        .unwrap();
    }

    /// An org with a Stripe customer (made through setup, against the mock)
    /// and a card on file (as the webhook leaves it).
    async fn org_with_card(db: &Db, pool: &PgPool, mock: &MockStripe, slug: &str) -> OrgId {
        let org = new_org(pool, slug).await;
        setup(db, mock, org).await;
        sqlx::query(
            "UPDATE subscriptions SET payment_method_status = 'active', \
               stripe_payment_method_id = 'pm_1', payment_method_event_at = now() \
             WHERE org_id = $1",
        )
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
        org
    }

    async fn subscription_of(pool: &PgPool, org: OrgId) -> Option<String> {
        sqlx::query_scalar("SELECT stripe_subscription_id FROM subscriptions WHERE org_id = $1")
            .bind(org)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn schedule_of(mock: &MockStripe, sub: &str) -> Value {
        let id = mock.subscription(sub).unwrap()["schedule"]
            .as_str()
            .expect("a schedule")
            .to_owned();
        mock.schedule(&id).unwrap()
    }

    fn phase_prices(phase: &Value) -> Vec<String> {
        let mut p: Vec<String> = phase["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["price"].as_str().unwrap().to_owned())
            .collect();
        p.sort();
        p
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn sync_creates_meters_prices_and_subscriptions_once(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls", "bytes"]).await;
        let current = price(&pool, "svc/calls", now, 7).await;
        // `bytes` is declared but unpriced: it gets a meter and no item.
        let org = org_with_card(&db, &pool, &mock, "acme").await;

        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(out.contains("created meter  svc/bytes"), "{out}");
        assert!(out.contains("created meter  svc/calls"), "{out}");
        assert!(
            out.contains(&format!("created price  svc/calls  from {now}")),
            "{out}"
        );
        assert!(out.contains("subscribed     org"), "{out}");
        assert_eq!(mock.counts(), (2, 1));

        // The meter is what meter events will name, mapped injectively, and
        // every POST's key is derived from its parameters.
        let meter = &mock.requests("POST", "/v1/billing/meters")[1];
        assert_eq!(meter.field("event_name"), Some("svc__calls"));
        assert!(meter
            .idempotency_key
            .as_deref()
            .is_some_and(|k| k.starts_with("otto-meter-")));
        let p = &mock.requests("POST", "/v1/prices")[0];
        assert_eq!(p.field("currency"), Some("usd"));
        assert_eq!(p.field("tiers_mode"), Some("graduated"));
        assert_eq!(p.field("recurring[usage_type]"), Some("metered"));
        assert_eq!(p.field("recurring[interval]"), Some("month"));
        assert_eq!(p.field("tiers[1][up_to]"), Some("inf"));
        assert_eq!(p.field("tiers[1][unit_amount_decimal]"), Some("0.000007"));
        assert_eq!(
            p.field("metadata[price_version_id]"),
            Some(current.to_string().as_str())
        );

        let sub = subscription_of(&pool, org).await.expect("subscribed");
        assert_eq!(
            mock.subscription_prices(&sub),
            [stripe_price_of(&pool, current).await]
        );
        let created = &mock.requests("POST", "/v1/subscriptions")[0];
        assert_eq!(created.field("proration_behavior"), Some("none"));
        let next = now.offset(1).unwrap();
        assert_eq!(
            created.field("billing_cycle_anchor"),
            Some(ts(next).to_string().as_str())
        );
        // A first subscription covers the whole month.
        assert_eq!(
            created.field("backdate_start_date"),
            Some(ts(now).to_string().as_str())
        );
        assert_eq!(
            created.field("metadata[org_id]"),
            Some(org.to_string().as_str())
        );
        // Nothing to switch: no schedule.
        assert!(mock.subscription(&sub).unwrap()["schedule"].is_null());

        // Again: nothing new, so not one Stripe call.
        let before = mock.seen().len();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert_eq!(out.trim(), "nothing to do: Stripe matches the price book");
        assert_eq!(mock.seen().len(), before, "an idempotent run called Stripe");
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_future_version_switches_exactly_at_the_first_of_its_month(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let next = earliest(&db).await;
        let after = next.offset(1).unwrap();
        declare(&pool, "svc", &["calls", "bytes"]).await;
        let old = price(&pool, "svc/calls", now, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        run(&db, &mock).await.0.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();

        // A new version of `calls` from next month, set the way an operator
        // sets it, and `bytes` priced for the first time from next month too.
        let tiers = Tiers::new(vec![Tier {
            up_to: None,
            unit_amount_ucents: 5,
        }])
        .unwrap();
        let mut tx = db.begin_unpinned().await.unwrap();
        let new = pricebook::set_version(&mut tx, "svc/calls", next, &tiers)
            .await
            .unwrap()
            .version
            .id;
        let bytes = pricebook::set_version(&mut tx, "svc/bytes", next, &tiers)
            .await
            .unwrap()
            .version
            .id;
        tx.commit().await.unwrap();

        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!(
                "scheduled      org {org}  prices switch at the start of {next}"
            )),
            "{out}"
        );
        let (old_p, new_p, bytes_p) = (
            stripe_price_of(&pool, old).await,
            stripe_price_of(&pool, new).await,
            stripe_price_of(&pool, bytes).await,
        );
        // Nothing changes now ...
        assert_eq!(mock.subscription_prices(&sub), std::slice::from_ref(&old_p));
        // ... and the schedule switches at 00:00 UTC on the first, without
        // proration, then releases the subscription a month later.
        let s = schedule_of(&mock, &sub).await;
        let phases = s["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 2);
        assert_eq!(phase_prices(&phases[0]), std::slice::from_ref(&old_p));
        assert_eq!(phases[0]["end_date"], ts(next));
        assert_eq!(phases[1]["start_date"], ts(next));
        assert_eq!(phases[1]["end_date"], ts(after));
        assert_eq!(
            phase_prices(&phases[1]),
            sorted(vec![new_p.clone(), bytes_p.clone()])
        );
        assert_eq!(s["end_behavior"], "release");
        assert_eq!(s["proration_behavior"], "none");
        for p in phases {
            assert_eq!(p["proration_behavior"], "none");
        }

        mock.advance_to(ts(next) - 1);
        assert_eq!(mock.subscription_prices(&sub), std::slice::from_ref(&old_p));
        mock.advance_to(ts(next));
        assert_eq!(
            mock.subscription_prices(&sub),
            sorted(vec![new_p.clone(), bytes_p.clone()])
        );
        mock.advance_to(ts(next) + 3600);

        // Nothing new: no Stripe call.
        let before = mock.seen().len();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(out.contains("nothing to do"), "{out}");
        assert_eq!(mock.seen().len(), before);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_replaced_future_version_updates_the_same_schedule(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let next = earliest(&db).await;
        let later = next.offset(2).unwrap();
        declare(&pool, "svc", &["calls"]).await;
        let old = price(&pool, "svc/calls", now, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        let flat = |u| {
            Tiers::new(vec![Tier {
                up_to: None,
                unit_amount_ucents: u,
            }])
            .unwrap()
        };
        let set = |month, u| {
            let db = db.clone();
            async move {
                let mut tx = db.begin_unpinned().await.unwrap();
                let v = pricebook::set_version(&mut tx, "svc/calls", month, &flat(u))
                    .await
                    .unwrap()
                    .version
                    .id;
                tx.commit().await.unwrap();
                v
            }
        };
        set(next, 5).await;
        run(&db, &mock).await.0.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();
        let first = schedule_of(&mock, &sub).await;

        // Replaced before its month (a new id), and another version later.
        let replacement = set(next, 4).await;
        let third = set(later, 3).await;
        run(&db, &mock).await.0.unwrap();
        let s = schedule_of(&mock, &sub).await;
        assert_eq!(s["id"], first["id"], "the same schedule, updated");
        let phases = s["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 3);
        assert_eq!(
            phase_prices(&phases[0]),
            [stripe_price_of(&pool, old).await]
        );
        assert_eq!(
            phase_prices(&phases[1]),
            [stripe_price_of(&pool, replacement).await]
        );
        assert_eq!(phases[1]["start_date"], ts(next));
        assert_eq!(phases[2]["start_date"], ts(later));
        assert_eq!(
            phase_prices(&phases[2]),
            [stripe_price_of(&pool, third).await]
        );
        // The replaced version's price is in no phase.
        assert_eq!(mock.counts().1, 4);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn this_months_items_are_corrected_at_once(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let last = now.offset(-1).unwrap();
        declare(&pool, "svc", &["calls", "bytes"]).await;
        let old = price(&pool, "svc/calls", last, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        run(&db, &mock).await.0.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();
        assert_eq!(
            mock.subscription_prices(&sub),
            [stripe_price_of(&pool, old).await]
        );

        // Versions that are already in effect (only possible by writing the
        // table directly, or a sync that could not run across a month start)
        // apply now: the item moved, the new meter's item added, no proration.
        let new = price(&pool, "svc/calls", now, 6).await;
        let bytes = price(&pool, "svc/bytes", now, 3).await;
        // An item on a price the price book does not know (added by hand in
        // the dashboard): sync never removes an item.
        let stray_meter = mock
            .client()
            .create_meter(
                &CreateMeter {
                    display_name: "stray".into(),
                    event_name: "stray__meter".into(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        let stray = mock
            .client()
            .create_metered_price(
                &otto_billing::stripe::CreateMeteredPrice {
                    currency: "usd".into(),
                    product: otto_billing::stripe::PriceProduct::New {
                        name: "stray".into(),
                    },
                    meter: stray_meter.id,
                    tiers: vec![otto_billing::stripe::PriceTier {
                        up_to: otto_billing::stripe::TierUpTo::Inf,
                        unit_amount_ucents: 1,
                    }],
                    lookup_key: None,
                    nickname: None,
                    metadata: Default::default(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        mock.client()
            .add_subscription_item(&sub, &stray.id, &IdempotencyKey::random())
            .await
            .unwrap();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        // A price changing inside its month is called out.
        assert!(
            out.contains(&format!(
                "warning: org {org}: svc/calls changed price in the middle of {now}"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "warning: org {org}: svc/bytes changed price in the middle of {now} (from no item)"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!("corrected      org {org}  svc/calls")),
            "{out}"
        );
        assert!(
            out.contains(&format!("corrected      org {org}  svc/bytes")),
            "{out}"
        );
        assert_eq!(
            mock.subscription_prices(&sub),
            sorted(vec![
                stripe_price_of(&pool, new).await,
                stripe_price_of(&pool, bytes).await,
                stray.id.clone(),
            ]),
            "the stray item is left alone"
        );
        for p in mock.posts_under("/v1/subscription_items") {
            assert_eq!(p.field("proration_behavior"), Some("none"));
        }
        let synced: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE org_id = $1 AND action = 'billing.subscription.items_synced'",
        )
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(synced >= 1);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn existing_stripe_objects_are_adopted_not_duplicated(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 7).await;
        let c = mock.client();
        // A meter an earlier run created and never recorded.
        let mtr = c
            .create_meter(
                &CreateMeter {
                    display_name: "calls".into(),
                    event_name: "svc__calls".into(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        run(&db, &mock).await.0.unwrap_or_default();
        let recorded: String = sqlx::query_scalar(
            "SELECT stripe_meter_id FROM stripe_meters WHERE meter = 'svc/calls'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(recorded, mtr.id);
        assert_eq!(mock.requests("POST", "/v1/billing/meters").len(), 1);

        // A subscription an earlier attempt created and never recorded.
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        let customer: String =
            sqlx::query_scalar("SELECT stripe_customer_id FROM subscriptions WHERE org_id = $1")
                .bind(org)
                .fetch_one(&pool)
                .await
                .unwrap();
        let price_id: String = sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices")
            .fetch_one(&pool)
            .await
            .unwrap();
        let orphan = c
            .create_subscription(
                &CreateSubscription {
                    customer,
                    prices: vec![price_id],
                    billing_cycle_anchor: None,
                    backdate_start_date: None,
                    metadata: [("org_id".to_owned(), org.to_string())].into(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!("adopted        org {org}  {}", orphan.id)),
            "{out}"
        );
        assert_eq!(subscription_of(&pool, org).await, Some(orphan.id));
        assert_eq!(mock.requests("POST", "/v1/subscriptions").len(), 1);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn two_live_subscriptions_tagged_with_one_org_are_an_error(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 7).await;
        run(&db, &mock).await.0.unwrap();
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        let customer: String =
            sqlx::query_scalar("SELECT stripe_customer_id FROM subscriptions WHERE org_id = $1")
                .bind(org)
                .fetch_one(&pool)
                .await
                .unwrap();
        let price_id: String = sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices")
            .fetch_one(&pool)
            .await
            .unwrap();
        let c = mock.client();
        for _ in 0..2 {
            c.create_subscription(
                &CreateSubscription {
                    customer: customer.clone(),
                    prices: vec![price_id.clone()],
                    billing_cycle_anchor: None,
                    backdate_start_date: None,
                    metadata: [("org_id".to_owned(), org.to_string())].into(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        }
        let (r, out) = run(&db, &mock).await;
        assert!(r.is_err(), "{out}");
        assert!(
            out.contains(&format!(
                "2 live Stripe subscriptions are tagged with org {org}"
            )),
            "{out}"
        );
        // Neither was taken, and no third was made.
        assert!(subscription_of(&pool, org).await.is_none());
        assert_eq!(mock.requests("POST", "/v1/subscriptions").len(), 2);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn sync_warns_near_the_item_limit_and_never_passes_it(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let names: Vec<String> = (0..MAX_SUBSCRIPTION_ITEMS + 2)
            .map(|i| format!("m{i:02}"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        declare(&pool, "svc", &refs).await;
        for n in &refs[..17] {
            price(&pool, &format!("svc/{n}"), now, 1).await;
        }
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();
        assert_eq!(mock.subscription_prices(&sub).len(), 17);
        assert!(out.contains("17 of Stripe's 20"), "{out}");

        // Five more priced: three fit, and the run says two are not billed.
        for n in &refs[17..] {
            price(&pool, &format!("svc/{n}"), now, 1).await;
        }
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert_eq!(mock.subscription_prices(&sub).len(), MAX_SUBSCRIPTION_ITEMS);
        assert!(out.contains("22 meters are priced"), "{out}");
        assert!(out.contains("2 are not billed"), "{out}");
        assert!(out.contains("20 of Stripe's 20"), "{out}");
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_meter_too_long_for_stripe_or_a_bad_version_is_reported_and_the_rest_synced(
        pool: PgPool,
    ) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let service = format!("s{}", "x".repeat(59));
        let meter = format!("m{}", "y".repeat(45));
        declare(&pool, &service, &[meter.as_str()]).await;
        let long = format!("{service}/{meter}");
        price(&pool, &long, now, 1).await;
        declare(&pool, "svc", &["calls", "bytes"]).await;
        price(&pool, "svc/calls", now, 1).await;
        // A version whose tiers were edited by hand into a shape that cannot
        // be priced (its unbounded tier removed).
        let bad = price(&pool, "svc/bytes", now, 1).await;
        sqlx::query("DELETE FROM price_tiers WHERE version_id = $1 AND up_to IS NULL")
            .bind(bad)
            .execute(&pool)
            .await
            .unwrap();

        let (r, out) = run(&db, &mock).await;
        let err = r.expect_err("a meter could not be synced");
        assert!(err.to_string().contains("error(s)"), "{err}");
        assert!(
            out.contains(&format!("error: meter {long} cannot be synced to Stripe")),
            "{out}"
        );
        assert!(out.contains("longer than 100 characters"), "{out}");
        assert!(
            out.contains(&format!("error: price of svc/bytes from {now}: malformed")),
            "{out}"
        );
        // Everything else went ahead.
        assert!(
            out.contains(&format!("created price  svc/calls  from {now}")),
            "{out}"
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn an_org_without_a_card_or_with_billing_stopped_is_not_subscribed(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 1).await;
        let detached = org_with_card(&db, &pool, &mock, "acme").await;
        sqlx::query(
            "UPDATE subscriptions SET payment_method_status = 'detached' WHERE org_id = $1",
        )
        .bind(detached)
        .execute(&pool)
        .await
        .unwrap();
        // Stripe canceled this one's subscription: billing is stopped.
        let stopped = org_with_card(&db, &pool, &mock, "beta").await;
        sqlx::query(
            "UPDATE subscriptions SET stripe_subscription_id = 'sub_gone', status = 'canceled', \
               billing_stopped_at = now() WHERE org_id = $1",
        )
        .bind(stopped)
        .execute(&pool)
        .await
        .unwrap();
        run(&db, &mock).await.0.unwrap();
        run(&db, &mock).await.0.unwrap();
        assert!(subscription_of(&pool, detached).await.is_none());
        assert_eq!(
            subscription_of(&pool, stopped).await.as_deref(),
            Some("sub_gone")
        );
        assert!(mock.requests("POST", "/v1/subscriptions").is_empty());
    }

    /// Usage counted for `org` this month, as ingest leaves it before the
    /// org has a subscription. A fixture.
    async fn counted(db: &Db, org: OrgId, meter: &str, month: Month, quantity: i64) {
        let mut tx = db.begin(org).await.unwrap();
        sqlx::query(
            "INSERT INTO org_meter_period_usage (org_id, meter, period_start, quantity) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(org)
        .bind(meter)
        .bind(month.first_day())
        .bind(quantity)
        .execute(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn queued(pool: &PgPool, org: OrgId) -> (i64, Vec<String>) {
        let (sum, customers): (Option<i64>, Vec<String>) = sqlx::query_as(
            "SELECT sum(value)::bigint, coalesce(array_agg(DISTINCT stripe_customer_id), '{}') \
             FROM stripe_meter_outbox WHERE org_id = $1",
        )
        .bind(org)
        .fetch_one(pool)
        .await
        .unwrap();
        (sum.unwrap_or(0), customers)
    }

    async fn customer_of(pool: &PgPool, org: OrgId) -> String {
        sqlx::query_scalar("SELECT stripe_customer_id FROM subscriptions WHERE org_id = $1")
            .bind(org)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_first_subscription_is_backdated_and_its_month_backfilled_once(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = Month::of(Utc::now());
        declare(&pool, "svc", &["calls", "bytes"]).await;
        price(&pool, "svc/calls", now, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        // Used before the card went on file: counted, never queued.
        counted(&db, org, "svc/calls", now, 1_234).await;
        counted(&db, org, "svc/bytes", now, 5).await;
        assert_eq!(queued(&pool, org).await.0, 0);

        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        let sub = subscription_of(&pool, org).await.expect("subscribed");
        assert_eq!(
            mock.subscription(&sub).unwrap()["start_date"],
            ts(now),
            "Stripe rates the whole month"
        );
        // Every counted unit is queued for the org's customer, once; an
        // unpriced meter's usage is queued too (Stripe bills it at nothing).
        let customer = customer_of(&pool, org).await;
        assert_eq!(queued(&pool, org).await, (1_239, vec![customer]));
        assert!(
            out.contains(&format!(
                "backfilled     org {org}  1239 unit(s) of this month's usage queued"
            )),
            "{out}"
        );
        let detail: Value = sqlx::query_scalar(
            "SELECT detail FROM audit_events \
             WHERE org_id = $1 AND action = 'billing.subscription.created'",
        )
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(detail["usageBackfilled"], 1_239);
        assert_eq!(
            detail["backdatedTo"],
            json!(Utc.timestamp_opt(ts(now), 0).unwrap())
        );

        // Again, directly and through sync: nothing more is queued.
        let mut tx = db.begin(org).await.unwrap();
        assert_eq!(
            otto_billing::stripe_outbox::backfill_period(&mut tx, now)
                .await
                .unwrap(),
            0
        );
        tx.commit().await.unwrap();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(out.contains("nothing to do"), "{out}");
        assert_eq!(queued(&pool, org).await.0, 1_239);
    }

    #[test]
    fn a_resubscription_is_backdated_only_past_the_old_one() {
        use otto_billing::billing::backdate_start_for;
        let oct = Month::new(2026, 10).unwrap();
        let start = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 10, 20, 13, 47, 0).unwrap();
        let hour = Utc.with_ymd_and_hms(2026, 10, 20, 13, 0, 0).unwrap();
        // A first subscription: the whole month.
        assert_eq!(backdate_start_for(false, None, oct, now), Some(start));
        // The old one ended before the month: the whole month.
        let sept = start - chrono::Duration::days(3);
        assert_eq!(backdate_start_for(true, Some(sept), oct, now), Some(start));
        // It ended this month: from this hour, never overlapping it.
        let earlier = Utc.with_ymd_and_hms(2026, 10, 9, 8, 0, 0).unwrap();
        assert_eq!(
            backdate_start_for(true, Some(earlier), oct, now),
            Some(hour)
        );
        let this_hour = Utc.with_ymd_and_hms(2026, 10, 20, 13, 5, 0).unwrap();
        assert_eq!(backdate_start_for(true, Some(this_hour), oct, now), None);
        assert_eq!(backdate_start_for(true, None, oct, now), Some(hour));
        // At the very start of the month there is nothing to backdate.
        assert_eq!(backdate_start_for(false, None, oct, start), None);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_live_subscription_with_a_stale_local_status_is_adopted_not_doubled(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        run(&db, &mock).await.0.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();

        // Our copy says it is not live (a webhook lost, or one still on its
        // way); Stripe says it is.
        for stale in ["incomplete", "incomplete_expired", "paused"] {
            sqlx::query(
                "UPDATE subscriptions SET status = $2, subscription_event_at = now() \
                 WHERE org_id = $1",
            )
            .bind(org)
            .bind(stale)
            .execute(&pool)
            .await
            .unwrap();
            let (r, out) = run(&db, &mock).await;
            r.unwrap();
            assert!(
                out.contains(&format!("adopted        org {org}  {sub}")),
                "{stale}: {out}"
            );
            assert_eq!(
                subscription_of(&pool, org).await.as_deref(),
                Some(sub.as_str())
            );
            let status: String =
                sqlx::query_scalar("SELECT status FROM subscriptions WHERE org_id = $1")
                    .bind(org)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(status, "active", "{stale}");
        }
        assert_eq!(
            mock.requests("POST", "/v1/subscriptions").len(),
            1,
            "never a second subscription"
        );
        assert_eq!(mock.subscription_ids(), [sub]);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn another_live_metered_subscription_blocks_creating_one(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 7).await;
        run(&db, &mock).await.0.unwrap_or_default();
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        let price_id: String = sqlx::query_scalar("SELECT stripe_price_id FROM stripe_prices")
            .fetch_one(&pool)
            .await
            .unwrap();
        // Made by hand in the dashboard, not tagged with the org.
        let manual = mock
            .client()
            .create_subscription(
                &CreateSubscription {
                    customer: customer_of(&pool, org).await,
                    prices: vec![price_id],
                    billing_cycle_anchor: None,
                    backdate_start_date: None,
                    metadata: Default::default(),
                },
                &IdempotencyKey::random(),
            )
            .await
            .unwrap();
        let (r, out) = run(&db, &mock).await;
        assert!(r.is_err(), "{out}");
        assert!(
            out.contains(&format!("already has live subscription {}", manual.id)),
            "{out}"
        );
        assert!(out.contains("bill the same usage twice"), "{out}");
        assert!(subscription_of(&pool, org).await.is_none());
        assert_eq!(mock.requests("POST", "/v1/subscriptions").len(), 1);
    }

    // ------------------------------------------------------- held invoices

    /// An org subscribed through sync, with its customer and subscription.
    async fn subscribed(db: &Db, pool: &PgPool, mock: &MockStripe) -> (OrgId, String, String) {
        let now = now_month(db).await;
        declare(pool, "svc", &["calls"]).await;
        price(pool, "svc/calls", now.offset(-3).unwrap(), 7).await;
        let org = org_with_card(db, pool, mock, "acme").await;
        run(db, mock).await.0.unwrap();
        let sub = subscription_of(pool, org).await.unwrap();
        (org, customer_of(pool, org).await, sub)
    }

    /// A month whose period has long closed, and the instant it ends.
    fn closed_month() -> (Month, i64) {
        let m = Month::of(Utc::now()).offset(-2).unwrap();
        (m, ts(m.offset(1).unwrap()))
    }

    /// One outbox row of the org's usage in `month`, `pending` or `sent`.
    async fn outbox_row(db: &Db, org: OrgId, customer: &str, month: Month, status: &str) {
        let mut tx = db.begin(org).await.unwrap();
        sqlx::query(
            "INSERT INTO stripe_meter_outbox \
               (org_id, event_name, stripe_customer_id, value, bucket_start, status, \
                finished_at) \
             VALUES ($1, 'svc__calls', $2, 3, $3, $4, \
                     CASE WHEN $4 = 'pending' THEN NULL ELSE now() END)",
        )
        .bind(org)
        .bind(customer)
        .bind(Utc.timestamp_opt(ts(month) + 5 * 3600, 0).unwrap())
        .bind(status)
        .execute(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn ship_all(db: &Db, org: OrgId) {
        let mut tx = db.begin(org).await.unwrap();
        sqlx::query(
            "UPDATE stripe_meter_outbox SET status = 'sent', finished_at = now() \
             WHERE status = 'pending'",
        )
        .execute(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Run the held invoices' clock forward: as if usage had been seen clear
    /// (or the hold begun) `ago` earlier.
    async fn held_since(db: &Db, org: OrgId, column: &str, ago: chrono::Duration) {
        let mut tx = db.begin(org).await.unwrap();
        sqlx::query(&format!(
            "UPDATE stripe_held_invoices SET {column} = now() - make_interval(secs => $1)"
        ))
        .bind(ago.num_seconds() as f64)
        .execute(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn held(pool: &PgPool) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT stripe_invoice_id, outcome FROM stripe_held_invoices ORDER BY 1")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    async fn invoice_event(
        db: &Db,
        mock: &MockStripe,
        event_id: &str,
        invoice: &Value,
    ) -> billing::EventOutcome {
        let event = otto_billing::stripe::WebhookEvent {
            id: event_id.into(),
            event_type: "invoice.created".into(),
            created: Utc::now().timestamp(),
            data: otto_billing::stripe::EventData {
                object: invoice.clone(),
            },
        };
        billing::handle_event(db, &mock.client(), &event, b"{}")
            .await
            .unwrap()
    }

    async fn billing_audit(pool: &PgPool, org: OrgId, action: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE org_id = $1 AND action = $2")
            .bind(org)
            .bind(action)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn an_invoice_is_held_until_its_usage_has_reached_stripe(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let (org, customer, sub) = subscribed(&db, &pool, &mock).await;
        let (month, end) = closed_month();
        outbox_row(&db, org, &customer, month, "sent").await;
        outbox_row(&db, org, &customer, month, "pending").await;

        // Stripe makes the month's invoice and tells us.
        let invoice = mock.add_invoice("in_1", &customer, &sub, end);
        assert_eq!(
            invoice_event(&db, &mock, "evt_inv_1", &invoice).await,
            billing::EventOutcome::Handled
        );
        assert_eq!(mock.invoice("in_1").unwrap()["auto_advance"], false);
        assert_eq!(held(&pool).await, [("in_1".to_owned(), None)]);
        // Redelivered, and the same invoice under another event id: held
        // once, audited once.
        assert_eq!(
            invoice_event(&db, &mock, "evt_inv_1", &invoice).await,
            billing::EventOutcome::Duplicate
        );
        assert_eq!(
            invoice_event(&db, &mock, "evt_inv_1b", &invoice).await,
            billing::EventOutcome::Handled
        );
        assert_eq!(held(&pool).await.len(), 1);
        assert_eq!(
            billing_audit(&pool, org, billing::actions::INVOICE_HELD).await,
            1
        );

        // Stripe would have finalized it an hour later; held, it stays a
        // draft, and sync leaves it while usage is waiting.
        mock.advance_to(end + 3 * 3600);
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(!out.contains("invoice "), "{out}");
        assert_eq!(mock.invoice("in_1").unwrap()["status"], "draft");
        // Even after the settle time.
        held_since(&db, org, "held_at", chrono::Duration::hours(1)).await;
        run(&db, &mock).await.0.unwrap();
        assert_eq!(mock.invoice("in_1").unwrap()["status"], "draft");

        // The usage is sent. The first run sees it clear, and waits one more
        // interval in case anything else is on its way.
        ship_all(&db, org).await;
        run(&db, &mock).await.0.unwrap();
        assert_eq!(mock.invoice("in_1").unwrap()["status"], "draft");
        assert!(mock
            .requests("POST", "/v1/invoices/in_1/finalize")
            .is_empty());
        held_since(&db, org, "clear_since", billing::INVOICE_SETTLE).await;
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!("invoice        org {org}  in_1  finalized")),
            "{out}"
        );
        let inv = mock.invoice("in_1").unwrap();
        assert_eq!(
            (inv["status"].clone(), inv["auto_advance"].clone()),
            (json!("open"), json!(true))
        );
        let finalize = mock.requests("POST", "/v1/invoices/in_1/finalize");
        assert_eq!(finalize.len(), 1);
        assert_eq!(finalize[0].field("auto_advance"), Some("true"));
        assert_eq!(
            held(&pool).await,
            [("in_1".to_owned(), Some("finalized".to_owned()))]
        );
        assert_eq!(
            billing_audit(&pool, org, billing::actions::INVOICE_RELEASED).await,
            1
        );

        // Once released: no more calls, and a late redelivery holds nothing.
        let before = mock.seen().len();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(out.contains("nothing to do"), "{out}");
        assert_eq!(
            invoice_event(&db, &mock, "evt_inv_1c", &invoice).await,
            billing::EventOutcome::Ignored("the invoice was already released".into())
        );
        assert_eq!(mock.seen().len(), before);
        assert_eq!(mock.invoice("in_1").unwrap()["auto_advance"], true);
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn an_invoice_held_too_long_is_finalized_anyway(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let (org, customer, sub) = subscribed(&db, &pool, &mock).await;
        let (month, end) = closed_month();
        outbox_row(&db, org, &customer, month, "pending").await;
        let invoice = mock.add_invoice("in_2", &customer, &sub, end);
        invoice_event(&db, &mock, "evt_inv_2", &invoice).await;

        held_since(
            &db,
            org,
            "held_at",
            billing::MAX_INVOICE_HOLD - chrono::Duration::minutes(1),
        )
        .await;
        run(&db, &mock).await.0.unwrap();
        assert_eq!(mock.invoice("in_2").unwrap()["status"], "draft");

        held_since(&db, org, "held_at", billing::MAX_INVOICE_HOLD).await;
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!("invoice        org {org}  in_2  finalized_late")),
            "{out}"
        );
        assert!(
            out.contains("maximum hold with usage still waiting"),
            "{out}"
        );
        assert_eq!(mock.invoice("in_2").unwrap()["status"], "open");
        assert_eq!(
            held(&pool).await,
            [("in_2".to_owned(), Some("finalized_late".to_owned()))]
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn an_invoice_finalized_by_someone_else_is_left_alone(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let (org, customer, sub) = subscribed(&db, &pool, &mock).await;
        let (_, end) = closed_month();
        let invoice = mock.add_invoice("in_3", &customer, &sub, end);
        invoice_event(&db, &mock, "evt_inv_3", &invoice).await;
        // Finalized by hand in the dashboard.
        mock.set_invoice_status("in_3", "open");
        run(&db, &mock).await.0.unwrap();
        held_since(&db, org, "clear_since", billing::INVOICE_SETTLE).await;
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!("invoice        org {org}  in_3  not_draft")),
            "{out}"
        );
        assert!(mock
            .requests("POST", "/v1/invoices/in_3/finalize")
            .is_empty());
        assert_eq!(
            held(&pool).await,
            [("in_3".to_owned(), Some("not_draft".to_owned()))]
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn only_cycle_drafts_of_the_recorded_subscription_are_held(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let (_, customer, sub) = subscribed(&db, &pool, &mock).await;
        let (_, end) = closed_month();
        let mut first = mock.add_invoice("in_4", &customer, &sub, end);
        first["billing_reason"] = json!("subscription_create");
        let other = mock.add_invoice("in_5", &customer, "sub_someone_else", end);
        let mut open = mock.add_invoice("in_6", &customer, &sub, end);
        open["status"] = json!("open");
        for (i, inv) in [first, other, open].iter().enumerate() {
            assert!(
                matches!(
                    invoice_event(&db, &mock, &format!("evt_x{i}"), inv).await,
                    billing::EventOutcome::Ignored(_)
                ),
                "{inv}"
            );
        }
        assert!(held(&pool).await.is_empty());
        assert!(mock.posts_under("/v1/invoices").is_empty());
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn only_one_sync_runs_at_a_time(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        sqlx::query(
            "INSERT INTO stripe_sync_lease (name, token, until) \
             VALUES ('sync', gen_random_uuid(), now() + interval '1 minute')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (r, _) = run(&db, &mock).await;
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("another stripe sync is running"),);
        assert!(mock.seen().is_empty());
        // An expired lease (a crashed run) is taken over.
        sqlx::query("UPDATE stripe_sync_lease SET until = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        run(&db, &mock).await.0.unwrap();
        let held: i64 = sqlx::query_scalar("SELECT count(*) FROM stripe_sync_lease")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(held, 0, "a finished run gives the lease back");
    }
}
