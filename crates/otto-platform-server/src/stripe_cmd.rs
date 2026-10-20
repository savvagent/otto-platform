//! `otto-platform-server stripe sync` — make Stripe match the price book
//! (savvagent/otto-platform#61).
//!
//! ```text
//! otto-platform-server stripe sync
//! ```
//!
//! Needs `DATABASE_URL` and `STRIPE_SECRET_KEY` (no webhook secret). Run it
//! after `pricebook set`, and again at 00:00 UTC on the first of a month in
//! which a new price version takes effect. It:
//!
//! 1. creates a Stripe billing meter for every declared meter that has none;
//! 2. creates a Stripe Price for every price-book version that has none
//!    (Stripe prices are immutable, so a version's price is created once);
//! 3. for every org with a card on file and no live subscription, creates one;
//!    for every live subscription, adds an item for each newly priced meter
//!    and moves each item to the price version in effect this month.
//!
//! See `otto_billing::billing::sync`. Idempotent: a second run with nothing
//! new prints `nothing to do`. It warns when a subscription nears Stripe's 20
//! items, and exits non-zero after printing every error (a meter whose key is
//! too long to be a Stripe event name, a Stripe refusal), having done
//! everything else; fix the cause and run it again.

use std::io::Write;

use otto_billing::billing::{self, SyncReport};
use otto_billing::stripe::Client;
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server stripe <command>

commands:
  sync    create missing Stripe meters and prices from the price book, subscribe
          orgs with a card on file, and keep every subscription's items on the
          price version in effect this month (needs STRIPE_SECRET_KEY)
";

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
    for (meter, month, id) in &r.prices_created {
        writeln!(out, "created price  {meter}  from {month}  {id}")?;
    }
    for (org, id) in &r.subscriptions_created {
        writeln!(out, "subscribed     org {org}  {id}")?;
    }
    for (org, meter) in &r.items_added {
        writeln!(out, "added item     org {org}  {meter}")?;
    }
    for (org, meter, month) in &r.items_moved {
        writeln!(
            out,
            "moved item     org {org}  {meter}  to the {month} price"
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use otto_billing::billing::mock::MockStripe;
    use otto_billing::billing::{SetupParams, MAX_SUBSCRIPTION_ITEMS};
    use otto_billing::pricebook::{self, Month};
    use otto_tenant::audit::Entry;
    use otto_tenant::ids::OrgId;
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

    async fn run(db: &Db, mock: &MockStripe) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let r = execute(db, &mock.client(), Command::Sync, &mut out).await;
        (r, String::from_utf8(out).unwrap())
    }

    async fn now_month(db: &Db) -> Month {
        let mut tx = db.begin_unpinned().await.unwrap();
        pricebook::current_month(tx.conn()).await.unwrap()
    }

    /// A service and its meters, as a resource server declares them.
    async fn declare(pool: &PgPool, service: &str, meters: &[&str]) {
        sqlx::query(
            "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
             VALUES ($1, $2, '{a}', '{}', $2)",
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

    /// An org with a Stripe customer (made through setup, against the mock)
    /// and a card on file (as the webhook leaves it).
    async fn org_with_card(db: &Db, pool: &PgPool, mock: &MockStripe, slug: &str) -> OrgId {
        let org: uuid::Uuid =
            sqlx::query_scalar("INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id")
                .bind(slug)
                .fetch_one(pool)
                .await
                .unwrap();
        let org = OrgId::from(org);
        billing::start_setup(
            db,
            &mock.client(),
            SetupParams {
                org,
                org_name: slug,
                owner_email: None,
                success_url: "https://otto.test/ok".into(),
                cancel_url: "https://otto.test/no".into(),
            },
            Entry::new(billing::actions::SETUP_STARTED),
        )
        .await
        .unwrap();
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

    async fn item_versions(pool: &PgPool, org: OrgId) -> Vec<(String, uuid::Uuid)> {
        sqlx::query_as(
            "SELECT meter, price_version_id FROM stripe_subscription_items \
             WHERE org_id = $1 ORDER BY meter",
        )
        .bind(org)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn sync_creates_meters_prices_and_subscriptions_once(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls", "bytes"]).await;
        let current = price(&pool, "svc/calls", now, 7).await;
        let future = price(&pool, "svc/calls", now.offset(1).unwrap(), 5).await;
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
        assert_eq!(mock.counts(), (2, 2), "two meters, a price per version");

        // The meter is what meter events will name, mapped injectively.
        let meter = &mock.requests("POST", "/v1/billing/meters")[1];
        assert_eq!(meter.field("event_name"), Some("svc__calls"));
        assert_eq!(
            meter.idempotency_key.as_deref(),
            Some("otto-meter-svc__calls")
        );
        // Prices: graduated, metered, monthly, in dollars, exact decimals, and
        // both versions of one meter on one product.
        let prices = mock.requests("POST", "/v1/prices");
        let first = &prices[0];
        assert_eq!(first.field("currency"), Some("usd"));
        assert_eq!(first.field("tiers_mode"), Some("graduated"));
        assert_eq!(first.field("recurring[usage_type]"), Some("metered"));
        assert_eq!(first.field("recurring[interval]"), Some("month"));
        assert_eq!(first.field("tiers[0][up_to]"), Some("100"));
        assert_eq!(first.field("tiers[0][unit_amount_decimal]"), Some("0"));
        assert_eq!(first.field("tiers[1][up_to]"), Some("inf"));
        assert_eq!(
            first.field("tiers[1][unit_amount_decimal]"),
            Some("0.000007")
        );
        assert_eq!(
            first.idempotency_key.as_deref(),
            Some(format!("otto-price-{current}").as_str())
        );
        assert!(first.field("product_data[name]").is_some());
        assert_eq!(prices[1].field("product_data[name]"), None);
        assert!(prices[1]
            .field("product")
            .is_some_and(|p| p.starts_with("prod_")));
        assert_eq!(
            prices[1].idempotency_key.as_deref(),
            Some(format!("otto-price-{future}").as_str())
        );

        // The subscription bills `calls` at this month's version.
        let sub = subscription_of(&pool, org).await.expect("subscribed");
        assert_eq!(
            item_versions(&pool, org).await,
            [("svc/calls".into(), current)]
        );
        let created = &mock.requests("POST", "/v1/subscriptions")[0];
        assert_eq!(created.field("proration_behavior"), Some("none"));
        assert!(created.field("billing_cycle_anchor").is_some());

        // Again: nothing new, nothing sent.
        let before = mock.seen().len();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert_eq!(out.trim(), "nothing to do: Stripe matches the price book");
        assert_eq!(mock.seen().len(), before, "an idempotent run called Stripe");
        assert_eq!(subscription_of(&pool, org).await, Some(sub));
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn sync_moves_items_to_a_new_version_and_adds_newly_priced_meters(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let last = now.offset(-1).unwrap();
        declare(&pool, "svc", &["calls", "bytes"]).await;
        let old = price(&pool, "svc/calls", last, 7).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        run(&db, &mock).await.0.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();
        assert_eq!(item_versions(&pool, org).await, [("svc/calls".into(), old)]);

        // A new month's version of `calls` takes effect, and `bytes` gets its
        // first price.
        let new = price(&pool, "svc/calls", now, 6).await;
        let bytes = price(&pool, "svc/bytes", now, 3).await;
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(
            out.contains(&format!(
                "moved item     org {org}  svc/calls  to the {now} price"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!("added item     org {org}  svc/bytes")),
            "{out}"
        );
        assert_eq!(
            item_versions(&pool, org).await,
            [("svc/bytes".into(), bytes), ("svc/calls".into(), new)]
        );

        // In Stripe: the same subscription, the item re-priced in place with
        // no proration, and a new item without proration.
        assert_eq!(mock.subscription_ids(), std::slice::from_ref(&sub));
        let new_price: String = sqlx::query_scalar(
            "SELECT stripe_price_id FROM stripe_prices WHERE price_version_id = $1",
        )
        .bind(new)
        .fetch_one(&pool)
        .await
        .unwrap();
        let bytes_price: String = sqlx::query_scalar(
            "SELECT stripe_price_id FROM stripe_prices WHERE price_version_id = $1",
        )
        .bind(bytes)
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut on_sub = mock.subscription_prices(&sub);
        on_sub.sort();
        let mut want = vec![new_price.clone(), bytes_price.clone()];
        want.sort();
        assert_eq!(on_sub, want);
        let moves: Vec<_> = mock
            .posts_under("/v1/subscription_items/")
            .into_iter()
            .collect();
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].field("price"), Some(new_price.as_str()));
        assert_eq!(moves[0].field("proration_behavior"), Some("none"));
        let adds = mock.requests("POST", "/v1/subscription_items");
        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].field("subscription"), Some(sub.as_str()));
        assert_eq!(adds[0].field("price"), Some(bytes_price.as_str()));
        assert_eq!(adds[0].field("proration_behavior"), Some("none"));

        // Audited in the org's trail.
        let synced: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE org_id = $1 AND action = 'billing.subscription.items_synced'",
        )
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(synced, 1);

        // And again: nothing to do.
        let before = mock.seen().len();
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        assert!(out.contains("nothing to do"), "{out}");
        assert_eq!(mock.seen().len(), before);
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
        declare(&pool, "svc", &refs[..17]).await;
        for n in &refs[..17] {
            price(&pool, &format!("svc/{n}"), now, 1).await;
        }
        let org = org_with_card(&db, &pool, &mock, "acme").await;

        // 17 priced meters: created with ten, the rest added one by one so
        // every item's id is known; and a warning.
        let (r, out) = run(&db, &mock).await;
        r.unwrap();
        let sub = subscription_of(&pool, org).await.unwrap();
        assert_eq!(mock.subscription_prices(&sub).len(), 17);
        assert_eq!(
            mock.requests("POST", "/v1/subscriptions")[0]
                .fields_starting("items[")
                .len(),
            10
        );
        assert_eq!(item_versions(&pool, org).await.len(), 17);
        assert!(
            out.contains("warning: ") && out.contains("17 of Stripe's 20"),
            "{out}"
        );

        // Five more: three fit, two are refused, and the run says so.
        for n in &refs[17..] {
            sqlx::query(
                "INSERT INTO meters (key, service, meter, display_name, unit) \
                 VALUES ($1, 'svc', $2, $2, 'unit')",
            )
            .bind(format!("svc/{n}"))
            .bind(n)
            .execute(&pool)
            .await
            .unwrap();
            price(&pool, &format!("svc/{n}"), now, 1).await;
        }
        let (r, out) = run(&db, &mock).await;
        assert!(r.is_err(), "{out}");
        assert_eq!(mock.subscription_prices(&sub).len(), MAX_SUBSCRIPTION_ITEMS);
        assert_eq!(
            item_versions(&pool, org).await.len(),
            MAX_SUBSCRIPTION_ITEMS
        );
        assert_eq!(
            out.matches("Stripe allows at most 20 items").count(),
            2,
            "{out}"
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_meter_too_long_for_stripe_is_reported_and_the_rest_synced(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        let service = format!("s{}", "x".repeat(59));
        let meter = format!("m{}", "y".repeat(45));
        declare(&pool, &service, &[meter.as_str()]).await;
        let long = format!("{service}/{meter}");
        price(&pool, &long, now, 1).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 1).await;

        let (r, out) = run(&db, &mock).await;
        let err = r.expect_err("a meter could not be synced");
        assert!(err.to_string().contains("error(s)"), "{err}");
        assert!(
            out.contains(&format!("error: meter {long} cannot be synced to Stripe")),
            "{out}"
        );
        assert!(out.contains("longer than 100 characters"), "{out}");
        assert!(
            out.contains(&format!(
                "error: price of {long} from {now}: its meter has no Stripe meter"
            )),
            "{out}"
        );
        // Everything else went ahead.
        assert!(out.contains("created meter  svc/calls"), "{out}");
        assert_eq!(mock.counts(), (1, 1));
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn an_org_without_a_card_is_not_subscribed(pool: PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let now = now_month(&db).await;
        declare(&pool, "svc", &["calls"]).await;
        price(&pool, "svc/calls", now, 1).await;
        let org = org_with_card(&db, &pool, &mock, "acme").await;
        sqlx::query(
            "UPDATE subscriptions SET payment_method_status = 'detached' WHERE org_id = $1",
        )
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();
        run(&db, &mock).await.0.unwrap();
        assert!(subscription_of(&pool, org).await.is_none());
        assert!(mock.requests("POST", "/v1/subscriptions").is_empty());
    }
}
