//! Per-service budgets through the console API, end to end against a real
//! Postgres: who may read and change them, that no bearer credential reaches
//! them, and the per-service part of the usage page.

mod common;

use chrono::Utc;
use common::{add_member, onboard, org_with_owner, Call, Harness};
use http::StatusCode;
use otto_billing::billing::mock::MockStripe;
use otto_billing::budgets::PendingBudgets;
use otto_billing::usage::{Metered, ShippedUsage, UsageExt};
use otto_core::orgs::Role;
use otto_tenant::ids::OrgId;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const THINGS: &str = "things";
const CALLS: &str = "things/calls";
const WIDGETS: &str = "widgets";
const SPINS: &str = "widgets/spins";

/// Both resource servers, with service slugs and one meter each. `things/calls`
/// costs one cent a call from this month; `widgets/spins` has no price.
async fn harness(pool: PgPool) -> Harness {
    let h = common::harness_with_two_resources(pool).await;
    for (uri, service, key, meter) in [
        (common::RESOURCE, THINGS, CALLS, "calls"),
        (common::OTHER_RESOURCE, WIDGETS, SPINS, "spins"),
    ] {
        sqlx::query("UPDATE resource_servers SET service = $2 WHERE resource_uri = $1")
            .bind(uri)
            .bind(service)
            .execute(h.db.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO meters (key, service, meter, display_name, unit) \
             VALUES ($1, $2, $3, 'Things', 'thing')",
        )
        .bind(key)
        .bind(service)
        .bind(meter)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ($1, date_trunc('month', now() AT TIME ZONE 'UTC')::date) RETURNING id",
    )
    .bind(CALLS)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, NULL, 1000000)",
    )
    .bind(version)
    .execute(h.db.pool())
    .await
    .unwrap();
    h
}

/// Ingest `quantity` of `meter` for `org`, as the platform's ingest does.
async fn ingest(h: &Harness, org: OrgId, uri: &str, service: &str, meter: &str, quantity: i64) {
    let mut tx = h.db.begin(org).await.unwrap();
    let mut budgets = PendingBudgets::default();
    tx.ingest_usage_deferred(
        uri,
        &ShippedUsage {
            event_id: Uuid::new_v4(),
            user: None,
            tool: "t",
            billable: true,
            occurred_at: Utc::now(),
            service: Some(service),
            metered: Some(Metered { meter, quantity }),
        },
        &mut budgets,
    )
    .await
    .unwrap();
    budgets.run(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
}

async fn budget_actions(h: &Harness, org: OrgId) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT action, detail FROM audit_events \
         WHERE org_id = $1 AND action LIKE 'billing.budget.%' ORDER BY id",
    )
    .bind(org)
    .fetch_all(h.db.pool())
    .await
    .unwrap()
}

async fn stored_budget(h: &Harness, org: OrgId) -> Option<(i64, bool)> {
    sqlx::query_as(
        "SELECT monthly_budget_cents, hard_stop FROM service_budgets \
         WHERE org_id = $1 AND service = $2",
    )
    .bind(org)
    .bind(THINGS)
    .fetch_optional(h.db.pool())
    .await
    .unwrap()
}

fn put(session: &str, service: &str, body: Value) -> Call {
    Call::put(format!("/api/orgs/acme/budgets/{service}"))
        .with_session(session)
        .json(body)
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn members_read_budgets_and_only_owners_and_admins_change_them(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    let admin = onboard(&h, "admin@acme.test").await;
    add_member(&h, org, admin.user, Role::Admin).await;
    let member = onboard(&h, "member@acme.test").await;
    add_member(&h, org, member.user, Role::Member).await;

    // Every metered service is listed, unbudgeted, to any member.
    let r = Call::get("/api/orgs/acme/budgets")
        .with_session(&member.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::OK);
    assert_eq!(
        r.body["services"],
        json!([
            {
                "service": THINGS, "spendCents": 0, "spendError": null,
                "thresholdsReached": [], "budget": null,
            },
            {
                "service": WIDGETS, "spendCents": 0, "spendError": null,
                "thresholdsReached": [], "budget": null,
            },
        ])
    );
    assert!(r.body["periodStart"].as_str().unwrap().ends_with("-01"));

    // A member may not set or clear one.
    let refused = put(
        &member.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000 }),
    )
    .send(&h.router)
    .await;
    refused.expect(StatusCode::FORBIDDEN);
    Call::delete("/api/orgs/acme/budgets/things")
        .with_session(&member.session)
        .send(&h.router)
        .await
        .expect(StatusCode::FORBIDDEN);
    assert_eq!(stored_budget(&h, org).await, None);

    // An admin may, and it is audited.
    let set = put(
        &admin.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000, "hardStop": true }),
    )
    .send(&h.router)
    .await;
    set.expect(StatusCode::OK);
    assert_eq!(set.body["service"], THINGS);
    assert_eq!(set.body["budget"]["monthlyBudgetCents"], 1000);
    assert_eq!(set.body["budget"]["hardStop"], true);
    assert_eq!(set.body["budget"]["percentUsed"], 0);
    assert_eq!(set.body["budget"]["blocked"], false);
    assert_eq!(stored_budget(&h, org).await, Some((1000, true)));
    let updated_by: Option<Uuid> = sqlx::query_scalar("SELECT updated_by FROM service_budgets")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(updated_by, Some(admin.user.as_uuid()));

    // So may an owner; `hardStop` defaults to off.
    put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 2500 }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);
    assert_eq!(stored_budget(&h, org).await, Some((2500, false)));

    // The member sees it.
    let r = Call::get("/api/orgs/acme/budgets")
        .with_session(&member.session)
        .send(&h.router)
        .await;
    assert_eq!(r.body["services"][0]["budget"]["monthlyBudgetCents"], 2500);
    assert_eq!(r.body["services"][1]["budget"], Value::Null);

    // Clearing is owner or admin too, idempotent, and audited when it removed one.
    for _ in 0..2 {
        Call::delete("/api/orgs/acme/budgets/things")
            .with_session(&owner.session)
            .send(&h.router)
            .await
            .expect(StatusCode::NO_CONTENT);
    }
    assert_eq!(stored_budget(&h, org).await, None);

    let audit = budget_actions(&h, org).await;
    let actions: Vec<&str> = audit.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "billing.budget.set",
            "billing.budget.set",
            "billing.budget.cleared"
        ]
    );
    assert_eq!(audit[0].1["monthlyBudgetCents"], 1000);
    assert_eq!(audit[0].1["previous"], Value::Null);
    assert_eq!(
        audit[1].1["previous"],
        json!({ "monthlyBudgetCents": 1000, "hardStop": true })
    );
    assert_eq!(audit[2].1["monthlyBudgetCents"], 2500);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn unknown_services_and_out_of_range_budgets_are_refused(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    // A resource server with no meters is not budgetable either.
    sqlx::query(
        "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
         VALUES ('https://bare.example/mcp', 'bare', '{a}', '{}', 'bare')",
    )
    .execute(h.db.pool())
    .await
    .unwrap();

    let long = "a".repeat(64);
    for service in [
        "nope",
        "bare",
        "things%2Fcalls",
        "Things",
        "a%00b",
        long.as_str(),
    ] {
        let r = put(
            &owner.session,
            service,
            json!({ "monthlyBudgetCents": 100 }),
        )
        .send(&h.router)
        .await;
        r.expect(StatusCode::NOT_FOUND);
        assert!(
            !r.text.contains(service),
            "the slug is not echoed: {}",
            r.text
        );
        Call::delete(format!("/api/orgs/acme/budgets/{service}"))
            .with_session(&owner.session)
            .send(&h.router)
            .await
            .expect(StatusCode::NOT_FOUND);
    }

    for cents in [json!(0), json!(-5), json!(1_000_000_001_i64)] {
        put(
            &owner.session,
            THINGS,
            json!({ "monthlyBudgetCents": cents }),
        )
        .send(&h.router)
        .await
        .expect(StatusCode::BAD_REQUEST);
    }
    // The upper bound itself is fine.
    put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1_000_000_000_i64 }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);

    // Malformed bodies are a 400 in the console's error shape, and change
    // nothing.
    for body in [
        json!({}),
        json!({ "monthlyBudgetCents": "100" }),
        json!({ "monthlyBudgetCents": 100, "surprise": true }),
    ] {
        let r = put(&owner.session, THINGS, body).send(&h.router).await;
        r.expect(StatusCode::BAD_REQUEST);
        assert_eq!(r.error_code(), Some("invalid_request"));
    }
    assert_eq!(stored_budget(&h, org).await, Some((1_000_000_000, false)));
    assert_eq!(budget_actions(&h, org).await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_bearer_token_or_pat_cannot_change_a_budget(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000 }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);

    // The owner's own personal access token, with every scope the server has.
    let minted = Call::post("/api/orgs/acme/tokens")
        .with_session(&owner.session)
        .json(json!({
            "name": "agent",
            "resource": common::RESOURCE,
            "scopes": common::RESOURCE_SCOPES,
        }))
        .send(&h.router)
        .await;
    minted.expect(StatusCode::CREATED);
    let pat = minted.body["token"].as_str().unwrap().to_owned();
    assert!(pat.starts_with("otto_pat_"));

    for call in [
        Call::put("/api/orgs/acme/budgets/things")
            .json(json!({ "monthlyBudgetCents": 999_999, "hardStop": true })),
        Call::delete("/api/orgs/acme/budgets/things"),
        Call::get("/api/orgs/acme/budgets"),
    ] {
        let r = call
            .header("authorization", format!("Bearer {pat}"))
            .send(&h.router)
            .await;
        r.expect(StatusCode::UNAUTHORIZED);
    }
    // No credential at all is refused the same way.
    Call::delete("/api/orgs/acme/budgets/things")
        .send(&h.router)
        .await
        .expect(StatusCode::UNAUTHORIZED);

    assert_eq!(stored_budget(&h, org).await, Some((1000, false)));
    assert_eq!(budget_actions(&h, org).await.len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn budget_writes_from_another_site_are_refused(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;

    let forged = put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000 }),
    )
    .header("origin", "https://evil.otto.test")
    .send(&h.router)
    .await;
    forged.expect(StatusCode::FORBIDDEN);
    assert_eq!(forged.error_code(), Some("cross_site_request"));
    let forged = Call::delete("/api/orgs/acme/budgets/things")
        .with_session(&owner.session)
        .header("origin", "null")
        .send(&h.router)
        .await;
    forged.expect(StatusCode::FORBIDDEN);
    assert_eq!(stored_budget(&h, org).await, None);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn spend_thresholds_and_the_usage_page_are_per_service(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000, "hardStop": true }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);
    put(
        &owner.session,
        WIDGETS,
        json!({ "monthlyBudgetCents": 1, "hardStop": true }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);

    // 850 calls at a cent: 85% of the things budget. Unpriced spins add nothing.
    ingest(&h, org, common::RESOURCE, THINGS, CALLS, 850).await;
    ingest(&h, org, common::OTHER_RESOURCE, WIDGETS, SPINS, 1_000_000).await;

    let r = Call::get("/api/orgs/acme/budgets")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    r.expect(StatusCode::OK);
    let things = &r.body["services"][0];
    assert_eq!(things["spendCents"], 850);
    assert_eq!(things["thresholdsReached"], json!([50, 80]));
    assert_eq!(things["budget"]["percentUsed"], 85);
    assert_eq!(things["budget"]["blocked"], false);
    let widgets = &r.body["services"][1];
    assert_eq!(widgets["spendCents"], 0);
    assert_eq!(widgets["thresholdsReached"], json!([]));
    assert_eq!(widgets["budget"]["blocked"], false);

    // Past the things budget, things is blocked and widgets is not.
    ingest(&h, org, common::RESOURCE, THINGS, CALLS, 200).await;
    let usage = Call::get("/api/orgs/acme/usage")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    usage.expect(StatusCode::OK);
    // The legacy fields are all still there.
    for field in [
        "plan",
        "includedOps",
        "billableUsed",
        "remaining",
        "totalCalls",
        "periodStart",
        "warning",
        "hardStop",
        "enforced",
    ] {
        assert!(usage.body.get(field).is_some(), "{field} is missing");
    }
    assert_eq!(usage.body["billableUsed"], 3);
    assert_eq!(
        usage.body["services"][0],
        json!({
            "service": THINGS,
            "meters": [{
                "meter": CALLS, "displayName": "Things", "unit": "thing", "quantity": 1050,
            }],
            "spendCents": 1050,
            "spendError": null,
            "budget": usage.body["services"][0]["budget"].clone(),
            // Billing is off in this harness, so nobody could add a card and
            // none is asked for (the billing-on case follows).
            "paymentRequired": false,
        })
    );
    assert_eq!(
        usage.body["hardStop"], false,
        "the legacy flag is never served, as in /internal"
    );
    assert_eq!(usage.body["services"][0]["budget"]["percentUsed"], 105);
    assert_eq!(usage.body["services"][0]["budget"]["blocked"], true);
    assert_eq!(usage.body["services"][1]["service"], WIDGETS);
    assert_eq!(
        usage.body["services"][1]["meters"][0]["quantity"],
        1_000_000
    );
    assert_eq!(usage.body["services"][1]["spendCents"], 0);
    assert_eq!(usage.body["services"][1]["budget"]["blocked"], false);
    assert_eq!(
        usage.body["services"][1]["paymentRequired"], false,
        "free usage never needs a card"
    );

    // With billing on, the same org, with no subscription and spend past
    // zero, is asked for a card for that service only.
    let mock = MockStripe::start().await;
    let config = otto_web::Config::new(common::PUBLIC_URL);
    let webauthn = otto_web::relying_party(&config).unwrap();
    let billed = otto_web::router(
        otto_web::AppState::new(h.db.clone(), common::cipher(), webauthn, config).with_stripe(
            Some(otto_billing::billing::Stripe {
                client: mock.client(),
                webhook_secret: otto_billing::stripe::WebhookSecret::new("whsec_test_budgets")
                    .unwrap(),
            }),
        ),
    );
    let usage = Call::get("/api/orgs/acme/usage")
        .with_session(&owner.session)
        .send(&billed)
        .await;
    usage.expect(StatusCode::OK);
    assert_eq!(usage.body["services"][0]["paymentRequired"], true);
    assert_eq!(usage.body["services"][1]["paymentRequired"], false);

    // A live subscription: nothing needs a card.
    sqlx::query(
        "INSERT INTO subscriptions (org_id, stripe_customer_id, stripe_subscription_id, status) \
         VALUES ($1, 'cus_acme', 'sub_acme', 'active') \
         ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = 'cus_acme', \
           stripe_subscription_id = 'sub_acme', status = 'active'",
    )
    .bind(org)
    .execute(h.db.pool())
    .await
    .unwrap();
    let usage = Call::get("/api/orgs/acme/usage")
        .with_session(&owner.session)
        .send(&billed)
        .await;
    usage.expect(StatusCode::OK);
    assert_eq!(usage.body["services"][0]["paymentRequired"], false);
    assert_eq!(usage.body["services"][1]["paymentRequired"], false);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_member_is_refused_before_the_body_is_read(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    let member = onboard(&h, "member@acme.test").await;
    add_member(&h, org, member.user, Role::Member).await;

    for body in [json!({}), json!("junk")] {
        put(&member.session, THINGS, body)
            .send(&h.router)
            .await
            .expect(StatusCode::FORBIDDEN);
    }
    // And before the service is looked at.
    put(&member.session, "nope", json!({ "monthlyBudgetCents": 1 }))
        .send(&h.router)
        .await
        .expect(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_pricing_fault_degrades_only_its_own_service(pool: PgPool) {
    let h = harness(pool).await;
    let owner = onboard(&h, "owner@acme.test").await;
    let org = org_with_owner(&h, "acme", &owner).await;
    put(
        &owner.session,
        WIDGETS,
        json!({ "monthlyBudgetCents": 100, "hardStop": true }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);
    put(
        &owner.session,
        THINGS,
        json!({ "monthlyBudgetCents": 1000 }),
    )
    .send(&h.router)
    .await
    .expect(StatusCode::OK);
    ingest(&h, org, common::RESOURCE, THINGS, CALLS, 300).await;
    ingest(&h, org, common::OTHER_RESOURCE, WIDGETS, SPINS, 5).await;
    // A widgets price edited by hand into a shape the rater refuses: a
    // bounded last tier.
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO price_versions (meter, effective_month) \
         VALUES ($1, date_trunc('month', now() AT TIME ZONE 'UTC')::date) RETURNING id",
    )
    .bind(SPINS)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
         VALUES ($1, 0, 10, 1000000)",
    )
    .bind(version)
    .execute(h.db.pool())
    .await
    .unwrap();

    let usage = Call::get("/api/orgs/acme/usage")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    usage.expect(StatusCode::OK);
    assert_eq!(
        usage.body["billableUsed"], 2,
        "the legacy fields still answer"
    );
    assert_eq!(usage.body["plan"], "Free");
    let things = &usage.body["services"][0];
    assert_eq!(
        (things["spendCents"].clone(), things["spendError"].clone()),
        (json!(300), Value::Null)
    );
    let widgets = &usage.body["services"][1];
    assert_eq!(widgets["service"], WIDGETS);
    assert_eq!(widgets["meters"][0]["quantity"], 5);
    assert_eq!(widgets["spendCents"], Value::Null);
    assert_eq!(widgets["spendError"], "pricing_unavailable");
    assert_eq!(
        widgets["paymentRequired"], false,
        "unknown spend never needs a card"
    );
    assert_eq!(widgets["budget"]["percentUsed"], Value::Null);
    assert_eq!(
        widgets["budget"]["blocked"], false,
        "unknown spend never blocks"
    );

    let budgets = Call::get("/api/orgs/acme/budgets")
        .with_session(&owner.session)
        .send(&h.router)
        .await;
    budgets.expect(StatusCode::OK);
    assert_eq!(budgets.body["services"][0]["spendCents"], 300);
    assert_eq!(budgets.body["services"][0]["budget"]["percentUsed"], 30);
    assert_eq!(
        budgets.body["services"][1]["spendError"],
        "pricing_unavailable"
    );
    assert_eq!(
        budgets.body["services"][1]["budget"]["monthlyBudgetCents"],
        100
    );
}
