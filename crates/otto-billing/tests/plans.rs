//! `plans::list_plans`: the public catalog, read on an unpinned transaction.
//!
//! Run against the seeded `plans` rows (migrations 0003 and 0016), because the
//! property that matters is that what the pricing page shows is what the
//! database holds, in the order a buyer reads tiers: cheapest first.

use otto_billing::plans::list_plans;
use otto_core::orgs::Plan;
use otto_tenant::Db;
use sqlx::PgPool;

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn every_plan_is_listed_in_tier_order(pool: PgPool) {
    let db = Db::from_pool(pool);
    let mut tx = db.begin_unpinned().await.unwrap();
    let plans = list_plans(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let order: Vec<Plan> = plans.iter().map(|p| p.plan).collect();
    assert_eq!(
        order,
        [Plan::Free, Plan::Team, Plan::Business, Plan::Enterprise]
    );

    let free = &plans[0];
    assert_eq!(free.monthly_cents, 0);

    let team = &plans[1];
    assert_eq!(team.display_name, "Team");
    assert_eq!(team.monthly_cents, 2900);
    assert_eq!(team.features["auto_rollback"], serde_json::json!(true));
}
