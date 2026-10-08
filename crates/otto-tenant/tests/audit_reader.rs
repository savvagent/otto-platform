//! `Db::audit_trail_for_user`: a user's own global audit rows, and nothing
//! else.
//!
//! The properties that matter are exclusions — another user's rows, org-scoped
//! rows the user acted on, and rows with no actor at all — and the narrowing of
//! what a returned row says about anybody but its actor.

use otto_tenant::audit::{action, Entry};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sqlx::PgPool;

async fn user(db: &Db) -> UserId {
    sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn org(db: &Db, slug: &str) -> OrgId {
    sqlx::query_scalar("INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id")
        .bind(slug)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn actions(events: &[otto_tenant::audit::AuditEvent]) -> Vec<&str> {
    events.iter().map(|e| e.action.as_str()).collect()
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_user_reads_only_their_own_global_rows(pool: PgPool) {
    let db = Db::from_pool(pool);
    let ada = user(&db).await;
    let bob = user(&db).await;
    let acme = org(&db, "acme").await;

    db.audit_global(
        Entry::new(action::LOGIN_SUCCEEDED)
            .actor(ada)
            .from_request(Some("203.0.113.7"), None)
            .detail(serde_json::json!({ "method": "passkey" })),
    )
    .await
    .unwrap();
    // Somebody else's sign-in.
    db.audit_global(Entry::new(action::LOGIN_SUCCEEDED).actor(bob))
        .await
        .unwrap();
    // Ada acted, but inside an org: that row is the org admins' to read.
    db.audit_for_org(acme, Entry::new(action::MEMBER_INVITED).actor(ada))
        .await
        .unwrap();
    // A failed sign-in that never identified an account: nobody's.
    db.audit_global(Entry::new(action::LOGIN_FAILED).from_request(Some("198.51.100.1"), None))
        .await
        .unwrap();
    // A row *about* Ada that an admin (Bob) acted on is Bob's, not Ada's.
    db.audit_global(
        Entry::new(action::PASSKEY_CLEARED)
            .actor(bob)
            .target("user", ada.to_string()),
    )
    .await
    .unwrap();

    let mine = db.audit_trail_for_user(ada, None, 100).await.unwrap();
    assert_eq!(actions(&mine), [action::LOGIN_SUCCEEDED]);
    let row = &mine[0];
    assert_eq!(row.actor_user_id, Some(ada));
    assert_eq!(row.org_id, None);
    assert_eq!(
        row.ip.as_deref(),
        Some("203.0.113.7"),
        "the address of the user's own sign-in is theirs to see"
    );
    assert_eq!(row.detail, serde_json::json!({ "method": "passkey" }));

    let bobs = db.audit_trail_for_user(bob, None, 100).await.unwrap();
    assert_eq!(
        actions(&bobs),
        [action::PASSKEY_CLEARED, action::LOGIN_SUCCEEDED]
    );
    assert!(bobs.iter().all(|e| e.actor_user_id == Some(bob)));

    let nobody = user(&db).await;
    assert!(db
        .audit_trail_for_user(nobody, None, 100)
        .await
        .unwrap()
        .is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn the_trail_is_newest_first_filtered_by_prefix_and_limited(pool: PgPool) {
    let db = Db::from_pool(pool);
    let ada = user(&db).await;

    for a in [
        action::PASSKEY_REGISTERED,
        action::LOGIN_SUCCEEDED,
        action::PASSKEY_RENAMED,
        action::LOGOUT,
    ] {
        db.audit_global(Entry::new(a).actor(ada)).await.unwrap();
    }

    let all = db.audit_trail_for_user(ada, None, 100).await.unwrap();
    assert_eq!(
        actions(&all),
        [
            action::LOGOUT,
            action::PASSKEY_RENAMED,
            action::LOGIN_SUCCEEDED,
            action::PASSKEY_REGISTERED,
        ]
    );

    let passkeys = db
        .audit_trail_for_user(ada, Some("auth.passkey."), 100)
        .await
        .unwrap();
    assert_eq!(
        actions(&passkeys),
        [action::PASSKEY_RENAMED, action::PASSKEY_REGISTERED]
    );

    let latest = db.audit_trail_for_user(ada, None, 1).await.unwrap();
    assert_eq!(actions(&latest), [action::LOGOUT]);

    // Clamped, not refused: a zero or negative limit still answers.
    assert_eq!(
        db.audit_trail_for_user(ada, None, 0).await.unwrap().len(),
        1
    );
}

/// Nothing about a second account reaches the first through its own trail.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn rows_are_narrowed_to_what_their_actor_may_read(pool: PgPool) {
    let db = Db::from_pool(pool);
    let ada = user(&db).await;
    let mallory = user(&db).await;

    // A hijacked registration ceremony: attributed to Ada, the ceremony's
    // owner, but the request — and so its address — was Mallory's.
    db.audit_global(
        Entry::new(action::PASSKEY_REGISTRATION_REFUSED)
            .actor(ada)
            .from_request(Some("192.0.2.66"), Some("evil/1.0"))
            .detail(serde_json::json!({ "attemptedBy": mallory.to_string() })),
    )
    .await
    .unwrap();
    // A claim refusal whose reason embeds another account's id.
    db.audit_global(
        Entry::new(action::CLAIM_REFUSED)
            .actor(ada)
            .from_request(Some("192.0.2.66"), None)
            .detail(serde_json::json!({
                "reason": format!("ceremony belongs to a different account than claim code for {mallory}")
            })),
    )
    .await
    .unwrap();
    // An ordinary row with a key nobody has decided the user may see.
    db.audit_global(
        Entry::new(action::LOGIN_FAILED)
            .actor(ada)
            .from_request(Some("203.0.113.7"), None)
            .detail(serde_json::json!({
                "method": "passkey",
                "reason": "account disabled",
                "internal": "not for the account holder"
            })),
    )
    .await
    .unwrap();

    let mine = db.audit_trail_for_user(ada, None, 100).await.unwrap();
    assert_eq!(mine.len(), 3);

    let mallory_id = mallory.to_string();
    for row in &mine {
        let rendered = serde_json::to_string(row).unwrap();
        assert!(
            !rendered.contains(&mallory_id),
            "{} leaked another account's id: {rendered}",
            row.action
        );
    }

    for cross in [action::PASSKEY_REGISTRATION_REFUSED, action::CLAIM_REFUSED] {
        let row = mine.iter().find(|e| e.action == cross).unwrap();
        assert_eq!(row.detail, serde_json::json!({}), "{cross}");
        assert_eq!(row.ip, None, "{cross}: the address was the other request's");
        assert_eq!(row.user_agent, None, "{cross}");
    }

    let failed = mine
        .iter()
        .find(|e| e.action == action::LOGIN_FAILED)
        .unwrap();
    assert_eq!(
        failed.detail,
        serde_json::json!({ "method": "passkey", "reason": "account disabled" })
    );
    assert_eq!(failed.ip.as_deref(), Some("203.0.113.7"));
}

/// Count the global and org-scoped `audit_events` rows visible to `otto_app`
/// — a role RLS applies to, standing in for a non-exempt owner on managed
/// Postgres — optionally pinned to `org`.
async fn visible_as_otto_app(db: &Db, org: Option<OrgId>) -> (i64, i64) {
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE otto_app")
        .execute(&mut *tx)
        .await
        .unwrap();
    if let Some(org) = org {
        sqlx::query("SELECT set_config('app.org_id', $1, true)")
            .bind(org.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let counts = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE org_id IS NULL), \
                count(*) FILTER (WHERE org_id IS NOT NULL) \
         FROM audit_events",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    counts
}

/// `0015_audit_global_read.sql`: under RLS, the unpinned control plane reads
/// global rows and still no org's rows, and a pinned transaction still reads
/// only its own org's rows — never a global one.
///
/// The superuser tests above cannot see this: RLS does not apply to them at
/// all. Without 0015, the first assertion fails (`(0, 0)`), which is the
/// managed-Postgres deployment shape where `Db::audit_trail_for_user` would
/// have returned nothing.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn under_rls_only_the_unpinned_control_plane_reads_global_rows(pool: PgPool) {
    let db = Db::from_pool(pool);
    let ada = user(&db).await;
    let acme = org(&db, "acme").await;
    let other = org(&db, "other").await;

    db.audit_global(Entry::new(action::LOGIN_SUCCEEDED).actor(ada))
        .await
        .unwrap();
    db.audit_global(Entry::new(action::LOGIN_FAILED))
        .await
        .unwrap();
    db.audit_for_org(acme, Entry::new(action::MEMBER_INVITED).actor(ada))
        .await
        .unwrap();
    db.audit_for_org(other, Entry::new(action::MEMBER_INVITED).actor(ada))
        .await
        .unwrap();

    assert_eq!(
        visible_as_otto_app(&db, None).await,
        (2, 0),
        "unpinned: every global row, and no org's rows"
    );
    assert_eq!(
        visible_as_otto_app(&db, Some(acme)).await,
        (0, 1),
        "pinned: only this org's rows, and no global ones"
    );
}
