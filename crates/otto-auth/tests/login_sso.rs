//! DB-backed tests for the `enforce_sso` refusal in `otto_auth::login`.
//!
//! otto-factory covered this only through its HTTP-level suite
//! (`of-web/tests/sso.rs`), which has no counterpart here until Phase 4; these
//! exercise `login::with_passkey` directly. The passkey ceremony itself is not
//! involved: `with_passkey` runs *after* a ceremony has already identified the
//! account, so handing it a `UserId` is exactly the state it sees in
//! production.

use otto_auth::login;
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::audit::action;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sqlx::PgPool;

async fn member(db: &Db, org: OrgId, email: &str, role: Role) -> UserId {
    let user = db.upsert_user(email, None).await.expect("create user");
    db.add_member(org, user.id, role).await.expect("add member");
    user.id
}

/// Flip the flag directly, bypassing `orgs::set_enforce_sso`'s lockout guards
/// (which are covered in otto-core's own suite): this test is about what login
/// does once enforcement is on, not about how it got turned on.
async fn enforce_sso(pool: &PgPool, org: OrgId) {
    sqlx::query("UPDATE orgs SET enforce_sso = true WHERE id = $1")
        .bind(org)
        .execute(pool)
        .await
        .expect("enable enforce_sso");
}

async fn audit_count(pool: &PgPool, user: UserId, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE actor_user_id = $1 AND action = $2")
        .bind(user)
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("count audit events")
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn passkey_login_is_refused_for_a_member_of_an_enforce_sso_org(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = member(&db, org.id, "alice@acme.test", Role::Member).await;
    enforce_sso(&pool, org.id).await;

    let err = login::with_passkey(&db, user, Some("203.0.113.9"))
        .await
        .err()
        .expect("passkey login must be refused");
    assert!(matches!(err, AuthError::SsoRequired), "got {err:?}");

    assert_eq!(audit_count(&pool, user, action::LOGIN_FAILED).await, 1);
    assert_eq!(audit_count(&pool, user, action::LOGIN_SUCCEEDED).await, 0);

    // The refusal came before a session was minted.
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM browser_sessions WHERE user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sessions, 0);
}

/// `enforce_sso` is scoped to org membership: belonging to one enforcing org
/// is enough, even if the same account also belongs to a non-enforcing one.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn one_enforcing_org_among_several_is_enough_to_refuse(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let plain = db.create_org("plain", "Plain").await.unwrap();
    let strict = db.create_org("strict", "Strict").await.unwrap();
    let user = member(&db, plain.id, "bob@plain.test", Role::Owner).await;
    db.add_member(strict.id, user, Role::Member).await.unwrap();
    enforce_sso(&pool, strict.id).await;

    let err = login::with_passkey(&db, user, None)
        .await
        .err()
        .expect("refused");
    assert!(matches!(err, AuthError::SsoRequired), "got {err:?}");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn passkey_login_still_works_when_no_org_enforces_sso(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = member(&db, org.id, "carol@acme.test", Role::Member).await;

    let logged_in = login::with_passkey(&db, user, None)
        .await
        .expect("no org enforces SSO");
    assert_eq!(logged_in.user, user);
    assert_eq!(audit_count(&pool, user, action::LOGIN_SUCCEEDED).await, 1);
}

/// The flag belongs to the org, not to the people outside it: an enforcing
/// org must not affect an account that is not one of its members.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn an_enforcing_org_does_not_affect_non_members(pool: PgPool) {
    let db = Db::from_pool(pool.clone());
    let strict = db.create_org("strict", "Strict").await.unwrap();
    let other = db.create_org("other", "Other").await.unwrap();
    let outsider = member(&db, other.id, "dave@other.test", Role::Member).await;
    enforce_sso(&pool, strict.id).await;

    login::with_passkey(&db, outsider, None)
        .await
        .expect("not a member of the enforcing org");
}
