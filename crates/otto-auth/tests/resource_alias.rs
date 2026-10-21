//! Moving a resource server to a new canonical URI, with the old one kept as
//! a time-boxed alias (savvagent/otto-platform#88, design D1): the rename and
//! its rewrites, the swap rollback, tombstones and collision refusals, alias
//! resolution, and introspection authentication through an alias.

use chrono::{DateTime, Duration, Utc};
use otto_auth::resources::{self, AliasState, ResourceServerSpec};
use otto_auth::tokens::{self, IssueParams};
use otto_auth::AuthError;
use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sqlx::PgPool;
use uuid::Uuid;

const OLD: &str = "https://otto-factory.example/mcp";
const NEW: &str = "https://otto-tower.example/mcp";
const FLAGS: &str = "https://otto-flags.example/mcp";

async fn register(db: &Db, uri: &str, name: &str) -> resources::ResourceServer {
    resources::register(
        db,
        ResourceServerSpec {
            resource_uri: uri,
            name,
            scopes: &["jobs:read", "jobs:write"],
            default_scopes: &["jobs:read"],
        },
    )
    .await
    .unwrap()
}

async fn member(db: &Db) -> (UserId, OrgId) {
    let org = db.create_org("acme", "Acme").await.unwrap();
    let user = db.upsert_user("dev@acme.example", None).await.unwrap();
    db.add_member(org.id, user.id, Role::Owner).await.unwrap();
    (user.id, org.id)
}

fn sunset() -> DateTime<Utc> {
    Utc::now() + Duration::days(90)
}

/// An access token (with a refresh token) for `resource`; returns the access
/// token.
async fn token(db: &Db, user: UserId, org: OrgId, resource: &str) -> String {
    tokens::issue(
        db,
        IssueParams {
            user_id: user,
            org_id: org,
            client_id: Some("agent"),
            scopes: &["jobs:read".to_owned()],
            resource,
            with_refresh: true,
        },
    )
    .await
    .unwrap()
    .access_token
}

/// An unconsumed authorization code for `resource`, written directly.
async fn code(db: &Db, user: UserId, org: OrgId, resource: &str) {
    sqlx::query(
        "INSERT INTO authorization_codes \
           (code_hash, client_id, user_id, org_id, redirect_uri, code_challenge, scopes, \
            resource, expires_at) \
         VALUES ($1, 'agent', $2, $3, 'http://127.0.0.1/cb', 'challenge', '{jobs:read}', $4, \
                 now() + interval '5 minutes')",
    )
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(user.as_uuid())
    .bind(org.as_uuid())
    .bind(resource)
    .execute(db.pool())
    .await
    .unwrap();
}

async fn claim(db: &Db, resource: &str, event: Uuid, org: OrgId) -> String {
    sqlx::query_scalar("SELECT claim_usage_event($1, $2, $3)")
        .bind(resource)
        .bind(event)
        .bind(org.as_uuid())
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn count(db: &Db, table: &str, column: &str, value: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE {column} = $1"))
        .bind(value)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Ages an alias past its sunset, as only time (or a superuser) can.
async fn expire(db: &Db, alias: &str) {
    sqlx::query(
        "UPDATE resource_server_aliases SET sunset_at = now() - interval '1 second' \
         WHERE alias_uri = $1",
    )
    .bind(alias)
    .execute(db.pool())
    .await
    .unwrap();
}

fn refused(err: &AuthError) -> bool {
    matches!(err, AuthError::InvalidRequest(_))
}

// ---- the rename ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_moves_the_canonical_uri_and_everything_that_names_it(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    register(&db, FLAGS, "otto-flags").await;
    let (user, org) = member(&db).await;
    let old_token = token(&db, user, org, OLD).await;
    let flags_token = token(&db, user, org, FLAGS).await;
    code(&db, user, org, OLD).await;
    code(&db, user, org, FLAGS).await;
    let event = Uuid::new_v4();
    assert_eq!(claim(&db, OLD, event, org).await, "new");
    claim(&db, FLAGS, Uuid::new_v4(), org).await;

    let until = sunset();
    let r = resources::rename(&db, OLD, NEW, Some(until), Some("otto-tower"))
        .await
        .unwrap();
    assert!(!r.swapped);
    assert_eq!(r.previous_uri, OLD);
    assert_eq!(r.resource.resource_uri, NEW);
    assert_eq!(r.resource.name, "otto-tower");
    assert_eq!(r.alias.alias_uri, OLD);
    assert_eq!(r.alias.resource_uri, NEW);
    assert_eq!(r.alias.sunset_at.timestamp(), until.timestamp());
    assert_eq!(r.alias.state(), AliasState::Live);
    assert_eq!(r.rewritten.access_tokens, 1);
    assert_eq!(r.rewritten.refresh_tokens, 1);
    assert_eq!(r.rewritten.authorization_codes, 1);
    assert_eq!(r.rewritten.usage_event_ids, 1);

    // Every row that named the old URI names the new one; the sibling's are
    // untouched.
    for (table, column) in [
        ("access_tokens", "resource"),
        ("refresh_tokens", "resource"),
        ("authorization_codes", "resource"),
        ("usage_event_ids", "resource_uri"),
    ] {
        assert_eq!(count(&db, table, column, OLD).await, 0, "{table}");
        assert_eq!(count(&db, table, column, NEW).await, 1, "{table}");
        assert_eq!(count(&db, table, column, FLAGS).await, 1, "{table}");
    }
    assert!(resources::get(&db, OLD).await.unwrap().is_none());

    // The old token is good for the canonical URI.
    let p = tokens::introspect(&db, &old_token, NEW).await.unwrap();
    assert_eq!(p.org_id, org);
    assert!(tokens::introspect(&db, &flags_token, FLAGS).await.is_ok());

    // Dedupe survives, whichever URI the event is claimed under.
    assert_eq!(claim(&db, NEW, event, org).await, "duplicate");
    assert_eq!(claim(&db, OLD, event, org).await, "duplicate");
    // And a new event claimed under the alias is recorded under canonical.
    let fresh = Uuid::new_v4();
    assert_eq!(claim(&db, OLD, fresh, org).await, "new");
    assert_eq!(claim(&db, NEW, fresh, org).await, "duplicate");
    assert_eq!(count(&db, "usage_event_ids", "resource_uri", OLD).await, 0);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn without_a_name_the_rename_keeps_the_name(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let r = resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    assert_eq!(r.resource.name, "otto-factory");
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn resolve_finds_the_canonical_row_by_either_uri(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();

    let by_new = resources::resolve(&db, NEW).await.unwrap().unwrap();
    assert_eq!(by_new.server.resource_uri, NEW);
    assert_eq!(by_new.named_as, NEW);
    assert!(by_new.alias.is_none());

    let by_old = resources::resolve(&db, OLD).await.unwrap().unwrap();
    assert_eq!(by_old.server.resource_uri, NEW, "the row stays canonical");
    assert_eq!(
        by_old.named_as, OLD,
        "the URI it was named by is kept apart"
    );
    assert_eq!(by_old.alias.as_ref().unwrap().alias_uri, OLD);

    assert!(resources::resolve(&db, "https://nobody.example/mcp")
        .await
        .unwrap()
        .is_none());

    // Expired and dropped aliases resolve to nothing, like unknown URIs.
    expire(&db, OLD).await;
    assert!(resources::resolve(&db, OLD).await.unwrap().is_none());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_is_validated(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;

    // An unknown resource.
    let err = resources::rename(&db, "https://nobody.example/mcp", NEW, Some(sunset()), None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTarget(_)), "{err:?}");
    // No sunset, a past one, a bad URI, the same URI, a blank name.
    for (new, until, name) in [
        (NEW, None, None),
        (NEW, Some(Utc::now() - Duration::minutes(1)), None),
        ("http://otto-tower.example/mcp", Some(sunset()), None),
        ("https://otto-tower.example/mcp#x", Some(sunset()), None),
        (OLD, Some(sunset()), None),
        (NEW, Some(sunset()), Some("  ")),
    ] {
        let err = resources::rename(&db, OLD, new, until, name)
            .await
            .unwrap_err();
        assert!(refused(&err), "{new} {until:?} {name:?}: {err:?}");
    }
    // Nothing changed.
    assert!(resources::get(&db, OLD).await.unwrap().is_some());
    assert!(resources::aliases(&db).await.unwrap().is_empty());

    // An alias cannot itself be renamed: the canonical URI is.
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    let err = resources::rename(&db, OLD, "https://third.example/mcp", Some(sunset()), None)
        .await
        .unwrap_err();
    assert!(refused(&err), "{err:?}");
}

// ---- tombstones and collisions ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn register_and_rename_refuse_every_alias_live_or_dead(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    register(&db, FLAGS, "otto-flags").await;
    const DEAD: &str = "https://dead.example/mcp";
    const DROPPED: &str = "https://dropped.example/mcp";
    // FLAGS -> DEAD -> DROPPED -> FLAGS2, leaving two aliases of FLAGS2 behind,
    // one expired and one dropped; and OLD -> NEW with a live alias.
    const FLAGS2: &str = "https://otto-flags-2.example/mcp";
    resources::rename(&db, FLAGS, DEAD, Some(sunset()), None)
        .await
        .unwrap();
    resources::rename(&db, DEAD, DROPPED, Some(sunset()), None)
        .await
        .unwrap();
    resources::rename(&db, DROPPED, FLAGS2, Some(sunset()), None)
        .await
        .unwrap();
    expire(&db, DEAD).await;
    resources::drop_alias(&db, DROPPED).await.unwrap();
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();

    // Earlier aliases follow the server to its newest canonical URI.
    let all = resources::aliases(&db).await.unwrap();
    assert!(all.iter().all(|a| a.alias_uri != NEW));
    for a in &all {
        let expect = if a.alias_uri == OLD { NEW } else { FLAGS2 };
        assert_eq!(a.resource_uri, expect, "{a:?}");
    }

    for taken in [OLD, FLAGS, DEAD, DROPPED] {
        let err = resources::register(
            &db,
            ResourceServerSpec {
                resource_uri: taken,
                name: "squatter",
                scopes: &["x"],
                default_scopes: &[],
            },
        )
        .await
        .unwrap_err();
        assert!(refused(&err), "register {taken}: {err:?}");
        assert!(
            resources::get(&db, taken).await.unwrap().is_none(),
            "{taken}"
        );
    }
    // Re-registering a canonical URI is still the idempotent update.
    register(&db, NEW, "otto-tower").await;

    // A rename onto any URI in use: another canonical, or an alias of either
    // server, live, expired or dropped. Only a live alias of the server
    // itself is the swap below.
    for (from, onto) in [
        (NEW, FLAGS2),
        (NEW, FLAGS),
        (NEW, DEAD),
        (NEW, DROPPED),
        (FLAGS2, OLD),
        (FLAGS2, NEW),
        (FLAGS2, DEAD),
        (FLAGS2, DROPPED),
    ] {
        let err = resources::rename(&db, from, onto, Some(sunset()), None)
            .await
            .unwrap_err();
        assert!(refused(&err), "rename {from} -> {onto}: {err:?}");
    }
    assert!(resources::get(&db, NEW).await.unwrap().is_some());
    assert!(resources::get(&db, FLAGS2).await.unwrap().is_some());
    assert_eq!(resources::aliases(&db).await.unwrap().len(), 4);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn alias_rows_are_never_deleted(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    let err = sqlx::query("DELETE FROM resource_server_aliases")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("never deleted"), "{err}");
    assert_eq!(resources::aliases(&db).await.unwrap().len(), 1);
}

// ---- dropping ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn drop_alias_marks_it_dropped_once(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();

    let dropped = resources::drop_alias(&db, OLD).await.unwrap();
    assert_eq!(dropped.alias.state(), AliasState::Dropped);
    let at = dropped.alias.dropped_at.unwrap();
    assert!(resources::resolve(&db, OLD).await.unwrap().is_none());

    // Again is a no-op that keeps the first time.
    let again = resources::drop_alias(&db, OLD).await.unwrap();
    assert_eq!(again.alias.dropped_at, Some(at));

    // Not an alias at all.
    for uri in [NEW, "https://nobody.example/mcp"] {
        let err = resources::drop_alias(&db, uri).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidTarget(_)), "{uri}: {err:?}");
    }
    assert_eq!(
        resources::aliases_of(&db, NEW).await.unwrap()[0].alias_uri,
        OLD
    );
}

/// Grants minted under the old URI by a request that raced the rename stay
/// good for the server while the alias lives or merely expires; dropping it
/// revokes them in the same transaction, so a dropped alias leaves no live
/// credential bound to it. Grants under the canonical URI are untouched, and
/// dropping again is safe.
#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn drop_alias_revokes_the_grants_still_bound_to_it(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let (user, org) = member(&db).await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    let raced = token(&db, user, org, OLD).await;
    code(&db, user, org, OLD).await;
    let canonical = token(&db, user, org, NEW).await;
    code(&db, user, org, NEW).await;
    assert!(tokens::introspect(&db, &raced, NEW).await.is_ok());

    let dropped = resources::drop_alias(&db, OLD).await.unwrap();
    assert_eq!(
        dropped.revoked,
        resources::GrantRevocations {
            access_tokens: 1,
            refresh_tokens: 1,
            authorization_codes: 1,
        }
    );
    assert!(tokens::introspect(&db, &raced, NEW).await.is_err());
    assert!(tokens::introspect(&db, &canonical, NEW).await.is_ok());
    let usable = |table: &'static str, cond: &'static str| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT count(*) FROM {table} WHERE resource = $1 AND {cond}"
            ))
            .bind(OLD)
            .fetch_one(db.pool())
            .await
            .unwrap()
        }
    };
    assert_eq!(usable("access_tokens", "revoked_at IS NULL").await, 0);
    assert_eq!(usable("refresh_tokens", "revoked_at IS NULL").await, 0);
    assert_eq!(
        usable("authorization_codes", "consumed_at IS NULL").await,
        0
    );
    let live_canonical_codes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM authorization_codes WHERE resource = $1 AND consumed_at IS NULL",
    )
    .bind(NEW)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(live_canonical_codes, 1);

    // Again: nothing left to revoke, the first drop time kept.
    let again = resources::drop_alias(&db, OLD).await.unwrap();
    assert_eq!(again.revoked, resources::GrantRevocations::default());
    assert_eq!(again.alias.dropped_at, dropped.alias.dropped_at);
}

// ---- the swap rollback ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn renaming_back_onto_a_live_alias_swaps_the_two_uris(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let (user, org) = member(&db).await;
    let t = token(&db, user, org, OLD).await;
    let event = Uuid::new_v4();
    claim(&db, OLD, event, org).await;
    let until = sunset();
    resources::rename(&db, OLD, NEW, Some(until), Some("otto-tower"))
        .await
        .unwrap();
    // A token minted after the rename, for the new URI.
    let t2 = token(&db, user, org, NEW).await;

    let back = resources::rename(&db, NEW, OLD, None, Some("otto-factory"))
        .await
        .unwrap();
    assert!(back.swapped);
    assert_eq!(back.resource.resource_uri, OLD);
    assert_eq!(back.resource.name, "otto-factory");
    assert_eq!(back.alias.alias_uri, NEW, "the retired URI stays reserved");
    assert_eq!(back.alias.resource_uri, OLD);
    assert_eq!(back.alias.sunset_at.timestamp(), until.timestamp());
    assert_eq!(back.rewritten.access_tokens, 2);

    let all = resources::aliases(&db).await.unwrap();
    assert_eq!(all.len(), 1, "{all:?}");
    assert!(resources::get(&db, NEW).await.unwrap().is_none());
    for t in [&t, &t2] {
        assert!(tokens::introspect(&db, t, OLD).await.is_ok());
    }
    assert_eq!(claim(&db, OLD, event, org).await, "duplicate");
    assert_eq!(claim(&db, NEW, event, org).await, "duplicate");

    // And forward again, with a new sunset this time.
    let later = until + Duration::days(30);
    let fwd = resources::rename(&db, OLD, NEW, Some(later), None)
        .await
        .unwrap();
    assert!(fwd.swapped);
    assert_eq!(fwd.resource.resource_uri, NEW);
    assert_eq!(fwd.alias.alias_uri, OLD);
    assert_eq!(fwd.alias.sunset_at.timestamp(), later.timestamp());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_dead_alias_cannot_be_swapped_back(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    expire(&db, OLD).await;
    let err = resources::rename(&db, NEW, OLD, None, None)
        .await
        .unwrap_err();
    assert!(refused(&err), "{err:?}");

    sqlx::query("UPDATE resource_server_aliases SET sunset_at = now() + interval '1 day'")
        .execute(db.pool())
        .await
        .unwrap();
    resources::drop_alias(&db, OLD).await.unwrap();
    let err = resources::rename(&db, NEW, OLD, Some(sunset()), None)
        .await
        .unwrap_err();
    assert!(refused(&err), "{err:?}");
    assert_eq!(
        resources::get(&db, NEW)
            .await
            .unwrap()
            .unwrap()
            .resource_uri,
        NEW
    );
}

// ---- introspection authentication ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_resource_server_authenticates_as_its_canonical_uri_or_a_live_alias(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    register(&db, FLAGS, "otto-flags").await;
    let secret = resources::rotate_introspection_secret(&db, OLD)
        .await
        .unwrap();
    let flags_secret = resources::rotate_introspection_secret(&db, FLAGS)
        .await
        .unwrap();
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();

    for uri in [OLD, NEW] {
        let a = resources::authenticate_introspection(&db, uri, &secret)
            .await
            .unwrap();
        assert_eq!(a.server.resource_uri, NEW, "{uri}");
        assert_eq!(a.named_as, uri);
    }
    // The alias is not a way in for another server's credential.
    let err = resources::authenticate_introspection(&db, OLD, &flags_secret)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidClient(_)), "{err:?}");

    // A disabled server is refused through its alias too.
    resources::set_disabled(&db, NEW, true).await.unwrap();
    assert!(resources::authenticate_introspection(&db, OLD, &secret)
        .await
        .is_err());
    resources::set_disabled(&db, NEW, false).await.unwrap();

    // Expired, then dropped: the same refusal as an unknown URI.
    expire(&db, OLD).await;
    let err = resources::authenticate_introspection(&db, OLD, &secret)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidClient(_)), "{err:?}");
    sqlx::query("UPDATE resource_server_aliases SET sunset_at = now() + interval '1 day'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(resources::authenticate_introspection(&db, OLD, &secret)
        .await
        .is_ok());
    resources::drop_alias(&db, OLD).await.unwrap();
    let err = resources::authenticate_introspection(&db, OLD, &secret)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidClient(_)), "{err:?}");
    assert!(resources::authenticate_introspection(&db, NEW, &secret)
        .await
        .is_ok());
}

// ---- races and guards ----

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_token_minted_under_the_old_uri_after_the_rename_is_still_good(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    register(&db, FLAGS, "otto-flags").await;
    let (user, org) = member(&db).await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    // What a mint that read the old canonical URI before the rename committed
    // writes after it.
    let late = token(&db, user, org, OLD).await;
    assert_eq!(count(&db, "access_tokens", "resource", OLD).await, 1);
    assert!(tokens::introspect(&db, &late, NEW).await.is_ok());
    // Still only for its own server, and still good once the alias expires.
    assert!(matches!(
        tokens::introspect(&db, &late, FLAGS).await,
        Err(AuthError::WrongAudience)
    ));
    expire(&db, OLD).await;
    assert!(tokens::introspect(&db, &late, NEW).await.is_ok());
    // Dropping the alias revokes it (see `drop_alias_revokes_the_grants_still_bound_to_it`).
    resources::drop_alias(&db, OLD).await.unwrap();
    assert!(tokens::introspect(&db, &late, NEW).await.is_err());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn only_tokens_still_usable_are_rewritten(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let (user, org) = member(&db).await;
    let live = token(&db, user, org, OLD).await;
    let revoked = token(&db, user, org, OLD).await;
    tokens::revoke_presented(&db, &revoked).await.unwrap();
    token(&db, user, org, OLD).await;
    sqlx::query(
        "UPDATE access_tokens SET expires_at = now() - interval '1 minute' \
         WHERE token_hash NOT IN ($1, $2)",
    )
    .bind(otto_auth::crypto::hash(&live))
    .bind(otto_auth::crypto::hash(&revoked))
    .execute(db.pool())
    .await
    .unwrap();
    code(&db, user, org, OLD).await;
    code(&db, user, org, OLD).await;
    sqlx::query(
        "UPDATE authorization_codes SET consumed_at = now() \
         WHERE ctid = (SELECT min(ctid) FROM authorization_codes)",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let r = resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    assert_eq!(r.rewritten.access_tokens, 1);
    assert_eq!(r.rewritten.authorization_codes, 1);
    assert_eq!(count(&db, "access_tokens", "resource", OLD).await, 2);
    assert!(tokens::introspect(&db, &live, NEW).await.is_ok());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn alias_rows_cannot_be_truncated(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap();
    let err = sqlx::query("TRUNCATE resource_server_aliases")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("never deleted"), "{err}");
    assert_eq!(resources::aliases(&db).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn tenant_pinned_code_cannot_touch_aliases(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let (_, org) = member(&db).await;
    for stmt in [
        format!(
            "INSERT INTO resource_server_aliases (alias_uri, resource_uri, sunset_at) \
             VALUES ('https://squat.example/mcp', '{OLD}', now() + interval '1 day')"
        ),
        "UPDATE resource_server_aliases SET dropped_at = now()".to_owned(),
        "SELECT count(*) FROM resource_server_aliases".to_owned(),
    ] {
        let mut tx = db.begin(org).await.unwrap();
        let err = sqlx::query(&stmt).execute(tx.conn()).await.unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "{stmt}: {err}"
        );
    }
    assert!(resources::aliases(&db).await.unwrap().is_empty());
}

#[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
async fn a_rename_waits_for_a_claim_in_flight_then_gives_up_cleanly(pool: PgPool) {
    let db = Db::from_pool(pool);
    register(&db, OLD, "otto-factory").await;
    let (_, org) = member(&db).await;

    // A claim whose transaction stays open past the rename's lock timeout.
    let mut claiming = db.begin(org).await.unwrap();
    let out: String = sqlx::query_scalar("SELECT claim_usage_event($1, $2, $3)")
        .bind(OLD)
        .bind(Uuid::new_v4())
        .bind(org.as_uuid())
        .fetch_one(claiming.conn())
        .await
        .unwrap();
    assert_eq!(out, "new");

    let err = resources::rename(&db, OLD, NEW, Some(sunset()), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AuthError::InvalidRequest(m) if m.contains("run it again")),
        "{err:?}"
    );
    claiming.commit().await.unwrap();
    assert!(resources::get(&db, OLD).await.unwrap().is_some());
    assert!(resources::aliases(&db).await.unwrap().is_empty());
}
