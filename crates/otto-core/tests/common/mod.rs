//! Shared fixtures for otto-core's DB-backed integration tests.
//!
//! Each test gets a throwaway database from `#[sqlx::test]`, migrated with
//! otto-tenant's full schema via `otto_tenant::db::MIGRATOR`.

#![allow(dead_code)]

use otto_core::orgs::{OrgsExt, Role};
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::Db;
use sqlx::PgPool;

pub struct Tenant {
    pub org: OrgId,
    pub user: UserId,
}

/// Create an org with one owner.
pub async fn tenant(db: &Db, slug: &str) -> Tenant {
    let org = db.create_org(slug, slug).await.expect("create org");
    let user = db
        .upsert_user(&format!("owner@{slug}.test"), Some("Owner"))
        .await
        .expect("create user");
    db.add_member(org.id, user.id, Role::Owner)
        .await
        .expect("add member");

    Tenant {
        org: org.id,
        user: user.id,
    }
}

pub fn db(pool: PgPool) -> Db {
    Db::from_pool(pool)
}
