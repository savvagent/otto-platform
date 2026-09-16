//! Orgs, users, and membership — the control plane.
//!
//! These run on **unpinned** transactions ([`Db::begin_unpinned`]) because they
//! answer the question that must be settled *before* an org can be pinned:
//! "who is this, and which orgs may they act in?". Everything here is reachable
//! only from otto-auth and a future console; a resource-server's tool surface
//! never calls it.

use crate::error::{Error, Result};
use crate::labels;
use otto_tenant::ids::{OrgId, UserId};
use otto_tenant::{Db, Tx};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, schemars::JsonSchema,
)]
#[sqlx(type_name = "org_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    /// Owners and admins may manage members, teams, and connections.
    pub fn can_administer(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    /// Only owners may change billing or delete the org.
    pub fn can_own(self) -> bool {
        matches!(self, Role::Owner)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    sqlx::Type,
    schemars::JsonSchema,
)]
#[sqlx(type_name = "org_plan", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    #[default]
    Free,
    Team,
    Business,
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Org {
    pub id: OrgId,
    pub slug: String,
    pub name: String,
    pub plan: Plan,
    pub enforce_sso: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: UserId,
    /// Absent until the account sets one.
    ///
    /// A passkey is what brings an account into existence, so there is a real
    /// moment — between registering a key and filling in a profile — where an
    /// account has no address. That is the moment that lets signup take no
    /// identifier at all, which is what removes the enumeration oracle; the
    /// nullability is the price and it is worth paying. Unique when set.
    pub email: Option<String>,
    pub name: Option<String>,
    /// The console language this account chose, or `None` for "never chose".
    ///
    /// `None` is not English. It is the state where the browser's own
    /// preference is still in charge, and collapsing the two would silently
    /// pin every new account to the base locale. Always one of
    /// [`crate::i18n::SUPPORTED_LOCALES`] when set — [`Db::set_profile`] is the
    /// only writer and it validates.
    pub locale: Option<String>,
    /// The words that name this account in a credential vault's picker.
    ///
    /// A name, not an identifier — nothing resolves an account from it, and two
    /// accounts drawing the same words is a cosmetic annoyance rather than a
    /// conflict, which is why there is no unique index behind it. It exists
    /// because a passkey named with a constant leaves two accounts on this site
    /// indistinguishable at exactly the moment somebody has to choose between
    /// them. Set once at insert by [`crate::labels::generate`] and never
    /// rewritten: the vault entry already carries the old words.
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub disabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: Role,
    pub org_slug: String,
    pub org_name: String,
    pub plan: Plan,
}

/// A member of one org, joined with their user record. Flat rather than nested
/// so it maps straight off the query — the console renders exactly these fields.
#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct OrgMember {
    pub id: UserId,
    pub email: Option<String>,
    pub name: Option<String>,
    /// See [`User::label`]. Carried here too because the console renders one
    /// person row for both the org-members and the teams page.
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub disabled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub role: Role,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

const ORG_COLS: &str = "id, slug, name, plan, enforce_sso, created_at";
const USER_COLS: &str = "id, email, name, locale, label, created_at, disabled_at";

/// An org is addressed by its slug as one URL path segment for the rest of its
/// life (`/api/orgs/{org}/...`), so the same character/length discipline team
/// slugs already get applies here — a slug containing `/` would otherwise be
/// stored and then never addressable again, and an empty-after-trim one would
/// collide with every other org that also trimmed to nothing.
fn validate_org_slug(slug: &str) -> Result<String> {
    let slug = slug.trim().to_lowercase();
    if slug.is_empty() {
        return Err(Error::Invalid("an org needs a slug".into()));
    }
    if slug.len() > 64 {
        return Err(Error::Invalid(
            "an org slug must be 64 characters or fewer".into(),
        ));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Invalid(format!(
            "org slug {slug:?} may contain only letters, digits, '-' and '_'"
        )));
    }
    Ok(slug)
}

/// Extension methods on [`otto_tenant::Db`] for the identity control plane.
///
/// Defined as an extension trait rather than inherent methods on `Db` itself:
/// `Db` is owned by `otto-tenant`, which knows nothing about orgs or users, so
/// every domain crate built on top of it (this one, and any other otto-*
/// service's own domain crate) adds its own queries this way instead of
/// `otto-tenant` growing a method for each dependent's domain.
pub trait OrgsExt {
    fn create_org(
        &self,
        slug: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Org>> + Send;

    fn create_org_with_owner(
        &self,
        slug: &str,
        name: &str,
        owner: UserId,
    ) -> impl std::future::Future<Output = Result<Org>> + Send;

    fn get_org(&self, id: OrgId) -> impl std::future::Future<Output = Result<Option<Org>>> + Send;

    fn get_org_by_slug(
        &self,
        slug: &str,
    ) -> impl std::future::Future<Output = Result<Option<Org>>> + Send;

    fn create_unclaimed_user(&self) -> impl std::future::Future<Output = Result<User>> + Send;

    fn set_profile(
        &self,
        user: UserId,
        email: Option<&str>,
        name: Option<&str>,
        locale: Option<Option<&str>>,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    fn upsert_user(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    fn get_user(
        &self,
        id: UserId,
    ) -> impl std::future::Future<Output = Result<Option<User>>> + Send;

    fn get_user_by_email(
        &self,
        email: &str,
    ) -> impl std::future::Future<Output = Result<Option<User>>> + Send;

    fn add_member(
        &self,
        org: OrgId,
        user: UserId,
        role: Role,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn remove_member(
        &self,
        org: OrgId,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn member_role(
        &self,
        org: OrgId,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<Option<Role>>> + Send;

    fn count_owners(&self, org: OrgId) -> impl std::future::Future<Output = Result<i64>> + Send;

    fn list_user_orgs(
        &self,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<Vec<Membership>>> + Send;

    fn list_org_members(
        &self,
        org: OrgId,
    ) -> impl std::future::Future<Output = Result<Vec<OrgMember>>> + Send;
}

impl OrgsExt for Db {
    async fn create_org(&self, slug: &str, name: &str) -> Result<Org> {
        let slug = validate_org_slug(slug)?;
        let org = sqlx::query_as(&format!(
            "INSERT INTO orgs (slug, name) VALUES ($1, $2) RETURNING {ORG_COLS}"
        ))
        .bind(&slug)
        .bind(name)
        .fetch_one(self.pool())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                Error::Invalid(format!("org slug {slug:?} is taken"))
            }
            _ => Error::Db(e),
        })?;
        Ok(org)
    }

    /// Create an org and add its first owner in one transaction.
    ///
    /// `create_org` followed by a separate `add_member` call would leave a
    /// window — a crash or a failed second statement between them — where the
    /// org exists with no owner at all, the exact invariant the rest of this
    /// module enforces everywhere else. Self-serve org creation always wants
    /// both or neither.
    async fn create_org_with_owner(&self, slug: &str, name: &str, owner: UserId) -> Result<Org> {
        let slug = validate_org_slug(slug)?;
        let mut tx = self.begin_unpinned().await?;

        let org: Org = sqlx::query_as(&format!(
            "INSERT INTO orgs (slug, name) VALUES ($1, $2) RETURNING {ORG_COLS}"
        ))
        .bind(&slug)
        .bind(name)
        .fetch_one(tx.conn())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                Error::Invalid(format!("org slug {slug:?} is taken"))
            }
            _ => Error::Db(e),
        })?;

        sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(org.id)
            .bind(owner)
            .execute(tx.conn())
            .await?;

        tx.commit().await?;
        Ok(org)
    }

    async fn get_org(&self, id: OrgId) -> Result<Option<Org>> {
        let org = sqlx::query_as(&format!("SELECT {ORG_COLS} FROM orgs WHERE id = $1"))
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        Ok(org)
    }

    async fn get_org_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        let org = sqlx::query_as(&format!(
            "SELECT {ORG_COLS} FROM orgs WHERE lower(slug) = lower($1)"
        ))
        .bind(slug)
        .fetch_optional(self.pool())
        .await?;
        Ok(org)
    }

    /// Create an account with no address, for a passkey that has just been
    /// registered.
    ///
    /// The account is real and signable-into from this moment; the profile
    /// comes after. Nothing about it is reachable by anyone who does not hold
    /// the key, so an abandoned registration leaves an inert row rather than a
    /// claimable identity.
    async fn create_unclaimed_user(&self) -> Result<User> {
        let user = sqlx::query_as(&format!(
            "INSERT INTO users (email, name, label) VALUES (NULL, NULL, $1) \
             RETURNING {USER_COLS}"
        ))
        .bind(labels::generate())
        .fetch_one(self.pool())
        .await?;
        Ok(user)
    }

    /// Set the address, display name and console language on an account that
    /// has a passkey.
    ///
    /// The address is unique when set, so this is where "that address is taken"
    /// is discovered. Deliberately a *signed-in* operation: it is the one place
    /// the product will tell you whether an address is in use, and requiring a
    /// session makes that answer attributable, rate-limited, and auditable
    /// rather than something a stranger can walk a list against.
    ///
    /// `locale` has **three** states where `email` and `name` have two, and the
    /// third is not a nicety: "match my browser" is a real choice somebody
    /// makes after having picked Spanish once, and `COALESCE` cannot express
    /// it — under `COALESCE` a `NULL` argument means "leave alone", so there is
    /// no argument that means "set to NULL".
    ///
    /// | `locale` | Effect |
    /// |---|---|
    /// | `None` | leave the stored locale alone |
    /// | `Some(Some("de"))` | set it, after validating against [`crate::i18n::SUPPORTED_LOCALES`] |
    /// | `Some(None)` | clear it — go back to following the browser |
    async fn set_profile(
        &self,
        user: UserId,
        email: Option<&str>,
        name: Option<&str>,
        locale: Option<Option<&str>>,
    ) -> Result<User> {
        if let Some(email) = email {
            let email = email.trim();
            if email.is_empty() || !email.contains('@') {
                return Err(Error::Invalid(format!("{email:?} is not an email address")));
            }
        }

        // Parsed rather than passed through, so an unsupported value is a
        // refusal that names the six options instead of a row nothing can read.
        let locale = match locale {
            Some(Some(raw)) => Some(Some(raw.parse::<crate::i18n::Locale>()?.as_str())),
            other => other,
        };

        let updated = sqlx::query_as(&format!(
            "UPDATE users SET \
               email  = COALESCE($2, email), \
               name   = COALESCE($3, name), \
               locale = CASE WHEN $4 THEN $5 ELSE locale END \
             WHERE id = $1 RETURNING {USER_COLS}"
        ))
        .bind(user)
        .bind(email.map(str::trim))
        .bind(name.map(str::trim))
        .bind(locale.is_some())
        .bind(locale.flatten())
        .fetch_one(self.pool())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                Error::Invalid("that email address is already in use".to_string())
            }
            _ => Error::from(e),
        })?;

        Ok(updated)
    }

    async fn upsert_user(&self, email: &str, name: Option<&str>) -> Result<User> {
        let email = email.trim();
        if email.is_empty() || !email.contains('@') {
            return Err(Error::Invalid(format!("{email:?} is not an email address")));
        }

        if let Some(existing) = self.get_user_by_email(email).await? {
            return Ok(existing);
        }

        let user = sqlx::query_as(&format!(
            "INSERT INTO users (email, name, label) VALUES ($1, $2, $3) \
             ON CONFLICT (lower(email)) DO UPDATE SET email = users.email \
             RETURNING {USER_COLS}"
        ))
        .bind(email)
        .bind(name)
        .bind(labels::generate())
        .fetch_one(self.pool())
        .await?;

        Ok(user)
    }

    async fn get_user(&self, id: UserId) -> Result<Option<User>> {
        let user = sqlx::query_as(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        Ok(user)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as(&format!(
            "SELECT {USER_COLS} FROM users WHERE lower(email) = lower($1)"
        ))
        .bind(email)
        .fetch_optional(self.pool())
        .await?;
        Ok(user)
    }

    async fn add_member(&self, org: OrgId, user: UserId, role: Role) -> Result<()> {
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3) \
             ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(org)
        .bind(user)
        .bind(role)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn remove_member(&self, org: OrgId, user: UserId) -> Result<()> {
        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The user's role in an org, or `None` if they are not a member.
    ///
    /// This is the authorization check every request runs before pinning a
    /// transaction: RLS enforces that a pinned transaction stays inside its org,
    /// but nothing in the database decides *which* org a given user may pin.
    /// That decision is here, and it is the reason a token's org is fixed at
    /// issuance rather than chosen per request.
    async fn member_role(&self, org: OrgId, user: UserId) -> Result<Option<Role>> {
        let role =
            sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
                .bind(org)
                .bind(user)
                .fetch_optional(self.pool())
                .await?;
        Ok(role)
    }

    /// How many owners this org has.
    ///
    /// Read-only and unlocked — fine for a display, wrong for a guard. A
    /// caller about to remove or demote an owner wants
    /// [`TeamsTxExt`](crate::teams) / [`Tx::count_owners_for_update`] instead,
    /// in the same transaction as the write it is guarding: two concurrent
    /// callers reading this method's answer on separate connections can each
    /// see the same count, each pass, and both writes land, leaving an org
    /// with no owner — a state only a human with database access can undo.
    async fn count_owners(&self, org: OrgId) -> Result<i64> {
        let n = sqlx::query_scalar(
            "SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'",
        )
        .bind(org)
        .fetch_one(self.pool())
        .await?;
        Ok(n)
    }

    async fn list_user_orgs(&self, user: UserId) -> Result<Vec<Membership>> {
        let rows = sqlx::query_as(
            "SELECT m.org_id, m.user_id, m.role, o.slug AS org_slug, o.name AS org_name, o.plan \
             FROM org_members m JOIN orgs o ON o.id = m.org_id \
             WHERE m.user_id = $1 AND o.deleted_at IS NULL \
             ORDER BY o.name",
        )
        .bind(user)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    async fn list_org_members(&self, org: OrgId) -> Result<Vec<OrgMember>> {
        let rows = sqlx::query_as(
            "SELECT u.id, u.email, u.name, u.label, u.created_at, u.disabled_at, \
                    m.role, m.created_at AS joined_at \
             FROM org_members m JOIN users u ON u.id = m.user_id \
             WHERE m.org_id = $1 ORDER BY u.email",
        )
        .bind(org)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}

/// Extension methods on [`otto_tenant::Tx`] for org membership changes that
/// must share a commit with something else in the same tenant transaction
/// (e.g. an owner-count guard, or an audit row).
pub trait OrgsTxExt {
    fn count_owners_for_update(&mut self) -> impl std::future::Future<Output = Result<i64>> + Send;

    fn add_member(
        &mut self,
        user: UserId,
        role: Role,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn remove_member(
        &mut self,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl OrgsTxExt for Tx<'_> {
    /// Owner rows locked for the rest of this transaction.
    ///
    /// A caller demoting or removing an owner reads this count and, if it
    /// clears the guard, writes the membership change — both inside one
    /// transaction. Without the lock, two concurrent callers (two owners
    /// demoting each other, say) can each read `count == 2` on separate
    /// connections, each pass the guard, and both writes land, leaving the
    /// org with zero owners (see [`OrgsExt::count_owners`]). `FOR UPDATE`
    /// cannot ride an aggregate, so this locks the owner rows themselves and
    /// returns how many there were; a second transaction reaching the same
    /// rows blocks here until the first commits or rolls back, then sees the
    /// count that transaction left behind.
    async fn count_owners_for_update(&mut self) -> Result<i64> {
        let org = self.org();
        let owners: Vec<(UserId,)> = sqlx::query_as(
            "SELECT user_id FROM org_members WHERE org_id = $1 AND role = 'owner' FOR UPDATE",
        )
        .bind(org)
        .fetch_all(self.conn())
        .await?;
        Ok(owners.len() as i64)
    }

    /// As [`OrgsExt::add_member`], pinned to this transaction so a role change
    /// can share a commit with [`Self::count_owners_for_update`]'s guard.
    async fn add_member(&mut self, user: UserId, role: Role) -> Result<()> {
        let org = self.org();
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3) \
             ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(org)
        .bind(user)
        .bind(role)
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// As [`OrgsExt::remove_member`], pinned to this transaction so the guard,
    /// any cleanup, and an audit entry either all land or none do.
    async fn remove_member(&mut self, user: UserId) -> Result<()> {
        let org = self.org();
        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .execute(self.conn())
            .await?;
        Ok(())
    }
}
