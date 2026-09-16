//! Teams — the subdivision inside an org.
//!
//! A team is a visibility scope, not a second tenant boundary. Nothing here
//! weakens the org boundary — every statement is still `org_id = $1` inside a
//! pinned transaction, and a team id from another org simply does not
//! resolve.
//!
//! **Membership of a team requires membership of the org**, checked here rather
//! than trusted from the caller. `team_members` has its own `org_id` column and
//! its own RLS policy, so a bad insert would be refused by the database — but it
//! would be refused with a constraint error rather than a sentence an admin can
//! act on, and "that person is not in this org yet; invite them first" is the
//! useful answer.
//!
//! Extracted from otto-factory's `of_core::teams`, which additionally refused
//! to delete a team that still owned repos, jobs, or messages — otto-factory's
//! own domain tables. otto-platform has no domain tables of its own scoped to
//! a team (each otto-* service owns its own domain database, per
//! `docs/specs/2026-09-15-otto-flags-design.md` §3, with no cross-database
//! foreign key to check), so [`TeamsExt::delete_team`] here simply deletes the
//! team. A service that scopes its own domain rows to a team is responsible
//! for its own "team still in use" guard against its own tables before (or
//! instead of) calling this.

use crate::error::{Error, Result};
use otto_tenant::ids::{OrgId, TeamId, UserId};
use otto_tenant::Tx;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: TeamId,
    pub org_id: OrgId,
    pub slug: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A team member, joined with their user record — the shape the console renders.
#[derive(Debug, Clone, PartialEq, Serialize, FromRow, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub user_id: UserId,
    pub email: Option<String>,
    pub name: Option<String>,
    /// See [`crate::orgs::User::label`]. Carried here too because the console
    /// renders one person row for both the org-members and the teams page.
    pub label: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// Fields a team update may change. `None` leaves a field alone, which is what
/// makes this a PATCH rather than a replace.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamPatch {
    pub slug: Option<String>,
    pub name: Option<String>,
}

const TEAM_COLS: &str = "id, org_id, slug, name, created_at";

/// Slugs appear in URLs and in agent-facing arguments, so they are constrained
/// to something unambiguous rather than normalized silently — a team the admin
/// typed as "Platform Team" that comes back as "platform-team" is a surprise
/// every time they go looking for it.
fn validate_slug(slug: &str) -> Result<String> {
    let slug = slug.trim().to_lowercase();
    if slug.is_empty() {
        return Err(Error::Invalid("a team needs a slug".into()));
    }
    if slug.len() > 64 {
        return Err(Error::Invalid(
            "a team slug must be 64 characters or fewer".into(),
        ));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Invalid(format!(
            "team slug {slug:?} may contain only letters, digits, '-' and '_'"
        )));
    }
    Ok(slug)
}

/// Extension methods on [`otto_tenant::Tx`] for team management. See this
/// module's docs for why these are an extension trait rather than inherent
/// methods: `Tx` is owned by `otto-tenant`, which knows nothing of teams.
pub trait TeamsExt {
    fn create_team(
        &mut self,
        slug: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Team>> + Send;

    fn list_teams(&mut self) -> impl std::future::Future<Output = Result<Vec<Team>>> + Send;

    fn get_team(
        &mut self,
        id: TeamId,
    ) -> impl std::future::Future<Output = Result<Option<Team>>> + Send;

    fn get_team_by_slug(
        &mut self,
        slug: &str,
    ) -> impl std::future::Future<Output = Result<Option<Team>>> + Send;

    fn resolve_team(
        &mut self,
        slug: &str,
    ) -> impl std::future::Future<Output = Result<Team>> + Send;

    fn update_team(
        &mut self,
        id: TeamId,
        patch: TeamPatch,
    ) -> impl std::future::Future<Output = Result<Team>> + Send;

    fn delete_team(&mut self, id: TeamId) -> impl std::future::Future<Output = Result<()>> + Send;

    fn add_team_member(
        &mut self,
        team: TeamId,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn remove_team_member(
        &mut self,
        team: TeamId,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn list_team_members(
        &mut self,
        team: TeamId,
    ) -> impl std::future::Future<Output = Result<Vec<TeamMember>>> + Send;

    fn list_user_teams(
        &mut self,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<Vec<Team>>> + Send;

    fn remove_from_all_teams(
        &mut self,
        user: UserId,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
}

impl TeamsExt for Tx<'_> {
    async fn create_team(&mut self, slug: &str, name: &str) -> Result<Team> {
        let slug = validate_slug(slug)?;
        let name = name.trim();
        let name = if name.is_empty() { &slug } else { name };
        let org = self.org();

        sqlx::query_as(&format!(
            "INSERT INTO teams (org_id, slug, name) VALUES ($1,$2,$3) RETURNING {TEAM_COLS}"
        ))
        .bind(org)
        .bind(&slug)
        .bind(name)
        .fetch_one(self.conn())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => Error::TeamSlugTaken(slug),
            _ => Error::Db(e),
        })
    }

    async fn list_teams(&mut self) -> Result<Vec<Team>> {
        let org = self.org();
        let teams = sqlx::query_as(&format!(
            "SELECT {TEAM_COLS} FROM teams WHERE org_id = $1 ORDER BY name"
        ))
        .bind(org)
        .fetch_all(self.conn())
        .await?;
        Ok(teams)
    }

    async fn get_team(&mut self, id: TeamId) -> Result<Option<Team>> {
        let org = self.org();
        let team = sqlx::query_as(&format!(
            "SELECT {TEAM_COLS} FROM teams WHERE org_id = $1 AND id = $2"
        ))
        .bind(org)
        .bind(id)
        .fetch_optional(self.conn())
        .await?;
        Ok(team)
    }

    async fn get_team_by_slug(&mut self, slug: &str) -> Result<Option<Team>> {
        let org = self.org();
        let team = sqlx::query_as(&format!(
            "SELECT {TEAM_COLS} FROM teams WHERE org_id = $1 AND slug = lower($2)"
        ))
        .bind(org)
        .bind(slug.trim())
        .fetch_optional(self.conn())
        .await?;
        Ok(team)
    }

    /// Resolve a team by slug, or fail naming what is registered.
    async fn resolve_team(&mut self, slug: &str) -> Result<Team> {
        if let Some(team) = self.get_team_by_slug(slug).await? {
            return Ok(team);
        }
        let known = self
            .list_teams()
            .await?
            .iter()
            .map(|t| t.slug.clone())
            .collect::<Vec<_>>()
            .join(", ");
        Err(Error::TeamNotFound {
            slug: slug.trim().to_string(),
            known: if known.is_empty() {
                "(none yet)".into()
            } else {
                known
            },
        })
    }

    async fn update_team(&mut self, id: TeamId, patch: TeamPatch) -> Result<Team> {
        let slug = patch.slug.as_deref().map(validate_slug).transpose()?;
        let org = self.org();

        sqlx::query_as(&format!(
            "UPDATE teams SET slug = COALESCE($3, slug), name = COALESCE($4, name) \
             WHERE org_id = $1 AND id = $2 RETURNING {TEAM_COLS}"
        ))
        .bind(org)
        .bind(id)
        .bind(slug.as_deref())
        .bind(
            patch
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty()),
        )
        .fetch_optional(self.conn())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                Error::TeamSlugTaken(slug.unwrap_or_default())
            }
            _ => Error::Db(e),
        })?
        .ok_or_else(|| Error::TeamNotFound {
            slug: id.to_string(),
            known: String::new(),
        })
    }

    /// Delete a team. `team_members` rows for it cascade via the foreign key;
    /// see this module's docs for why there is no "still in use" guard beyond
    /// that — otto-platform has no domain table of its own that scopes to a
    /// team.
    async fn delete_team(&mut self, id: TeamId) -> Result<()> {
        let org = self.org();

        let n = sqlx::query("DELETE FROM teams WHERE org_id = $1 AND id = $2")
            .bind(org)
            .bind(id)
            .execute(self.conn())
            .await?
            .rows_affected();

        if n == 0 {
            return Err(Error::TeamNotFound {
                slug: id.to_string(),
                known: String::new(),
            });
        }
        Ok(())
    }

    /// Put an org member on a team. Idempotent — adding twice is not an error,
    /// because the admin's intent ("this person is on this team") is satisfied
    /// either way.
    async fn add_team_member(&mut self, team: TeamId, user: UserId) -> Result<()> {
        let org = self.org();

        // The team must be ours. Without this the insert would still be refused
        // — by RLS, on `team_members.org_id` — but with a constraint error
        // rather than a sentence.
        if self.get_team(team).await?.is_none() {
            return Err(Error::TeamNotFound {
                slug: team.to_string(),
                known: String::new(),
            });
        }

        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(org)
        .bind(user)
        .fetch_one(self.conn())
        .await?;

        if !is_member {
            return Err(Error::NotAMember(user));
        }

        sqlx::query(
            "INSERT INTO team_members (org_id, team_id, user_id) VALUES ($1,$2,$3) \
             ON CONFLICT (team_id, user_id) DO NOTHING",
        )
        .bind(org)
        .bind(team)
        .bind(user)
        .execute(self.conn())
        .await?;
        Ok(())
    }

    async fn remove_team_member(&mut self, team: TeamId, user: UserId) -> Result<()> {
        let org = self.org();
        sqlx::query("DELETE FROM team_members WHERE org_id = $1 AND team_id = $2 AND user_id = $3")
            .bind(org)
            .bind(team)
            .bind(user)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    async fn list_team_members(&mut self, team: TeamId) -> Result<Vec<TeamMember>> {
        let org = self.org();
        let rows = sqlx::query_as(
            "SELECT tm.user_id, u.email, u.name, u.label, tm.created_at AS joined_at \
             FROM team_members tm JOIN users u ON u.id = tm.user_id \
             WHERE tm.org_id = $1 AND tm.team_id = $2 ORDER BY u.email",
        )
        .bind(org)
        .bind(team)
        .fetch_all(self.conn())
        .await?;
        Ok(rows)
    }

    /// The teams one user belongs to in this org — what decides which
    /// team-scoped repos and jobs they can see.
    async fn list_user_teams(&mut self, user: UserId) -> Result<Vec<Team>> {
        let org = self.org();
        let rows = sqlx::query_as(
            "SELECT t.id, t.org_id, t.slug, t.name, t.created_at \
             FROM teams t JOIN team_members tm ON tm.team_id = t.id \
             WHERE t.org_id = $1 AND tm.org_id = $1 AND tm.user_id = $2 ORDER BY t.name",
        )
        .bind(org)
        .bind(user)
        .fetch_all(self.conn())
        .await?;
        Ok(rows)
    }

    /// Remove a user from every team in this org. Called when they leave the
    /// org, so a re-invited person does not silently reappear on their old
    /// teams months later.
    async fn remove_from_all_teams(&mut self, user: UserId) -> Result<u64> {
        let org = self.org();
        let n = sqlx::query("DELETE FROM team_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .execute(self.conn())
            .await?
            .rows_affected();
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_constrained_and_lowercased() {
        assert_eq!(validate_slug(" Platform ").unwrap(), "platform");
        assert_eq!(validate_slug("web-ui_2").unwrap(), "web-ui_2");

        for bad in ["", "   ", "platform team", "team/one", "über"] {
            assert!(validate_slug(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_slug(&"a".repeat(65)).is_err());
    }
}
