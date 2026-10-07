//! Teams — the visibility scope inside an org.
//!
//! Reads are open to any member and writes need an admin, which is the same
//! split as members: seeing how your own org is organized is not
//! privileged, and changing it is.

use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use otto_core::teams::TeamsExt;
use otto_core::teams::{Team, TeamMember, TeamPatch};
use otto_tenant::ids::UserId;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiResult;
use crate::session::OrgCtx;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTeamRequest {
    pub slug: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// `GET /api/orgs/{org}/teams`
pub async fn list_teams(State(state): State<AppState>, ctx: OrgCtx) -> ApiResult<Json<Vec<Team>>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let teams = tx.list_teams().await?;
    tx.commit().await?;
    Ok(Json(teams))
}

/// `POST /api/orgs/{org}/teams`
pub async fn create_team(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Json(req): Json<CreateTeamRequest>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx
        .create_team(&req.slug, req.name.as_deref().unwrap_or(&req.slug))
        .await?;
    tx.commit().await?;

    Ok((http::StatusCode::CREATED, Json(team)).into_response())
}

/// `GET /api/orgs/{org}/teams/{team}` — by slug, not by id.
///
/// Slugs are what a person types and what a URL should carry; ids exist for the
/// places that need stability across renames.
pub async fn get_team(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Team>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    tx.commit().await?;
    Ok(Json(team))
}

/// `PATCH /api/orgs/{org}/teams/{team}`
pub async fn update_team(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug)): Path<(String, String)>,
    Json(patch): Json<TeamPatch>,
) -> ApiResult<Json<Team>> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    let team = tx.update_team(team.id, patch).await?;
    tx.commit().await?;
    Ok(Json(team))
}

/// `DELETE /api/orgs/{org}/teams/{team}`
///
/// Deletes the team unconditionally. There is no "still in use" guard here:
/// resource servers scope their own rows to a team in their own databases, with
/// no foreign key back to this one, so this server cannot see what depends on
/// the team. Cleaning up after a deleted team is the resource server's job, on
/// being told — see `otto_core::teams`'s module docs.
pub async fn delete_team(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug)): Path<(String, String)>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    tx.delete_team(team.id).await?;
    tx.commit().await?;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/orgs/{org}/teams/{team}/members`
pub async fn list_team_members(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug)): Path<(String, String)>,
) -> ApiResult<Json<Vec<TeamMember>>> {
    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    let members = tx.list_team_members(team.id).await?;
    tx.commit().await?;
    Ok(Json(members))
}

/// `PUT /api/orgs/{org}/teams/{team}/members/{user}` — put a member on a team.
///
/// `PUT` rather than `POST`: it is idempotent, and the console's checkbox is
/// naturally expressed as "make this true" rather than "append".
pub async fn add_team_member(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug, user)): Path<(String, String, Uuid)>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    tx.add_team_member(team.id, UserId::from(user)).await?;
    tx.commit().await?;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/orgs/{org}/teams/{team}/members/{user}`
pub async fn remove_team_member(
    State(state): State<AppState>,
    ctx: OrgCtx,
    Path((_org, slug, user)): Path<(String, String, Uuid)>,
) -> ApiResult<Response> {
    ctx.require_admin()?;

    let mut tx = state.db.begin(ctx.org.id).await?;
    let team = tx.resolve_team(&slug).await?;
    tx.remove_team_member(team.id, UserId::from(user)).await?;
    tx.commit().await?;

    Ok(http::StatusCode::NO_CONTENT.into_response())
}
