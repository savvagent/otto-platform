//! `/internal/*` — the API a resource server uses to get what it no longer
//! has in its own database.
//!
//! Every route is authenticated as the calling resource server
//! ([`CallingResourceServer`]) and answers in snake_case JSON, using the wire
//! types in `otto-resource` that the client deserializes.
//!
//! ```text
//!   POST /internal/usage                                     batch usage ingest
//!   GET  /internal/orgs/{org}/usage-status                   period usage vs plan
//!   GET  /internal/orgs/{org}/members/{user}                 whoami: user + org + role
//!   GET  /internal/orgs/{org}/members/by-email?email=        member lookup
//!   GET  /internal/orgs/{org}/members/{user}/teams           the member's teams in the org
//!   GET  /internal/orgs/{org}/teams/{team}                   team in org
//!   GET  /internal/orgs/{org}/teams/by-slug/{slug}           team in org, by slug
//! ```
//!
//! Lookups answer 404 for anything not found *within the named org*, with one
//! shape for "no such user" and "user not in this org": `users` is global, and
//! these routes must not become an oracle for whether an address has an
//! account.
//!
//! These routes are not scoped to the orgs a resource server has issued tokens
//! for: any registered resource server can ask about any org id. Resource
//! servers are first-party and operator-provisioned, and org ids are
//! unguessable UUIDs, which is the whole of the defence; see the PR for the
//! open question.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use otto_billing::usage::{IngestOutcome, ShippedUsage, UsageExt};
use otto_core::orgs::{Org, OrgsExt};
use otto_core::teams::{Team, TeamsExt};
use otto_resource::{
    MemberInfo, MemberTeams, OrgInfo, RejectedEvent, TeamInfo, UsageBatch, UsageReceipt,
    UsageStatus, UserInfo, MAX_USAGE_BATCH,
};
use otto_tenant::ids::{OrgId, TeamId, UserId};
use otto_tenant::Db;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::{wire_role, ApiError, CallingResourceServer};

/// The longest `tool` name accepted. Tool names are short identifiers; a
/// kilobyte of one is a bug in the shipper.
const MAX_TOOL_LEN: usize = 128;

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/internal/usage", post(ingest_usage))
        .route("/internal/orgs/{org}/usage-status", get(usage_status))
        .route(
            "/internal/orgs/{org}/members/by-email",
            get(member_by_email),
        )
        .route("/internal/orgs/{org}/members/{user}", get(member))
        .route(
            "/internal/orgs/{org}/members/{user}/teams",
            get(member_teams),
        )
        .route(
            "/internal/orgs/{org}/teams/by-slug/{slug}",
            get(team_by_slug),
        )
        .route("/internal/orgs/{org}/teams/{team}", get(team))
        .with_state(db)
}

/// An org that exists and has not been deleted, or 404.
async fn live_org(db: &Db, org: Uuid) -> Result<Org, ApiError> {
    db.get_active_org(OrgId::from(org))
        .await?
        .ok_or(ApiError::NotFound)
}

// ------------------------------------------------------------------- usage

/// Count a batch of usage events, idempotently.
///
/// Each event is keyed `(calling resource server, event_id)`; one already seen
/// counts as a duplicate and changes nothing, so a shipper whose response was
/// lost just sends the batch again. Events are grouped by org and each org's
/// events share one pinned transaction, so a database error part-way through an
/// org rolls that org back whole. The caller gets a 500 and resends everything,
/// which the dedupe makes harmless.
///
/// An event the platform can never accept is reported in `rejected` instead
/// of failing the batch, so one poison event cannot wedge the shipper's
/// outbox. That covers an unknown or deleted org, a bad tool name, an
/// `occurred_at` outside the accepted window (see `otto_billing::usage`), and
/// an `event_id` already used for a different org.
async fn ingest_usage(
    State(db): State<Db>,
    CallingResourceServer(rs): CallingResourceServer,
    Json(batch): Json<UsageBatch>,
) -> Result<Json<UsageReceipt>, ApiError> {
    if batch.events.len() > MAX_USAGE_BATCH {
        return Err(ApiError::TooLarge(format!(
            "a batch holds at most {MAX_USAGE_BATCH} events"
        )));
    }

    let mut receipt = UsageReceipt::default();
    let mut by_org: BTreeMap<Uuid, Vec<&otto_resource::UsageEvent>> = BTreeMap::new();
    for ev in &batch.events {
        let tool = ev.tool.trim();
        if tool.is_empty() || tool.len() > MAX_TOOL_LEN {
            receipt.rejected.push(RejectedEvent {
                event_id: ev.event_id,
                reason: format!("`tool` must be 1 to {MAX_TOOL_LEN} characters"),
            });
        } else {
            by_org.entry(ev.org_id).or_default().push(ev);
        }
    }

    for (org, events) in by_org {
        if db.get_active_org(OrgId::from(org)).await?.is_none() {
            receipt
                .rejected
                .extend(events.iter().map(|ev| RejectedEvent {
                    event_id: ev.event_id,
                    reason: format!("org {org} does not exist"),
                }));
            continue;
        }

        let mut tx = db.begin(OrgId::from(org)).await?;
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut rejected = Vec::new();
        for ev in events {
            let outcome = tx
                .ingest_usage(
                    &rs.resource_uri,
                    &ShippedUsage {
                        event_id: ev.event_id,
                        user: ev.user_id.map(UserId::from),
                        tool: ev.tool.trim(),
                        billable: ev.billable,
                        occurred_at: ev.occurred_at,
                    },
                )
                .await?;
            match outcome {
                IngestOutcome::Counted => accepted += 1,
                IngestOutcome::Duplicate => duplicates += 1,
                IngestOutcome::Rejected(reason) => rejected.push(RejectedEvent {
                    event_id: ev.event_id,
                    reason: reason.to_owned(),
                }),
            }
        }
        tx.commit().await?;
        receipt.accepted += accepted;
        receipt.duplicates += duplicates;
        receipt.rejected.extend(rejected);
    }

    Ok(Json(receipt))
}

/// The org's usage this month against its plan. Resource servers cache this
/// for 60 s, so it is a cheap read and may be slightly behind the counters.
async fn usage_status(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path(org): Path<Uuid>,
) -> Result<Json<UsageStatus>, ApiError> {
    live_org(&db, org).await?;

    let mut tx = db.begin(OrgId::from(org)).await?;
    let usage = tx.current_usage().await?;
    let limits = tx.plan_limits().await?;
    tx.rollback().await?;

    Ok(Json(UsageStatus {
        org_id: org,
        plan: limits.plan.as_str().to_owned(),
        period_start: usage.period_start,
        billable_count: usage.billable_count,
        total_count: usage.total_count,
        included_ops: limits.included_ops,
        hard_stop: limits.hard_stop,
    }))
}

// ---------------------------------------------------------------- identity

fn org_info(org: &Org) -> OrgInfo {
    OrgInfo {
        id: org.id.as_uuid(),
        slug: org.slug.clone(),
        name: org.name.clone(),
        plan: org.plan.as_str().to_owned(),
    }
}

/// The user, org, and role of an active member, or 404.
async fn member_info(db: &Db, org: Uuid, user: Uuid) -> Result<MemberInfo, ApiError> {
    let org_row = live_org(db, org).await?;
    let role = db
        .active_member_role(org_row.id, UserId::from(user))
        .await?
        .ok_or(ApiError::NotFound)?;
    let user_row = db
        .get_user(UserId::from(user))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(MemberInfo {
        user: UserInfo {
            id: user,
            email: user_row.email,
            name: user_row.name,
        },
        org: org_info(&org_row),
        role: wire_role(role),
    })
}

async fn member(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path((org, user)): Path<(Uuid, Uuid)>,
) -> Result<Json<MemberInfo>, ApiError> {
    member_info(&db, org, user).await.map(Json)
}

#[derive(Deserialize)]
struct ByEmail {
    email: String,
}

async fn member_by_email(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path(org): Path<Uuid>,
    Query(q): Query<ByEmail>,
) -> Result<Json<MemberInfo>, ApiError> {
    let email = q.email.trim();
    if email.is_empty() {
        return Err(ApiError::BadRequest("`email` is required".into()));
    }
    // "No account" and "not in this org" are the same 404; see the module docs.
    let user = db
        .get_user_by_email(email)
        .await?
        .ok_or(ApiError::NotFound)?;
    member_info(&db, org, user.id.as_uuid()).await.map(Json)
}

// ------------------------------------------------------------------- teams

fn team_info(t: Team) -> TeamInfo {
    TeamInfo {
        id: t.id.as_uuid(),
        org_id: t.org_id.as_uuid(),
        slug: t.slug,
        name: t.name,
    }
}

/// A team by id, and only if it belongs to the named org: a team id from
/// another org is a 404, the same as `require_team_in_org` in a single
/// database.
async fn team(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path((org, team)): Path<(Uuid, Uuid)>,
) -> Result<Json<TeamInfo>, ApiError> {
    live_org(&db, org).await?;
    let mut tx = db.begin(OrgId::from(org)).await?;
    let found = tx.get_team(TeamId::from(team)).await?;
    tx.rollback().await?;
    found.map(team_info).map(Json).ok_or(ApiError::NotFound)
}

async fn team_by_slug(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path((org, slug)): Path<(Uuid, String)>,
) -> Result<Json<TeamInfo>, ApiError> {
    live_org(&db, org).await?;
    let mut tx = db.begin(OrgId::from(org)).await?;
    let found = tx.get_team_by_slug(&slug).await?;
    tx.rollback().await?;
    found.map(team_info).map(Json).ok_or(ApiError::NotFound)
}

/// The teams one active member belongs to in the named org.
///
/// 404 unless the user is an active member of that live org (the same single
/// shape as `member`), so this is no oracle for accounts or for teams in other
/// orgs: the query runs in a transaction pinned to `org`, which only ever sees
/// that org's teams and memberships. A member on no teams is a 200 with an
/// empty list.
async fn member_teams(
    State(db): State<Db>,
    CallingResourceServer(_rs): CallingResourceServer,
    Path((org, user)): Path<(Uuid, Uuid)>,
) -> Result<Json<MemberTeams>, ApiError> {
    let org_row = live_org(&db, org).await?;
    let user = UserId::from(user);
    db.active_member_role(org_row.id, user)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut tx = db.begin(org_row.id).await?;
    let teams = tx.list_user_teams(user).await?;
    tx.rollback().await?;
    Ok(Json(MemberTeams {
        teams: teams.into_iter().map(team_info).collect(),
    }))
}
