//! `/internal/*` — the API a resource server uses to get what it no longer
//! has in its own database.
//!
//! Every route is authenticated as the calling resource server
//! ([`CallingResourceServer`]) and answers in snake_case JSON, using the wire
//! types in `otto-resource` that the client deserializes.
//!
//! ```text
//!   POST /internal/usage                                     batch usage ingest
//!   PUT  /internal/meters                                    declare the caller's value meters
//!   GET  /internal/orgs/{org}/usage-status                   the caller's meters, budget, plan features
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

use std::collections::{BTreeMap, HashSet};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use otto_billing::budgets::{
    self, PendingBudgets, ServiceBudgetStatus, BUDGET_EXCEEDED, SPEND_UNAVAILABLE,
};
use otto_billing::meters::{self, MeterSpec};
use otto_billing::pricebook::Month;
use otto_billing::usage::{
    self, IngestOutcome, Metered, MeteringFields, ShippedUsage, Shipper, UsageExt,
};
use otto_core::orgs::{Org, OrgsExt};
use otto_core::teams::{Team, TeamsExt};
use otto_resource::{
    BudgetStatus, MemberInfo, MemberTeams, MeterDeclarationBatch, MeterDeclarationReceipt,
    MeterUsage, OrgInfo, RejectedEvent, RejectedMeter, TeamInfo, UsageBatch, UsageReceipt,
    UsageStatus, UserInfo, MAX_METER_DECLARATIONS, MAX_USAGE_BATCH,
};
use otto_tenant::ids::{OrgId, TeamId, UserId};
use otto_tenant::{Db, Tx};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::{wire_role, ApiError, CallingResourceServer};

/// The longest `tool` name accepted. Tool names are short identifiers; a
/// kilobyte of one is a bug in the shipper.
const MAX_TOOL_LEN: usize = 128;

/// The largest `PUT /internal/meters` body read. Fifty well-formed meters fit
/// in well under a quarter of this.
const MAX_METERS_BODY: usize = 64 * 1024;

/// How much of a refused meter key is echoed back. A valid key is at most
/// 63 + 1 + 63 bytes.
const MAX_ECHOED_KEY: usize = 128;

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/internal/usage", post(ingest_usage))
        .route(
            "/internal/meters",
            put(declare_meters).layer(DefaultBodyLimit::max(MAX_METERS_BODY)),
        )
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
/// `occurred_at` outside the accepted window (see `otto_billing::usage`), an
/// `event_id` already used for a different org, and the metering refusals of
/// [`usage::check_metering`] (`unknown_meter`, `service_mismatch`,
/// `invalid_quantity`), whose reason starts with that code.
///
/// Every event counts in the caller's own per-service pool, keyed by the
/// caller's service slug and never by anything the event says. The caller's
/// declared meters are read once per request, not once per event.
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

    let service = rs.service.as_deref();
    let declared = declared_meters(&db, service, &batch.events).await?;
    let shipper = Shipper {
        service,
        declared: &declared,
    };

    let mut receipt = UsageReceipt::default();
    let mut by_org: BTreeMap<Uuid, Vec<(&otto_resource::UsageEvent, Option<Metered<'_>>)>> =
        BTreeMap::new();
    for ev in &batch.events {
        let tool = ev.tool.trim();
        if tool.is_empty() || tool.len() > MAX_TOOL_LEN {
            receipt.rejected.push(RejectedEvent {
                event_id: ev.event_id,
                reason: format!("`tool` must be 1 to {MAX_TOOL_LEN} characters"),
            });
            continue;
        }
        match usage::check_metering(
            &shipper,
            MeteringFields {
                service: ev.service.as_deref(),
                meter: ev.meter.as_deref(),
                quantity: ev.quantity,
            },
        ) {
            Ok(metered) => by_org.entry(ev.org_id).or_default().push((ev, metered)),
            Err(refused) => receipt.rejected.push(RejectedEvent {
                event_id: ev.event_id,
                reason: refused.to_string(),
            }),
        }
    }

    for (org, events) in by_org {
        if db.get_active_org(OrgId::from(org)).await?.is_none() {
            receipt
                .rejected
                .extend(events.iter().map(|(ev, _)| RejectedEvent {
                    event_id: ev.event_id,
                    reason: format!("org {org} does not exist"),
                }));
            continue;
        }

        let mut tx = db.begin(OrgId::from(org)).await?;
        let mut budgets = PendingBudgets::default();
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut rejected = Vec::new();
        for (ev, metered) in events {
            let outcome = tx
                .ingest_usage_deferred(
                    &rs.resource_uri,
                    &ShippedUsage {
                        event_id: ev.event_id,
                        user: ev.user_id.map(UserId::from),
                        tool: ev.tool.trim(),
                        billable: ev.billable,
                        occurred_at: ev.occurred_at,
                        service,
                        metered,
                    },
                    &mut budgets,
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
        // Budget alerts, once per service and period this batch touched. It
        // never fails the events (see `PendingBudgets::run`).
        budgets.run(&mut tx).await?;
        tx.commit().await?;
        receipt.accepted += accepted;
        receipt.duplicates += duplicates;
        receipt.rejected.extend(rejected);
    }

    Ok(Json(receipt))
}

/// The meter keys `service` has declared, read only when the batch names a
/// meter at all: an unmetered batch, or a caller with no service (which can
/// have declared nothing), costs no query.
async fn declared_meters(
    db: &Db,
    service: Option<&str>,
    events: &[otto_resource::UsageEvent],
) -> Result<HashSet<String>, ApiError> {
    let Some(service) = service else {
        return Ok(HashSet::new());
    };
    if events.iter().all(|ev| ev.meter.is_none()) {
        return Ok(HashSet::new());
    }
    let mut tx = db.begin_unpinned().await?;
    let declared = meters::list_meters(&mut tx, service).await?;
    tx.rollback().await?;
    Ok(declared.into_iter().map(|m| m.key).collect())
}

// ------------------------------------------------------------------ meters

/// Declare the calling resource server's value meters, idempotently.
///
/// Each meter's key must be `<service>/<meter>` under the caller's own
/// `service` (assigned by an operator with `resource set-service`); a key in
/// another namespace, a malformed field, or a key repeated in the request is
/// refused per meter in the receipt, and the rest are still declared. A caller
/// with no service yet gets 409 `service_not_set`: it has no namespace to
/// declare into, and retrying will not help until an operator assigns one.
async fn declare_meters(
    State(db): State<Db>,
    CallingResourceServer(rs): CallingResourceServer,
    Json(batch): Json<MeterDeclarationBatch>,
) -> Result<Response, ApiError> {
    let Some(service) = rs.service.as_deref() else {
        let mut res = (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "service_not_set",
                "error_description": "this resource server has no service slug yet; \
                    an operator assigns one with `otto-platform-server resource set-service`",
            })),
        )
            .into_response();
        res.headers_mut()
            .insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
        return Ok(res);
    };
    if batch.meters.len() > MAX_METER_DECLARATIONS {
        return Err(ApiError::TooLarge(format!(
            "a declaration holds at most {MAX_METER_DECLARATIONS} meters"
        )));
    }

    let mut receipt = MeterDeclarationReceipt::default();
    let mut valid = Vec::with_capacity(batch.meters.len());
    for m in &batch.meters {
        let checked = meters::check_declaration(
            service,
            &MeterSpec {
                key: &m.key,
                display_name: &m.display_name,
                unit: &m.unit,
            },
        )
        .and_then(|v| {
            if valid
                .iter()
                .any(|seen: &meters::ValidMeter| seen.key == v.key)
            {
                Err("`key` is declared more than once in this request".to_owned())
            } else {
                Ok(v)
            }
        });
        match checked {
            Ok(v) => valid.push(v),
            Err(reason) => receipt.rejected.push(RejectedMeter {
                key: truncate(&m.key, MAX_ECHOED_KEY),
                reason,
            }),
        }
    }

    let mut tx = db.begin_unpinned().await?;
    meters::upsert_meters(&mut tx, &valid).await?;
    tx.commit().await?;
    receipt.declared = valid.into_iter().map(|v| v.key).collect();
    Ok(Json(receipt).into_response())
}

/// At most `max` bytes of `s`, cut on a character boundary.
fn truncate(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// The org's usage this month. Resource servers cache this for 60 s, so it is
/// a cheap read and may be slightly behind the counters. Reading it is free
/// and works however much has been used.
///
/// `service`, `meters` and `budget` are the calling resource server's own
/// only: another service's usage or budget never shows here, so a hard stop on
/// one service never blocks another. `budget` is absent when the org has set
/// none for the caller's service. The legacy family-wide fields are
/// all still served for clients pinned to an older `otto-resource`, but
/// `hard_stop` is always `false`: an older client blocks on
/// `hard_stop && billable_count >= included_ops`, and with a family-wide count
/// that would let one service's usage stop work in another.
async fn usage_status(
    State(db): State<Db>,
    CallingResourceServer(rs): CallingResourceServer,
    Path(org): Path<Uuid>,
) -> Result<Json<UsageStatus>, ApiError> {
    live_org(&db, org).await?;

    let mut tx = db.begin(OrgId::from(org)).await?;
    let usage = tx.current_usage().await?;
    let limits = tx.plan_limits().await?;
    let (meters, budget) = match rs.service.as_deref() {
        Some(service) => {
            let meters = tx.service_meter_usage(service).await?;
            let period = Month::containing(usage.period_start);
            (meters, budget_status(&mut tx, service, period).await?)
        }
        None => (Vec::new(), None),
    };
    tx.rollback().await?;

    let meters = meters
        .into_iter()
        .map(|m| {
            Ok(MeterUsage {
                quantity: u64::try_from(m.quantity).map_err(ApiError::internal)?,
                meter: m.meter,
                display_name: m.display_name,
                unit: m.unit,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(UsageStatus {
        org_id: org,
        plan: limits.plan.as_str().to_owned(),
        period_start: usage.period_start,
        billable_count: usage.billable_count,
        total_count: usage.total_count,
        included_ops: limits.included_ops,
        // Never the plan's flag; see above.
        hard_stop: false,
        features: match limits.features {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            _ => Default::default(),
        },
        service: rs.service,
        meters,
        budget,
    }))
}

/// The caller's budget this period, or `None` when it has none.
///
/// A budget whose spend cannot be computed (a malformed price version, an
/// overflow) is still reported, with `spend_cents` and `percent_used` null,
/// `blocked` false and reason `spend_unavailable`: enforcement fails open,
/// visibly. A database error fails the request.
async fn budget_status(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
) -> Result<Option<BudgetStatus>, ApiError> {
    budgets::service_status(tx, service, period)
        .await
        .map(|status| wire_budget(&status))
        .map_err(ApiError::internal)
}

fn wire_budget(status: &ServiceBudgetStatus) -> Option<BudgetStatus> {
    let budget = status.budget.as_ref()?;
    let blocked = status.blocked();
    let reason = if blocked {
        Some(BUDGET_EXCEEDED)
    } else if status.spend_cents.is_none() {
        Some(SPEND_UNAVAILABLE)
    } else {
        None
    };
    Some(BudgetStatus {
        monthly_budget_cents: budget.monthly_budget_cents,
        spend_cents: status.spend_cents,
        percent_used: status.percent_used(),
        thresholds_reached: status.thresholds_reached.clone(),
        hard_stop: budget.hard_stop,
        blocked,
        reason: reason.map(str::to_owned),
    })
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
