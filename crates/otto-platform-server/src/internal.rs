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

use axum::extract::{DefaultBodyLimit, FromRef, Path, Query, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use otto_billing::billing::gate::{self, Standing};
use otto_billing::budgets::{
    self, PendingBudgets, ServiceBudgetStatus, BUDGET_EXCEEDED, SPEND_UNAVAILABLE,
};
use otto_billing::meters::{self, MeterSpec};
use otto_billing::period::{self, Month};
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

/// Whether this deployment bills through Stripe ([`gate::Billing`]): decides
/// whether usage-status may ever answer `payment_required`.
pub use otto_billing::billing::gate::Billing;

/// Billing as `config` sets it up: enabled when both Stripe secrets are set
/// ([`crate::Config::stripe`]).
pub fn billing_of(config: &crate::Config) -> Billing {
    Billing::enabled_if(config.stripe.is_some())
}

/// What the `/internal` routes share. A route takes the parts it needs
/// (`State<Db>`, `State<Billing>`) through [`FromRef`], so one that needs
/// the billing mode cannot be mounted without it: the router does not
/// compile unless its state provides every handler's.
#[derive(Debug, Clone)]
pub struct InternalState {
    pub db: Db,
    pub billing: Billing,
    /// The most of one meter an org may accrue in a billing month before
    /// usage ingest holds further events for review
    /// ([`usage::DEFAULT_HOLD_THRESHOLD`]).
    pub hold_threshold: i64,
}

/// The threshold a handler reads from [`InternalState`].
#[derive(Debug, Clone, Copy)]
struct HoldThreshold(i64);

impl FromRef<InternalState> for HoldThreshold {
    fn from_ref(state: &InternalState) -> Self {
        HoldThreshold(state.hold_threshold)
    }
}

impl FromRef<InternalState> for Db {
    fn from_ref(state: &InternalState) -> Self {
        state.db.clone()
    }
}

impl FromRef<InternalState> for Billing {
    fn from_ref(state: &InternalState) -> Self {
        state.billing
    }
}

pub fn router(db: Db, billing: Billing) -> Router {
    router_with_hold_threshold(db, billing, usage::DEFAULT_HOLD_THRESHOLD)
}

/// [`router`] with the usage review threshold set (`OTTO_USAGE_HOLD_THRESHOLD`).
pub fn router_with_hold_threshold(db: Db, billing: Billing, hold_threshold: i64) -> Router {
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
        .with_state(InternalState {
            db,
            billing,
            hold_threshold,
        })
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
/// which the dedupe makes harmless. A batch that raced a `resource
/// rename-service` (it read the old slug, and the rename committed before it
/// wrote), or that gave up waiting for a lock, is refused the same way, as a
/// 503 `temporarily_unavailable` with `Retry-After` rather than a 500; see
/// [`ingest_error`].
///
/// Each org's transaction waits at most [`INGEST_LOCK_TIMEOUT`] for any one
/// lock: the org's ingest lock, the usage-ledger lock a `resource rename` of
/// this server holds, or the tables a `rename-service` holds. Waiting longer
/// would only hold a pooled connection while the shipper's request times out;
/// the shipper resends after `Retry-After` instead. The lock order is in
/// `otto_auth::resources`.
///
/// An event the platform can never accept is reported in `rejected` instead
/// of failing the batch, so one poison event cannot wedge the shipper's
/// outbox. That covers an unknown or deleted org, a bad tool name, an
/// `occurred_at` outside the accepted window (see `otto_billing::usage`), an
/// `event_id` already used for a different org, and the metering refusals of
/// [`usage::check_metering`] (`unknown_meter`, `service_mismatch`,
/// `invalid_quantity`), whose reason starts with that code.
///
/// An event for an org that has not authorized the calling resource server
/// (it holds no access or refresh token bound to it, see
/// [`usage::org_authorized_resource`]) is rejected, reason `not_authorized`.
/// A metered event that would take the org's total of its meter in its
/// billing month past the review threshold is not counted either: it is
/// kept in `usage_held_events`, listed by `otto-platform-server usage held`,
/// and reported rejected with a reason starting `held_for_review` (the
/// shipper then drops it, and a resend is a duplicate).
///
/// Every event counts in the caller's own per-service pool, keyed by the
/// caller's service slug and never by anything the event says. The caller's
/// declared meters are read once per request, not once per event.
///
/// An event whose billing month has already closed (see
/// `otto_billing::period`) is accepted and billed in the current period.
///
/// Each org's transaction first takes the org's ingest lock
/// ([`usage::lock_org_ingest`]), so concurrent batches for one org run one
/// after the other instead of deadlocking on each other's counter rows, and
/// counts the org's events in billed order (period, then `occurred_at`).
async fn ingest_usage(
    State(db): State<Db>,
    State(HoldThreshold(hold_threshold)): State<HoldThreshold>,
    CallingResourceServer { server: rs, .. }: CallingResourceServer,
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

    let now = chrono::Utc::now();
    for (org, mut events) in by_org {
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
        sqlx::query(&format!("SET LOCAL lock_timeout = '{INGEST_LOCK_TIMEOUT}'"))
            .execute(tx.conn())
            .await?;
        usage::lock_org_ingest(&mut tx)
            .await
            .map_err(|e| ingest_error(e.into()))?;
        // The caller may only bill orgs that authorized it. Judged per org
        // under the ingest lock, before anything is claimed, so a refused
        // event leaves no trace and can be resent once the org has.
        if !usage::org_authorized_resource(&mut tx, &rs.resource_uri)
            .await
            .map_err(|e| ingest_error(e.into()))?
        {
            tx.rollback().await?;
            tracing::warn!(
                org = %org,
                resource = %rs.resource_uri,
                events = events.len(),
                "usage refused: the org never authorized this resource server"
            );
            receipt
                .rejected
                .extend(events.iter().map(|(ev, _)| RejectedEvent {
                    event_id: ev.event_id,
                    reason: format!(
                        "not_authorized: org {org} has not authorized this resource server"
                    ),
                }));
            continue;
        }
        // Stable, so events of one instant keep the batch's order.
        events.sort_by_key(|(ev, _)| {
            let at = period::billed_at(ev.occurred_at, now);
            (Month::of(at), ev.occurred_at)
        });
        let mut budgets = PendingBudgets::default();
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut rejected = Vec::new();
        for (ev, metered) in events {
            let outcome = tx
                .ingest_usage_held(
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
                    hold_threshold,
                )
                .await
                .map_err(ingest_error)?;
            match outcome {
                IngestOutcome::Counted => accepted += 1,
                IngestOutcome::Duplicate => duplicates += 1,
                IngestOutcome::Rejected(reason) => rejected.push(RejectedEvent {
                    event_id: ev.event_id,
                    reason: reason.to_owned(),
                }),
                IngestOutcome::Held(reason) => {
                    tracing::error!(
                        org = %org,
                        event = %ev.event_id,
                        resource = %rs.resource_uri,
                        %reason,
                        "usage held for operator review, not billed"
                    );
                    rejected.push(RejectedEvent {
                        event_id: ev.event_id,
                        reason,
                    });
                }
            }
        }
        // Budget alerts, once per service and period this batch touched. It
        // never fails the events (see `PendingBudgets::run`).
        budgets.run(&mut tx).await.map_err(ingest_error)?;
        tx.commit().await.map_err(|e| ingest_error(e.into()))?;
        receipt.accepted += accepted;
        receipt.duplicates += duplicates;
        receipt.rejected.extend(rejected);
    }

    Ok(Json(receipt))
}

/// The foreign keys (migration 0024) that refuse a row written under a
/// service slug or meter key a `rename-service` moved away after this batch
/// read the caller's service and declared meters.
const RENAMED_KEYS: &[&str] = &[
    "usage_events_meter_declared",
    "org_meter_period_usage_meter_declared",
    "org_service_period_usage_service_registered",
];

/// How long an ingest transaction waits for any one lock before the batch is
/// refused with a retriable 503.
pub const INGEST_LOCK_TIMEOUT: &str = "5s";

/// An ingest failure worth a retry is a 503, not an internal error: a batch
/// that raced a service rename, or one that gave up waiting for a lock
/// ([`otto_tenant::is_retryable_lock_failure`]: a lock timeout, a deadlock,
/// a cancel). The org's transaction is rolled back (its event ids unclaimed
/// with it), orgs already committed come back as duplicates, and the resent
/// batch is judged afresh: after a service rename, against the new slug,
/// where a metered event under an old key is `unknown_meter` like any
/// undeclared one.
fn ingest_error(e: otto_core::Error) -> ApiError {
    let db = match &e {
        otto_core::Error::Db(d) | otto_core::Error::Tenant(otto_tenant::Error::Db(d)) => Some(d),
        _ => None,
    };
    let raced = db.is_some_and(|d| match d {
        sqlx::Error::Database(d) => {
            d.is_foreign_key_violation()
                && d.constraint().is_some_and(|c| RENAMED_KEYS.contains(&c))
        }
        _ => false,
    });
    if raced {
        tracing::warn!(error = %e, "usage batch raced a service rename; asking for a retry");
        return ApiError::Unavailable(
            "this resource server's service was renamed while the batch was being counted; \
             one org's events were not recorded, resend the whole batch (events already \
             recorded come back as duplicates)"
                .into(),
        );
    }
    if db.is_some_and(otto_tenant::is_retryable_lock_failure) {
        tracing::warn!(error = %e, "usage batch gave up waiting for a lock; asking for a retry");
        return ApiError::Unavailable(
            "the platform was busy with this resource server's usage (a rename, or another \
             batch for the same org) and gave up waiting; one org's events were not \
             recorded, resend the whole batch (events already recorded come back as \
             duplicates)"
                .into(),
        );
    }
    ApiError::from(e)
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
    CallingResourceServer { server: rs, .. }: CallingResourceServer,
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
/// `service`, `meters`, `budget` and `blocked_reason` are the calling
/// resource server's own only: another service's usage or budget never shows
/// here, so a hard stop on one service never blocks another. `budget` is
/// absent when the org has set none for the caller's service.
///
/// `blocked_reason` says why the caller must refuse billable calls, as
/// [`gate::blocked_reason`] decides (the same function the console's usage
/// page uses): `budget_exceeded` (its budget's hard stop) or
/// `payment_required` (billing is enabled, the org is not in good standing
/// to pay — no subscription, `unpaid`, or a failed payment past its grace —
/// and the service's spend this month is above zero, past its free tiers);
/// the budget wins when both apply. With billing disabled
/// ([`Billing::Disabled`]) there is no way to put a card on file, so
/// `payment_required` is never answered. The platform only reports it;
/// resource servers enforce it, and fail open. Spend is computed only when an
/// answer needs it ([`gate::needs_spend`]): with a budget, or when payment
/// is required. An org in good standing with no budget never waits on (or
/// fails with) the price book.
///
/// The legacy family-wide fields are all still served for clients pinned to
/// an older `otto-resource`, but `hard_stop` is always `false`: an older
/// client blocks on `hard_stop && billable_count >= included_ops`, and with a
/// family-wide count that would let one service's usage stop work in another.
async fn usage_status(
    State(db): State<Db>,
    State(billing): State<Billing>,
    CallingResourceServer { server: rs, .. }: CallingResourceServer,
    Path(org): Path<Uuid>,
) -> Result<Json<UsageStatus>, ApiError> {
    live_org(&db, org).await?;

    let mut tx = db.begin(OrgId::from(org)).await?;
    let usage = tx.current_usage().await?;
    let limits = tx.plan_limits().await?;
    let (meters, gate) = match rs.service.as_deref() {
        Some(service) => {
            let meters = tx.service_meter_usage(service).await?;
            let period = Month::containing(usage.period_start);
            (
                meters,
                service_gate(&mut tx, service, period, billing).await?,
            )
        }
        None => (Vec::new(), Gate::default()),
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
        budget: gate.budget,
        blocked_reason: gate.blocked_reason.map(str::to_owned),
    }))
}

/// What usage-status says about the caller's spend this period.
#[derive(Debug, Default)]
struct Gate {
    /// `None` when the org has set no budget for the service.
    budget: Option<BudgetStatus>,
    /// [`BUDGET_EXCEEDED`], [`budgets::PAYMENT_REQUIRED`], or `None`.
    blocked_reason: Option<&'static str>,
}

/// The caller's budget this period and whether it must refuse billable
/// calls, rating its spend only when the answer depends on it
/// ([`gate::needs_spend`]).
///
/// A budget whose spend cannot be computed (a malformed price version, an
/// overflow) is still reported, with `spend_cents` and `percent_used` null,
/// `blocked` false and reason `spend_unavailable`; unknown spend never
/// requires payment either: enforcement fails open, visibly. A database
/// error fails the request.
async fn service_gate(
    tx: &mut Tx<'_>,
    service: &str,
    period: Month,
    billing_mode: Billing,
) -> Result<Gate, ApiError> {
    let has_budget = budgets::get_budget(tx, service)
        .await
        .map_err(ApiError::internal)?
        .is_some();
    // With billing off every org is in good standing, without a query.
    let standing: Standing = gate::standing(tx, billing_mode)
        .await
        .map_err(ApiError::internal)?;
    if !gate::needs_spend(has_budget, standing) {
        return Ok(Gate::default());
    }
    let status = budgets::service_status(tx, service, period)
        .await
        .map_err(ApiError::internal)?;
    Ok(Gate {
        budget: wire_budget(&status),
        blocked_reason: gate::blocked_reason(&status, standing),
    })
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
    _caller: CallingResourceServer,
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
    _caller: CallingResourceServer,
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
    _caller: CallingResourceServer,
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
    _caller: CallingResourceServer,
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
    _caller: CallingResourceServer,
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
