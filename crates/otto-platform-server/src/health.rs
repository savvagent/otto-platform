//! Liveness and readiness, which are not the same question.
//!
//! **`/healthz` never touches the database, on purpose.** A liveness probe
//! answers "is this process wedged, should it be killed?", and an orchestrator
//! kills what fails it. Point one at the database and a thirty-second database
//! blip restarts every replica simultaneously — turning a brief outage into a
//! cold start of the entire fleet, against a database that is already unwell.
//!
//! **`/readyz` does touch it**, because it answers a different question: "should
//! traffic come *here*?" The answer to that is no while the database is
//! unreachable, and the remedy is to route elsewhere and try again — not to
//! kill anything. This is the check a load balancer should be pointed at.
//!
//! Mirrors otto-factory's `of-server/src/health.rs`.

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use otto_tenant::Db;

/// How long a readiness check waits on the database.
///
/// Short by design. A readiness probe that hangs for the pool's full acquire
/// timeout is indistinguishable from a hung process to whatever is polling it,
/// and the answer it eventually gives arrives after the decision was needed.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(db)
}

/// `GET /healthz` — the process is running and the runtime is scheduling.
async fn healthz() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

/// `GET /readyz` — this replica can serve a request that needs the database.
async fn readyz(State(db): State<Db>) -> Response {
    // Deliberately *not* `Db::begin`: that needs an `OrgId`, and there is no
    // org here. This is the one place a bare pool query is the right thing,
    // because it touches no tenant table — it is asking about the connection,
    // not about anyone's data.
    let probe =
        tokio::time::timeout(READY_TIMEOUT, sqlx::query("SELECT 1").execute(db.pool())).await;

    match probe {
        Ok(Ok(_)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
            .into_response(),

        // The body says which of the two it was: a refused connection is a
        // database that is down, a timeout is usually a pool with every
        // connection checked out, and those have different fixes.
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "readiness check failed");
            unready("the database rejected a probe query")
        }
        Err(_) => {
            tracing::warn!(timeout = ?READY_TIMEOUT, "readiness check timed out");
            unready("the database did not answer a probe query in time")
        }
    }
}

fn unready(reason: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "status": "unready", "reason": reason })),
    )
        .into_response()
}
