//! `otto-platform-server` — boots the shared identity/auth/billing substrate
//! against a real Postgres, runs migrations, proves tenant isolation is
//! actually in force, and only then starts serving HTTP.
//!
//! The HTTP surface is health checks only for now (see `lib.rs`). The OAuth
//! endpoints and console are Phase 4 of
//! `docs/plans/2026-10-06-platform-cutover.md`.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use otto_tenant::Db;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    // Loads `.env` if there is one. `dotenvy` never overwrites a variable that
    // is already set, so a file that accidentally ships inside an image cannot
    // override the deployment's real configuration.
    let dotenv = dotenvy::dotenv();

    init_tracing()?;
    match dotenv {
        Ok(path) => tracing::debug!(path = %path.display(), "loaded .env"),
        Err(_) => tracing::debug!("no .env file; using the process environment"),
    }

    let bind: SocketAddr = std::env::var("OTTO_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()
        .context("OTTO_BIND must be a socket address like 0.0.0.0:8080")?;

    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must be set. Copy .env.example to .env for local runs.")?;

    // Off by default in case a deployment wants a separate migration step
    // ahead of a rolling restart. On by default for local development, where
    // `cargo run` should always leave the schema current.
    let run_migrations = std::env::var("OTTO_RUN_MIGRATIONS")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    let db = Db::connect(&database_url)
        .await
        .context("could not connect to DATABASE_URL")?;

    if run_migrations {
        // sqlx holds a Postgres advisory lock for the whole run, so several
        // replicas starting together is safe: the losers block until the
        // winner is done rather than racing each other through the same DDL.
        tracing::info!("applying migrations");
        db.migrate().await.context("migrations failed")?;
    } else {
        tracing::warn!("OTTO_RUN_MIGRATIONS is off; assuming the schema is already current");
    }

    // Prove tenant isolation before doing anything else, never after.
    // Row-level security is the one guard the *environment* can switch off —
    // the same migrations isolate perfectly under one database role and not
    // at all under another, and no amount of reading this repository tells
    // you which one a deployment connects as. Discovering that from a
    // customer is not a recoverable failure, so it is a startup error naming
    // the remediation.
    let isolation = db
        .verify_tenant_isolation()
        .await
        .context("refusing to serve: tenant isolation is not enforced by this database")?;
    tracing::info!("{}", isolation.summary());

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("could not bind {bind}"))?;
    tracing::info!(%bind, "otto-platform-server ready: schema migrated, tenant isolation verified");

    axum::serve(listener, otto_platform_server::router(db))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    tracing::info!("shut down cleanly");
    Ok(())
}

/// Resolves on SIGINT or SIGTERM.
///
/// `SIGTERM` is the one that matters — it is what a container runtime sends
/// before it waits its grace period and then sends `SIGKILL`. A server that
/// only handles `SIGINT` looks fine in a terminal and is hard-killed on every
/// single deploy, dropping whatever was in flight.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install the SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install the SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT; shutting down"),
        _ = terminate => tracing::info!("SIGTERM; shutting down"),
    }
}

fn init_tracing() -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);

    // JSON for deployments, whose log pipeline parses fields; human-readable
    // text for a terminal. Read directly rather than after dotenv-loaded
    // config, because tracing has to be up before anything else can log.
    let json = std::env::var("OTTO_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
    } else {
        registry.with(tracing_subscriber::fmt::layer()).try_init()
    }
    .context("could not initialize tracing")?;
    Ok(())
}
