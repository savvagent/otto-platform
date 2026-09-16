//! `otto-platform-server` — boots the shared identity/auth/billing substrate
//! against a real Postgres, runs migrations, and proves tenant isolation is
//! actually in force before calling itself ready.
//!
//! This is deliberately **not** a full HTTP API yet. otto-platform's own
//! network surface (OAuth endpoints, a console) is future work — see
//! `docs/specs/2026-09-15-otto-flags-design.md` in the otto-flags repo. What
//! this binary proves today is narrower and load-bearing on its own: that the
//! five-crate workspace (`otto-tenant`, `otto-core`, `otto-billing`,
//! `otto-auth`) compiles together, that its migrations apply cleanly to a
//! fresh database, and that row-level security is genuinely enforced against
//! whatever role it connects as.

use anyhow::{Context, Result};
use otto_tenant::Db;

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

    tracing::info!("otto-platform-server ready: schema migrated, tenant isolation verified");

    // No HTTP surface yet — see this binary's module docs. Idle until asked
    // to stop, so a deployment can treat this the same as any other
    // long-running service (health-checked, restarted on exit) rather than
    // this boot check racing the process's own shutdown.
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    Ok(())
}

fn init_tracing() -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .context("could not initialize tracing")?;
    Ok(())
}
