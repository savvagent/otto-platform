//! `otto-platform-server` — boots the shared identity/auth/billing substrate
//! against a real Postgres, runs migrations, proves tenant isolation is
//! actually in force, and only then starts serving HTTP.
//!
//! The HTTP surface is health checks plus the identity API and OAuth
//! authorization server (see `lib.rs`). Resource-server endpoints and the
//! console are the rest of Phase 4 of
//! `docs/plans/2026-10-06-platform-cutover.md`.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use otto_platform_server::{app, Config, LogFormat};
use otto_tenant::Db;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    // Loads `.env` if there is one. `dotenvy` never overwrites a variable that
    // is already set, so a file that accidentally ships inside an image cannot
    // override the deployment's real configuration.
    let dotenv = dotenvy::dotenv();

    let config = Config::from_env().context(
        "configuration is incomplete. Copy .env.example to .env for local runs, \
         or set the variables named above in the deployment",
    )?;

    init_tracing(config.log_format)?;
    match dotenv {
        Ok(path) => tracing::debug!(path = %path.display(), "loaded .env"),
        Err(_) => tracing::debug!("no .env file; using the process environment"),
    }

    // Validate the key before anything else can be built with it, so a bad one
    // is a startup error naming the variable rather than a failure the first
    // time something needs to encrypt a secret hours later. `app` checks it
    // again, which is cheap and keeps it from relying on this call.
    otto_tenant::crypto::Cipher::from_base64_key(&config.encryption_key)
        .context("OTTO_ENCRYPTION_KEY is not a valid 32-byte base64 key")?;

    let db = Db::connect(&config.database_url)
        .await
        .context("could not connect to DATABASE_URL")?;

    if config.run_migrations {
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

    let router = app(db, &config)?;

    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("could not bind {}", config.bind))?;
    tracing::info!(
        bind = %config.bind,
        public_url = %config.public_url,
        enforce_quotas = config.enforce_quotas,
        "otto-platform-server ready: schema migrated, tenant isolation verified"
    );

    // `ConnectInfo` is not decoration: `otto_web::state::client_ip` reads the
    // peer address out of it, and that address is what every per-IP throttle and
    // every audit entry is keyed on. Serve without this and `client_ip` returns
    // `None` for every request, which silently disables rate limiting on the
    // login and registration endpoints.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
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

fn init_tracing(format: LogFormat) -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);

    // JSON for deployments, whose log pipeline parses fields; human-readable
    // text for a terminal.
    match format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init(),
        LogFormat::Text => registry.with(tracing_subscriber::fmt::layer()).try_init(),
    }
    .context("could not initialize tracing")?;
    Ok(())
}
