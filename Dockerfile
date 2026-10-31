# syntax=docker/dockerfile:1

# savvagent-platform-server image, with the console bundle baked in for self-hosters.
#
# The bundle lives at /srv/console; the server serves it when SAVVAGENT_STATIC_DIR
# points there (fly.toml does). An optional Cloudflare Worker (web/worker,
# docs/deploy/cloudflare.md) can serve it from the edge instead.

# ---------------------------------------------------------------- console
# Built first and separately. It changes on a different cadence from the server
# and shares none of its toolchain, so a Rust edit must not reinstall npm
# packages and a console edit must not recompile a workspace.
FROM node:22-slim AS console

WORKDIR /web
# Manifests alone, so `npm ci` is cached until a dependency actually changes.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# ---------------------------------------------------------------- server
FROM rust:1-slim-bookworm AS build

# webauthn-rs (savvagent-auth) pulls in webauthn-attestation-ca, which links
# openssl for attestation certificate verification. openssl-sys builds against
# the system OpenSSL, so it needs the headers and pkg-config to find them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# No DATABASE_URL and no `.sqlx` offline data: every statement is a runtime
# `sqlx::query`, not a `query!` macro, so the image builds with no database.
#
# The cache mounts hold the registry and the target directory across builds.
# `target/` lives inside one, so the binary has to be copied out within the
# same RUN — anything left there vanishes with the mount. Ids keep these
# caches from being shared with other projects' builds on the same host.
RUN --mount=type=cache,id=otto-platform-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=otto-platform-target,target=/app/target,sharing=locked \
    cargo build --release -p savvagent-platform-server \
    && cp target/release/savvagent-platform-server /usr/local/bin/savvagent-platform-server

# ---------------------------------------------------------------- runtime
FROM debian:bookworm-slim AS runtime

# ca-certificates for Postgres over TLS (and, later, outbound OIDC calls).
# libssl3 because the binary links the system OpenSSL dynamically (see above).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Nothing here writes to the filesystem or binds a privileged port.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin savvagent
USER savvagent

COPY --from=build   /usr/local/bin/savvagent-platform-server /usr/local/bin/savvagent-platform-server
COPY --from=console /web/build                          /srv/console

# SAVVAGENT_STATIC_DIR is deliberately not defaulted here: a deployment opts in (fly.toml
# does), so an API-only or Worker-fronted deployment is not shadowed by a second console.
ENV SAVVAGENT_BIND=0.0.0.0:8080 \
    SAVVAGENT_LOG_FORMAT=json \
    RUST_LOG=info

EXPOSE 8080

# Exec form, so the process is PID 1 and receives SIGTERM directly and the
# graceful shutdown actually runs on every deploy.
ENTRYPOINT ["/usr/local/bin/savvagent-platform-server"]
