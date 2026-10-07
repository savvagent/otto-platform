# otto-platform

The shared identity/auth/billing/tenant-isolation substrate for the otto-*
family of agent-facing MCP servers (otto-factory, otto-flags, and future
otto-* services).

## Relationship to otto-factory, otto-flags, and the design doc

otto-factory's `of-core`/`of-auth` crates originally mixed generic identity,
auth, and billing infrastructure together with otto-factory-specific domain
code (jobs, repos, leases, trackers, messages). This repository is the
extraction of just the generic substrate, so that a second product,
otto-flags, and any future otto-* service can share one identity/org/billing/
auth backend instead of each reimplementing it.

See otto-flags' design doc, `docs/specs/2026-09-15-otto-flags-design.md` §2–§5
(in the otto-flags repo), and its `VISION.md`, for the full rationale. In
short:

- One physical **identity database** (this repo's Postgres) holds `orgs`,
  `users`, `org_members`, auth, and billing. It is the single source of truth
  for "who is this org" and "what can they do."
- Each otto-* service keeps its **own domain database** (otto-factory's
  jobs/repos/leases; otto-flags' flags/environments/targeting). They share no
  tables, only the same `org_id` UUID namespace — no cross-database foreign
  keys, application-level referential integrity only.
- Tokens are minted by this repo's auth layer and audience-bound per service
  (RFC 8707 resource indicators). A token minted for one otto-* service
  cannot be replayed against another.

**otto-factory is not yet repointed at this repo.** This extraction proves the
split compiles and boots against a real Postgres; wiring otto-factory to
depend on it (and otto-flags to build its own domain crate against
`otto-tenant`) is deliberately deferred, separate work.

`otto-platform-server` serves the identity HTTP surface — the OAuth 2.1
authorization server, sign-in (passkeys and enterprise SSO), and the
account/org API — for every registered resource server. See "What's not here
yet" below for what is still to come.

## Crate layout

```
crates/
├── otto-tenant/          lowest-level: typed ids, the pinned-transaction
│                         connection pool (Db/Tx/Unpinned), the row-level-
│                         security isolation proof, the audit-events pattern,
│                         `Cipher` (AES-256-GCM encryption at rest).
│                         Owns no domain model — no users, no orgs.
├── otto-core/            identity domain: users, orgs, org_members, teams,
│                         org_invites, locales, account labels, enterprise
│                         SSO data (IdP connections, claimed domains,
│                         federated identities, SSO ceremonies,
│                         enforce_sso guards). Built on otto-tenant.
├── otto-billing/         usage metering and plan-limit queries
│                         (usage_events, org_period_usage, plans,
│                         subscriptions). Built on otto-tenant and otto-core.
├── otto-auth/            OAuth 2.1 authorization server, passkeys/WebAuthn,
│                         browser sessions, personal access tokens,
│                         login-attempt rate limiting, OIDC federation client
│                         and DNS domain verification. Built on
│                         otto-tenant and otto-core.
├── otto-web/             the HTTP surface as a library: OAuth discovery,
│                         /oauth/*, /sso/callback, /api/auth/*, /api/me*,
│                         and the org API (members, invites, teams, SSO
│                         admin, tokens, usage, audit). Routes and the
│                         OpenAPI document come from one catalog. Built on
│                         otto-tenant, otto-core, otto-billing, otto-auth.
└── otto-platform-server/ thin binary: loads config, connects, runs
                          migrations, verifies tenant isolation, then serves
                          /healthz, /readyz and otto-web's router.
```

Dependency direction: `otto-tenant` ← `otto-core` ← `otto-billing`,
`otto-auth` ← `otto-web` ← `otto-platform-server`.

Because `otto_tenant::Db` and `otto_tenant::Tx` are defined in a crate that
`otto-core`/`otto-billing`/`otto-auth` depend on rather than own, Rust's
orphan rules mean their query methods are added as **extension traits**
(`otto_core::orgs::OrgsExt`, `otto_core::orgs::OrgsTxExt`,
`otto_core::teams::TeamsExt`, `otto_core::invites::InvitesExt`,
`otto_core::invites::AccountClaimsExt`, `otto_billing::usage::UsageExt`)
rather than the inherent `impl Db { ... }` / `impl Tx<'_> { ... }` blocks
otto-factory's original single `of-core` crate could write. Import the
trait alongside `Db`/`Tx` to call its methods, e.g.:

```rust
use otto_core::orgs::OrgsExt;
use otto_tenant::Db;

let user = db.get_user(user_id).await?;
```

## What's not here yet

- **No resource-server API yet.** Token introspection (RFC 7662), usage
  ingest, and lifecycle webhooks are separate pieces of Phase 4 of
  `docs/plans/2026-10-06-platform-cutover.md`, as is the console UI (the
  server serves the API the console calls, not the console itself).
- **Consent screens show raw scope names.** Each resource server's scopes
  come from the `resource_servers` registry, which carries no human-readable
  descriptions yet. Adding them needs a migration; tracked in #3.
- **No `plans.features` JSONB column.** Design doc §4 proposes one to gate
  per-service capabilities from a shared plan; not added here since no
  extracted code reads or writes it yet.

## Running it locally

Requires a local Postgres. Point `DATABASE_URL` at it and set the two
required settings (see `.env.example`, which documents every variable):

```sh
cp .env.example .env
# edit .env: DATABASE_URL=postgres://postgres:postgres@localhost:5432/otto_platform
#            OTTO_ENCRYPTION_KEY=$(openssl rand -base64 32)

cargo run -p otto-platform-server
```

Configuration is all `OTTO_*` (plus `DATABASE_URL` and `RUST_LOG`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | Postgres connection string. |
| `OTTO_PUBLIC_URL` | required | Public origin, e.g. `https://otto.savvagent.com`. The OAuth issuer and every link are built from it, and its **host is the WebAuthn relying party id** — changing it invalidates every passkey. |
| `OTTO_ENCRYPTION_KEY` | required | 32 bytes, base64. Encrypts secrets at rest (SSO IdP client secrets). |
| `OTTO_BIND` | `0.0.0.0:8080` | Listen address. |
| `OTTO_CLIENT_IP_HEADER` | unset | Header a trusted proxy *overwrites* with the client address (`fly-client-ip` on Fly). Keys rate limits and audit IPs; leave unset without such a proxy. |
| `OTTO_ENFORCE_QUOTAS` | `0` | Reporting only: whether resource servers enforce hard-stop plans, echoed as `enforced` by the usage endpoint. |
| `OTTO_RUN_MIGRATIONS` | `1` | Apply migrations at startup. |
| `OTTO_LOG_FORMAT` | `text` | `json` for structured logs. |

On startup it will:

1. Connect to `DATABASE_URL`.
2. Run every migration in `crates/otto-tenant/migrations/` (idempotent —
   safe to run from multiple replicas at once; sqlx takes a Postgres
   advisory lock for the duration).
3. Verify tenant isolation is actually enforced — as the role a tenant
   transaction runs as, not just that the migrations ran — and refuse to
   report ready if it is not.
4. Build the WebAuthn relying party from `OTTO_PUBLIC_URL` (failing here, not
   at someone's first sign-in, if it has no host) and serve HTTP.

Set `OTTO_RUN_MIGRATIONS=0` to skip step 2 (e.g. a deployment that migrates
as a separate step ahead of a rolling restart).

A resource server must be registered (`otto_auth::resources::register`, which
each service calls at its own startup) before clients can authorize against
it. The authorization server serves every registered one; a client names its
target with the RFC 8707 `resource` parameter, which may be omitted only while
exactly one is registered.

### Running just the migrations

Any tool that runs `sqlx::migrate!` against `crates/otto-tenant/migrations/`
works, including the `sqlx-cli`:

```sh
sqlx migrate run --source crates/otto-tenant/migrations
```

## Testing

```sh
cargo build --workspace
cargo test --workspace
```

Unit tests run without a database. The integration tests (`#[sqlx::test]`,
including `otto-web`'s HTTP tests, which drive the real router with a
software passkey authenticator and a mock IdP) need a Postgres whose role can
create databases, named by `DATABASE_URL` — CI uses a `postgres:16` service on
port 15434 (see `.github/workflows/ci.yml`; create the `otto_app` role first).
To run the server against a database by hand:

```sh
createdb otto_platform_dev
DATABASE_URL=postgres://localhost/otto_platform_dev \
  OTTO_PUBLIC_URL=http://localhost:8080 \
  OTTO_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  cargo run -p otto-platform-server
```

A successful boot logs a line like:

```
tenant isolation enforced as role "otto_app" (assumed via SET LOCAL ROLE); 7 tenant tables, 7 forced
```

## License

AGPL-3.0-or-later. See `LICENSE`.
