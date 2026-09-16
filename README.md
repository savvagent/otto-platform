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

This repo currently ships no HTTP surface (no OAuth endpoints, no console) —
see "What's not here yet" below.

## Crate layout

```
crates/
├── otto-tenant/          lowest-level: typed ids, the pinned-transaction
│                         connection pool (Db/Tx/Unpinned), the row-level-
│                         security isolation proof, the audit-events pattern.
│                         Owns no domain model — no users, no orgs.
├── otto-core/            identity domain: users, orgs, org_members, teams,
│                         org_invites, locales, account labels. Built on
│                         otto-tenant.
├── otto-billing/         usage metering and plan-limit queries
│                         (usage_events, org_period_usage, plans,
│                         subscriptions). Built on otto-tenant and otto-core.
├── otto-auth/            OAuth 2.1 authorization server, passkeys/WebAuthn,
│                         browser sessions, personal access tokens,
│                         login-attempt rate limiting. Built on otto-tenant
│                         and otto-core.
└── otto-platform-server/ thin binary: loads config, connects, runs
                          migrations, verifies tenant isolation, prints
                          ready. Not a full HTTP API yet — see below.
```

Dependency direction: `otto-tenant` ← `otto-core` ← `otto-billing`,
`otto-auth`. `otto-platform-server` depends only on `otto-tenant` (it just
needs to migrate and verify isolation).

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

- **No HTTP surface.** `otto-platform-server` migrates and verifies isolation
  and then idles; it does not serve OAuth endpoints, a console, or any REST
  API. Otto Console and the OAuth HTTP routes are future work.
- **No enterprise SSO.** `idp_connections`/`claimed_domains`/`user_identities`
  were not carried over from otto-factory — no extracted code touches them.
  `orgs.enforce_sso` is carried as a plain flag for a future implementation.
- **No `plans.features` JSONB column.** Design doc §4 proposes one to gate
  per-service capabilities from a shared plan; not added here since no
  extracted code reads or writes it yet.

## Running it locally

Requires a local Postgres. Point `DATABASE_URL` at it (see `.env.example`):

```sh
cp .env.example .env
# edit .env: DATABASE_URL=postgres://postgres:postgres@localhost:5432/otto_platform

cargo run -p otto-platform-server
```

On startup it will:

1. Connect to `DATABASE_URL`.
2. Run every migration in `crates/otto-tenant/migrations/` (idempotent —
   safe to run from multiple replicas at once; sqlx takes a Postgres
   advisory lock for the duration).
3. Verify tenant isolation is actually enforced — as the role a tenant
   transaction runs as, not just that the migrations ran — and refuse to
   report ready if it is not.
4. Log `otto-platform-server ready: ...` and idle until `Ctrl-C`.

Set `OTTO_RUN_MIGRATIONS=0` to skip step 2 (e.g. a deployment that migrates
as a separate step ahead of a rolling restart).

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

Every unit test in this workspace runs without a database (pure-logic tests
for the isolation-report judgment, redirect-URI matching, PKCE, rate-limit
math, label generation, and locale parsing). No `#[sqlx::test]` integration
tests are included in this extraction — otto-factory's original `of-core`/
`of-auth` integration test suites (which exercise real signup/login/OAuth
flows against a live Postgres) were not ported; see the extraction notes for
why. To exercise the schema and RLS against a real database by hand:

```sh
createdb otto_platform_dev
DATABASE_URL=postgres://localhost/otto_platform_dev cargo run -p otto-platform-server
```

A successful boot logs a line like:

```
tenant isolation enforced as role "otto_app" (assumed via SET LOCAL ROLE); 7 tenant tables, 7 forced
```

## License

AGPL-3.0-or-later. See `LICENSE`.
