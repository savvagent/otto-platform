# otto-platform: build, deploy, and cut otto-factory over

**Status:** Draft for review.
**Date:** 2026-10-06
**Repos:** `savvagent/otto-platform` (this repo), `savvagent/otto-factory`, and otto-flags (local, unpublished).
**Context:** otto-flags `docs/specs/2026-09-15-otto-flags-design.md` §2–§4 (the "why").
This document covers the "how, in what order."

## Goal

1. otto-platform is a deployed, separately running service. It owns identity, auth,
   billing, and the account/org console, with its own identity database.
2. otto-factory stops owning those things. It authenticates users and agents through
   otto-platform and keeps only its domain: jobs, repos, leases, trackers, and messages.
3. otto-flags can then be built as the second consumer with no further platform work
   beyond registering itself.

## Constraints and decisions already made

- **Production data is disposable.** otto-factory production (`otto-factory.savvagent.com`)
  holds only the owner's test data. The Phase 4 cutover resets data rather than migrating
  it, and re-registering passkeys is acceptable.
- **The platform lives on a `savvagent.com` subdomain.**
- **otto-platform is public, AGPL-3.0-or-later.** otto-flags depends on it from GitHub
  by pinned rev.
- **Scope covers all four phases.** Each phase ships independently and leaves production
  working.

## Where things stand (2026-10-06)

- otto-platform is extracted (5 crates, ~7k lines) and pushed. It has no HTTP surface,
  no CI, no Dockerfile, and no deployment.
- It has already fallen behind otto-factory:
  - **#185** (passkey ceremony ownership check): ~150 lines plus tests.
  - **#189** (enterprise OIDC federation): ~2.5k lines of Rust, ~4k lines of tests,
    ~900 lines of console code, and migration `0031_sso_ceremonies`. The
    `idp_connections`, `claimed_domains`, and `user_identities` tables it depends on
    were deliberately left out of the extraction.
  - `Cipher` (`of-core/src/crypto.rs`), which IdP client secrets and trackers depend on.
- otto-factory does not depend on otto-platform at all.

## Phase 1: Repo hygiene, CI, infrastructure (≈0.5–1 day)

1. **CI** (`.github/workflows/ci.yml`):
   - fmt and clippy `-D warnings`.
   - `cargo test --workspace` against a postgres:16 service that pre-creates `otto_app`.
     Mirror otto-factory's CI setup.
   - A PR-title check.
   - release-please, matching otto-factory's conventions.
2. **Dockerfile** for `otto-platform-server`, a multi-stage build modeled on otto-factory's.
3. **Fly infrastructure, provisioned early to shake out problems:**
   - App `otto-platform` in org `savvagent`, region `iad`.
   - Database `otto_platform` on `otto-db`, one unmanaged Postgres app shared with
     otto-factory (`otto_factory`). It's unmanaged because migrations need CREATEROLE,
     which the managed `savvagent-pg` cluster won't grant (otto-factory
     `docs/deploy/fly.md`). It's shared for cost; split onto dedicated instances before
     real customers, since each app's attach role is a superuser on the instance.
   - Deploy the current boot-only binary and confirm `/readyz`. This needs a minimal
     health route.
4. **Add the CI deploy job** (`flyctl deploy` on release), using an app-scoped
   `FLY_API_TOKEN`.

**Exit:** green CI, and `otto-platform.fly.dev/readyz` returns 200 against its own database.

## Phase 2: Catch up with otto-factory (≈2–3 days)

Port the drift so otto-factory loses nothing when it switches over.

1. **#185** into `otto-auth::passkeys`: `CeremonyAccountMismatch`, the `expected`
   parameter, the refusal audit row, and the `PASSKEY_REGISTRATION_REFUSED` action.
2. **#189 data layer and logic:**
   - A new migration `0006_sso.sql`: `idp_connections`, `claimed_domains`,
     `user_identities`, `sso_ceremonies`, plus the corresponding RLS registrations.
   - otto-core gains `ceremonies`, `domains`, `identities`, `idp`, and the SSO additions
     to `orgs.rs`.
   - otto-auth gains `oidc.rs`, `dns.rs`, the SSO token prefixes, error variants, and the
     enforce_sso refusal in `login.rs`.
   - Port the tests alongside.
3. **`Cipher`** into `otto-tenant`, a new `crypto` module, since every service needs
   encryption at rest.
4. **Make the tenant role configurable.** `otto_app` is hard-coded in `otto-tenant/src/db.rs`.
   Keep `otto_app` as the default, but let a consumer whose database predates the platform
   name its own role. See Phase 3 step 2.
5. **Register multiple resources and scopes.** The AS currently accepts exactly one
   `resource_uri`, and scopes are hard-coded to otto-factory's (`KNOWN_SCOPES`).
   - Replace both with a registry: a `resource_servers` table holding `resource_uri`,
     `allowed_scopes`, and introspection credentials.
   - Keep the data model only for now. Phase 4 adds the HTTP side.

**Exit:** otto-platform matches otto-factory feature-for-feature on identity, auth, and
billing. Every ported test passes.

## Phase 3: otto-factory runs on otto-platform crates, same deployment (≈3–5 days)

This is a library swap only: one database, one process, one hostname. It proves the
extraction against real traffic before anything moves.

1. Add `otto-tenant`, `otto-core`, `otto-auth`, and `otto-billing` as git dependencies,
   pinned by rev. Delete the matching modules from `of-core`/`of-auth` and keep the
   domain modules.
2. **Migrations.** otto-factory keeps its own migrator and its 0001–0031 history, and
   never calls `otto_tenant::Db::migrate` (versions collide and checksums differ). Add
   migration `0032` to rename the role `of_app` → `otto_app`. There's precedent: 0018
   renamed `df_app` → `of_app`. After that, `otto_tenant::Db` works unmodified.
3. **Call sites:**
   - ~100 source and ~200 test call sites: add extension-trait imports (`OrgsExt`,
     `TeamsExt`, `InvitesExt`, `UsageExt`). Mostly mechanical.
   - ~120 `of_core::` and ~80 `of_auth` path references to rewrite.
4. **Semantic fixes the extraction introduced:**
   - `of-mcp/src/auth.rs:152` matches only `AuthError::Db`, so the new `AuthError::Tenant(Db)`
     would turn a database outage into a 401. Map it to 503.
   - `otto_core::delete_team` dropped the "team in use by repos/jobs" guard. Re-add it as
     an otto-factory wrapper.
   - Factory columns on `orgs` (`next_job_seq`, `jobs_completed_total`,
     `jobs_failed_total`) stay where they are for now. Phase 4 moves them.
   - Token prefixes change from `of_*` to `otto_*`. Existing tokens still validate because
     tokens are compared by hash. Fix the tests that check prefixes.
5. Ship through the normal otto-factory release and deploy. Watch for regressions in
   login, passkeys, OAuth, PATs, SSO, and metering.

**Exit:** otto-factory production runs on otto-platform crates, with no identity code of
its own left in `of-core`/`of-auth`.

## Phase 4: Split into separate services (≈1.5–3 weeks)

### Target topology

```
                     otto.savvagent.com  (Fly app: otto-platform)
                     ├── OAuth 2.1 AS, discovery, RFC 7662 introspection
                     ├── login / signup / passkeys / SSO (WebAuthn rp_id = otto.savvagent.com)
                     ├── account + org console (members, teams, SSO, tokens, usage, audit)
                     └── internal API for resource servers (usage ingest, member lookup)
                                 │ identity DB: otto_platform on otto-db
                                 │
     otto-factory.savvagent.com  ├── (Fly app: otto-factory-mcp)
       ├── POST /mcp  (resource server; validates tokens via introspection)
       ├── factory console (queue, repos, trackers, connect), logs in via OAuth to otto.savvagent.com
       └── domain DB: otto_factory on otto-db (no identity tables)

     otto-flags (later): same shape as otto-factory
```

### Workstreams

1. **HTTP surface for otto-platform-server.** Move from `of-web` into otto-platform:
   - discovery
   - `/oauth/*`
   - `/sso/callback`
   - `/api/auth/*`, `/api/me*`, orgs, members, invites, teams, SSO admin, tokens, usage,
     and audit (otto-factory `of-web/src/catalog.rs`)

   Rename the `OF_*` config to `OTTO_*`.
2. **Token introspection** (RFC 7662).
   - `POST /oauth/introspect` authenticates the resource server using its Phase 2
     registry credentials, and returns `active`, `sub`, `org_id`, `role`, `scope`, `aud`,
     and `exp`.
   - otto-factory's `require_bearer` calls it and caches positive results for 60 s.
     Revocation therefore takes up to the cache TTL to take effect.
   - Tokens stay opaque, which keeps today's revocation semantics. Short-lived JWTs are a
     later option if the extra network hop shows up in latency.
3. **Metering across databases.** The domain-transaction atomicity in `usage.rs` can't
   survive the split. Replace it with an outbox:
   - `Factory::charge` writes `usage_outbox` rows in the domain transaction, which keeps
     local atomicity.
   - A background shipper posts batches to `POST /internal/usage`, which is idempotent
     on event id.
   - For quota checks, otto-factory reads the org's period status from the platform and
     caches it for 60 s. Overrun is bounded by that window, which is acceptable for a
     usage bucket.
   - `classify.rs` (the otto-factory price list) stays in otto-factory.
4. **Identity reads from domain code.** These need internal API calls or introspection
   claims:
   - `member_by_email` (`coord.rs:598`)
   - whoami (`org.rs:44`)
   - `require_team_in_org` (`repos.rs:220`, `routes/jobs.rs:89`)
5. **Cross-database references.**
   - Drop otto-factory's FKs to `orgs`/`users`/`teams` and enforce them in the
     application instead.
   - The platform sends lifecycle webhooks (`org.deleted`, `team.deleted`,
     `member.removed`) to each registered resource server, and otto-factory cleans up in
     response.
   - Move `next_job_seq` and the job counters into an otto-factory `org_counters` table.
6. **Audit.** Identity events go to the platform's `audit_events`. Domain events (`REPO_*`,
   `TRACKER_*`, `JOB_*`) go to a domain-side `audit_events` using the same `otto-tenant`
   pattern. The console audit page shows both: the platform owns its own events and links
   to each service's events.
7. **Console split.**
   - Generic `web/` pages move to otto-platform: login, signup, claim, invite, orgs/new,
     settings, members, teams, sso, usage, audit.
   - otto-factory keeps queue, repos, trackers, connect, docs/api, and the overview.
   - otto-factory's console signs in with OAuth authorization code + PKCE against the
     platform, and keeps its own session cookie.
   - The two consoles link to each other.
   - A unified plugin console (design doc open question) is deferred until a second
     service exists to justify the interface.
8. **Data reset and migration squash.** Since production data is disposable:
   - Create the platform identity database fresh.
   - Recreate otto-factory's domain database from a new squashed, domain-only baseline
     migration. This retires the 0001–0031 interleaving for good.
   - Re-register passkeys and OAuth clients.
9. **Deploy and DNS.**
   - Add `otto.savvagent.com` with `fly certs`. DNS is at Namecheap.
   - Cut over by deploying the platform first, then otto-factory pointed at it.
   - Update the MCP client config docs (`client-skills`, `docs/clients/matrix.md`) for
     the new authorization server.

**Exit:** otto-factory production authenticates entirely through `otto.savvagent.com`,
its database holds no identity tables, and otto-flags can register as a second
resource server.

## Decisions needed before Phase 4

1. **Platform hostname.** Proposed: `otto.savvagent.com`.
2. **WebAuthn rp_id.** Proposed: the platform host itself, not `savvagent.com`.
   - Passkey ceremonies happen only on the auth origin. Resource servers never perform
     WebAuthn, so a domain-wide rp_id isn't needed.
   - A domain-wide rp_id would let any `*.savvagent.com` origin (e.g. nels) request
     assertions for otto passkeys, which is needless phishing surface.
3. **Console split.** Proposed: each service keeps its own domain UI and logs in through
   OAuth to the platform (above), rather than a unified plugin console now.
4. **Reset production data at cutover.** Proposed: yes, with a squashed otto-factory
   baseline.

## Follow-ups outside this plan

- otto-flags spec §3 still says `df_app`. Update it to `otto_app` and to the resource-server
  registration flow.
- `plans.features` (design doc §4) remains deferred until the first gated capability.
- `OF_SIGNING_KEY` is set as a Fly secret but nothing reads it. Remove it.

## Tracking

One GitHub issue per phase, filed in `savvagent/otto-platform` (Phases 1, 2, 4) and
`savvagent/otto-factory` (Phases 3, 4). Every PR references its issue.
