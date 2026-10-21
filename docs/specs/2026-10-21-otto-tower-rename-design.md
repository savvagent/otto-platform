# otto-tower rename — design and decomposition

> **Status:** IN PROGRESS
> **Epic:** savvagent/otto-platform#81

## Goal

Rename otto-factory to **otto-tower** everywhere a user, buyer, or agent sees it. The server stays content-readable.

## Success criteria (verbatim from the epic)

1. `https://otto-tower.savvagent.com/mcp` is the canonical endpoint and resource URI. `https://otto-factory.savvagent.com/mcp` keeps working (both URIs registered at the platform) until a published sunset date, and each response through it carries a deprecation notice.
2. The MCP server advertises itself as `otto-tower`, so a client added with the documented `claude mcp add` command exposes `mcp__otto-tower__*` tools. `whoami` and `usage` say otto-tower.
3. The console, marketing pages, plan catalog (`GET /api/plans`), README, design docs and deploy runbook name otto-tower. A repo-wide grep for `otto-factory` finds only the deliberately kept internal identifiers and the deprecation path.
4. The GitHub repo is `savvagent/otto-tower` (GitHub redirects the old name), and the rbh-plugins plugin `otto-factory` becomes `otto-tower` with skills `tower-scanner` and `tower-worker`. Every cross-reference in dev-workflow skills and `workflow-section.md` is updated.
5. The billing service id is `otto-tower` before otto-factory#222 records any meter, so no usage or Stripe data exists under the old name.

### Sharpened readings (assumptions)

- **Criterion 5.** otto-factory#222 was already deployed when work started: v0.13.0 went out at 2026-10-21T03:11Z, declaring `otto-factory/jobs_completed`. The owner chose to rename the slug to `otto-tower` and retire the old declaration while metered usage is still zero. The criterion is therefore read as: no metered usage and no Stripe data exists under `otto-factory/*`. The guarded rename enforces this.
- **Criterion 3's grep.** It covers the otto-factory repo, which is the product's own repo. In otto-platform, the criterion covers the user-visible surfaces only: marketing, console, README, deploy docs and the plan catalog. Crate doc comments and test fixtures that use `otto-factory` as an example slug are internal.
- **Criterion 1's deprecation notice.** The notice is carried in HTTP headers on every response: `Deprecation`, `Sunset` (when a date is configured) and `Link rel="successor-version"`. MCP `initialize` instructions over the legacy host also open with a deprecation paragraph, so agents see it, not only HTTP tooling.

## Non-goals (verbatim)

- Renaming internal identifiers: the `of-*` crates, `OF_*` env vars, the `otto_factory` database on otto-db, and the Fly app `otto-factory-mcp`.
- Making the server content-blind.
- Any behaviour change to jobs, leases, messages or trackers.

## Design

### D1. Resource URI alias at the platform

There is one resource server. Its canonical `resource_uri` is renamed to the otto-tower URI, and the old URI becomes a **time-boxed alias**.

**Storage.** `resource_server_aliases(alias_uri PK, resource_uri FK ON UPDATE CASCADE, sunset_at timestamptz NOT NULL, dropped_at timestamptz NULL)`.

**Tombstones.** Alias rows are never deleted. `register`, `rename` and alias creation refuse any URI that already appears in `resource_servers.resource_uri` or `resource_server_aliases.alias_uri`, whether the alias is live, expired or dropped. A retired URI can therefore never be given to a different server.

**Rename transaction.** The rename runs as one transaction that:
- changes the canonical PK; FKs follow through `ON UPDATE CASCADE`;
- inserts the alias;
- rewrites `resource` from the old URI to the new one on `access_tokens`, `refresh_tokens` and `authorization_codes`, so existing tokens stay valid past the sunset and never point at a dead URI;
- rewrites `usage_event_ids.resource_uri`, so dedupe survives the rename;
- optionally sets `name` with `--name`. The consent screen shows this name.

**Rollback.** `rename <new> <old>`, when `<old>` is a live alias of `<new>`, swaps the two URIs.

**Authentication.** A resource server may authenticate (introspection Basic auth) as its canonical URI or as a live alias. `CallingResourceServer` keeps the canonical row and carries the authenticated URI in a **separate field**. Only introspection reads that field: it sets `aud` to the URI the caller authenticated as. The Bearer-secret path has no URI, so its `aud` is the canonical URI. Usage ingest and dedupe always use the canonical URI.

**OAuth flows.** Authorize, code redemption, refresh and PAT issuance resolve a live alias to its canonical row. They store and compare canonical URIs.

**Expired or dropped aliases** behave exactly like an unknown URI: `invalid_target`, and introspection authentication fails.

**Operator commands:**
- `resource rename <old-uri> <new-uri> --alias-until <RFC3339> [--name <name>]`
- `resource drop-alias <alias-uri>`
- `resource list` and `resource describe` show aliases with their sunset

**Deploy-order consequences.**
- Before the rename, the running otto-factory binary (`OF_RESOURCE_URI` = old URI) authenticates as the canonical URI.
- After the rename, it authenticates as the live alias, gets `aud` equal to the old URI, and keeps working with no config change.
- Only after `resource list` shows the alias may the Fly env flip (`OF_RESOURCE_URI` = new URI) happen. Flipping first fails introspection authentication, and the server answers 503 everywhere.

### D2. Guarded billing-service rename at the platform

**Operator command:** `resource rename-service <resource-uri> <new-slug>`.

**Implementation.** It is implemented as a `SECURITY DEFINER` function, added in a new migration, following the pattern of `claim_usage_event` (0009). It counts blockers and re-keys rows across **all orgs** in one transaction. A plain transaction on a role without BYPASSRLS would see zero rows in the FORCE-RLS tables and pass vacuously.

**Blocks only on billing or money data under the old service:**
- `usage_events` rows whose meter starts with `<old>/`
- `org_meter_period_usage` rows whose meter starts with `<old>/`
- any `stripe_meters` or `stripe_prices` row for an `<old>/` meter
- `stripe_meter_outbox` rows whose `event_name` comes from an `<old>/` meter

The error names each blocker and its count.

**Re-keys, when nothing blocks:**
- `meters`: `<old>/<m>` becomes `<new>/<m>`
- `price_versions`
- `org_service_period_usage` (service pool data, not billing)
- `service_budgets`
- `budget_alerts`
- `resource_servers.service`

**Amended during #86.** `set-service` still refuses once meters are declared. However, a service's unmetered pool, budget and alert rows now follow any slug change by `ON UPDATE CASCADE`, where before they were left stranded under the old slug.

**Closing the ingest race.** A usage batch could be in flight while a rename commits. To stop it stranding rows under the old slug, new rows are tied to the declared meters and services by NOT VALID foreign keys:
- `usage_events.meter` and `org_meter_period_usage.meter` reference `meters(key)`.
- The pool, budget and alert tables reference `resource_servers(service)` with `ON UPDATE CASCADE`.

`rename_service` takes a table lock and then the row lock before it counts. A batch caught mid-rename gets a retriable 503. The ingest cost of these keys is tracked in #90.

**Plan catalog.** `GET /api/plans` then lists `otto-tower/jobs_completed`.

### D3. Legacy host in otto-factory

**Config.**
- `OF_LEGACY_HOSTS` is a comma-separated list of extra accepted hosts, all of them deprecated. They are added to `allowed_hosts`.
- `OF_LEGACY_SUNSET` is an optional RFC 3339 date.
- Both error when set but unparseable, never a silent default.

**Origin host.** The Cloudflare Worker **sets** `X-Forwarded-Host` from `request.url`, overwriting anything the client sent. of-server reads the origin host from `X-Forwarded-Host`, else `Host`.

**Notices on legacy-host requests.** Every response to a request whose origin host is a legacy host carries:
- `Deprecation: true`
- `Link: <https://{canonical host}{path}>; rel="successor-version"`
- `Sunset: <http-date>`, when a sunset date is configured

MCP `initialize` instructions over a legacy host open with a deprecation paragraph that names the new URL and the sunset date.

**Discovery.** Over a legacy host, `/.well-known/oauth-protected-resource` and the WWW-Authenticate `resource_metadata` advertise the legacy resource URI, `https://<legacy host>/mcp`. Fresh OAuth flows started on the old URL therefore pass the client's RFC 9728 resource check.

**The host only selects; it never authorizes.** The host picks which configured value is used for notices, discovery and redirects. Token validation (`into_claims`) stays bound to `OF_RESOURCE_URI` alone. The rule that the audience is configuration and never derived from the Host still holds, and a test pins it.

**Amended during integration review.** Production is not fronted by the Cloudflare Worker: `otto-factory.savvagent.com` resolves straight to Fly. So of-server itself answers a legacy host's console pages and `/auth/login` with the 308. The Worker keeps the same rule for a Worker-fronted deployment.

**Console redirect.** On a legacy host, the console redirect answers SPA (non-origin) paths and `/auth/login` on a legacy host with a 308 to the canonical host. Every origin prefix is still proxied: `/mcp`, `/.well-known`, `/api`, `/auth/*` (except login), `/platform/webhooks`, `/webhooks`, `/oauth`. Webhook deliveries never get redirected.

### D4. Cutover is human-run and comes after the code ships

The code PRs change no deployed values: not `fly.toml` env values, Worker routes, certificates, DNS or platform registrations. Merging and deploying them before the cutover is safe. The cutover runbook in otto-factory `docs/deploy/fly.md` gives the order:

1. Release and deploy otto-platform with P1, P2a and P2b.
2. Release and deploy otto-factory with F1, F2 and F3. The new binary declares `otto-tower/jobs_completed`. The platform rejects that, because it is outside the service's namespace, so the shipper retries and **pauses shipping, losing nothing**. Expect a repeated declaration-failure log line.
3. Run the preflight. In production, `otto-platform-server resource describe` and a read-only check show no `otto-factory/*` rows in `stripe_meters` or `stripe_prices`.
4. **Immediately** run `resource rename-service <old-uri> otto-tower`. The shipper's next retry declares the meter and drains the queue.
5. Set up the new host: `fly certs add otto-tower.savvagent.com`, DNS, the Worker route and the custom domain.
6. Run `resource rename <old-uri> <new-uri> --alias-until <sunset> --name otto-tower`, then confirm `resource list` shows the alias.
7. Register the first-party console client for the new host with `client register --redirect-uri https://otto-tower.savvagent.com/auth/callback --first-party`.
8. Flip the Fly env: `OF_PUBLIC_URL`, `OF_RESOURCE_URI`, `OF_LEGACY_HOSTS=otto-factory.savvagent.com`, `OF_LEGACY_SUNSET`, `OF_CONSOLE_CLIENT_ID`. Then deploy.
9. Run `resource set-webhook` to point the lifecycle webhook URL at the new host.
10. Tell customers to move their tracker webhooks and re-add the MCP server before the sunset.
11. After the sunset, run `resource drop-alias`.

**Rollback.** Before step 8, swap the URIs back with `resource rename <new> <old>`.

### D5. Kept identifiers (grep allow-list)

- The `of-*` crates, the `OF_*` env vars, the `otto_factory` database and the `factory` Postgres role.
- The Fly app `otto-factory-mcp` and its `fly.dev` host.
- The Rust type `Factory`.
- `savvagent/otto-factory#NNN` issue references.
- The GitHub App slug `otto-factory` (separate ticket).
- The tracker trigger-label default `otto-factory`. It is stored data and a behaviour, so it is a non-goal (separate ticket).
- The Cloudflare Worker script names.
- `CHANGELOG.md`.
- Dated historical `docs/specs` and `docs/plans`, except the design of record's title and intro.
- The legacy host where it appears in deprecation config and docs.
- The `factory-scanner:` key prefix, still recognised for back-compat.

### D6. GitHub repo rename

Renaming `savvagent/otto-factory` to `savvagent/otto-tower` is a human hand-off.

### D7. One epic branch and one PR per repo

Each repo's epic branch merges through that repo's own gate. Release order:
1. otto-platform
2. otto-factory
3. The cutover, run by a human
4. rbh-plugins: its release follows otto-factory's docs. During the deprecation window, its skills accept both tool prefixes.

## Stories

| ID | Repo | Story | Batch | Depends on |
|---|---|---|---|---|
| #86 (P1) | otto-platform | Guarded billing-service rename | 0 | none |
| #87 (P3) | otto-platform | Marketing and console say otto-tower | 0 | none |
| #88 (P2a) | otto-platform | Resource URI rename with a time-boxed alias (core, CLI, introspection) | 1 | P1 (same files) |
| #89 (P2b) | otto-platform | OAuth flows resolve resource aliases | 2 | P2a |
| otto-factory#229 (F1) | otto-factory | MCP identity and billing meter say otto-tower | 0 | none |
| otto-factory#230 (F3) | otto-factory | Console, docs, skills and cutover runbook say otto-tower | 0 | none |
| otto-factory#231 (F2) | otto-factory | Legacy host with deprecation notice | 1 | F1 (same files), F3 (`.env.example`) |
| robhicks/rbh-plugins#9 (R1) | rbh-plugins | Plugin becomes otto-tower | 0 | none |

### P1. Guarded billing-service rename (otto-platform, batch 0)

**Scope.** D2 in full.

**Files:**
- `crates/otto-auth/src/resources.rs`
- `crates/otto-platform-server/src/resource_cmd.rs`
- a new migration under `crates/otto-tenant/migrations/`
- tests

**Acceptance criteria:**
- The `SECURITY DEFINER` function described in D2.
- The CLI command, with parse tests.
- sqlx tests:
  - Rename succeeds with declared meters, price versions, budgets, alerts and **unmetered** usage present, and those rows move.
  - Each blocker refuses, and the error names it.
  - A blocker in a second org is detected while running as a role that is neither superuser nor BYPASSRLS (`SET LOCAL ROLE otto_app`).
  - The new slug is validated and must be unique.
- `GET /api/plans` lists the new meter key after the rename.
- **Invariants:** RLS, and append-only migrations.

### P2a. Resource URI rename with a time-boxed alias (otto-platform, batch 1)

**Scope.** D1: storage, tombstones and collision guards; `resources::rename`, swap rollback, `drop_alias` and alias lookup; the token and usage rewrites; the CLI commands `rename`, `drop-alias`, and `list`/`describe` showing aliases; README CLI docs for `rename-service`, `rename` and `drop-alias`; alias authentication of the resource server with the authenticated URI in a separate field; and the introspection `aud` rule.

**Acceptance criteria.** Tests cover:
- an old-URI token introspected after the rename;
- the old binary's Basic user after the rename (`aud` equals the old URI);
- the new Basic user (`aud` equals the new URI);
- Bearer-secret authentication (`aud` is canonical);
- an expired alias (401 at authentication);
- a dropped alias;
- collisions on `register` and `rename` against aliases, live and dead;
- the swap rollback;
- usage ingest through the alias deduping against canonical.

### P2b. OAuth flows resolve resource aliases (otto-platform, batch 2)

**Scope.** Alias-to-canonical resolution in `crates/otto-web/src/oauth.rs` (`resolve_resource`), in `crates/otto-auth/src/oauth.rs` (code redemption, the equality check at about L634, consent seal) and in `crates/otto-auth/src/tokens.rs` (refresh at about L313, PAT issuance).

**Acceptance criteria.** Tests cover:
- authorize with `resource=<alias>` stores canonical;
- code redemption and refresh succeed when the client sends the alias;
- an expired alias gives `invalid_target`.

### P3. Marketing and console say otto-tower (otto-platform, batch 0)

**Scope:**
- In `web/src/lib/services.ts`: slug `tower`, name `Otto Tower`, `mcpUrl` `https://otto-tower.savvagent.com/mcp`, and the console URL on the new host.
- `/products/factory` redirects to `/products/tower`.
- The six locale files change in lockstep, with keys renamed to `product_tower_*`.
- `billing.ts` `serviceName` maps `otto-tower`, and still maps `otto-factory` for historical rows.
- `check-build`'s `PRODUCT_SLUGS`.
- Web tests.
- Product prose in `README.md` (not the CLI section), `web/README.md` and `docs/deploy/*.md`.

**Gates:** `npm run check`, `npm run lint`, `npm test`, `npm run build`.

### F1. MCP identity and billing meter say otto-tower (otto-factory, batch 0)

**Scope:**
- `server_info` name `otto-tower`.
- The instructions text.
- The whoami and usage descriptions.
- The billing error text.
- `RESOURCE_NAME`.
- The WWW-Authenticate realm.
- The OpenAPI title.
- The trackers user-facing error text.
- The outbound User-Agent `otto-tower/<ver>`.
- `METER_JOBS_COMPLETED = "otto-tower/jobs_completed"`.
- A new of-core migration that rewrites queued `usage_outbox.meter` from the old key to the new one. Per the CLAUDE.md pattern, it must be safe under every RLS shape: either the per-org loop, or reliance on the policy's org-less branch with a test.
- Crate doc comments.
- Tests updated.

**Files:** `crates/**` only, except of-server's config and router.

### F2. Legacy host with deprecation notice (otto-factory, batch 1)

**Scope.** D3 in full.

**Files:**
- `crates/of-server/src/{config.rs,lib.rs}`
- `crates/of-mcp/src/{lib.rs,server.rs,auth.rs}`
- `web/worker/index.ts` and its vitest
- the new variables in `.env.example`

**Acceptance criteria.** Tests cover:
- legacy MCP responses carry the headers and canonical ones carry none;
- `Sunset` appears only when configured;
- `initialize` instructions carry the notice only over the legacy host;
- legacy PRM and challenge advertise the legacy URI;
- a legacy-host token for the canonical audience still validates, and the audience is never taken from the Host;
- Worker: sets or overwrites `X-Forwarded-Host`, 308s SPA paths and `/auth/login` on a legacy host, and proxies webhooks without redirecting;
- config errors on a bad value.

### F3. Console, docs, skills and cutover runbook say otto-tower (otto-factory, batch 0)

**Scope:**
- `web/` messages in all six locales, Svelte strings, and the package name `otto-tower-console`.
- `README.md`, `CLAUDE.md` and `docs/clients/matrix.md`.
- `client-skills`, using `claude mcp add --transport http otto-tower https://otto-tower.savvagent.com/mcp` or the existing form.
- The design of record's title and intro.
- `docs/deploy/fly.md` and `cloudflare.md`, rewritten with D4's cutover runbook: preflight, the ordering warning, rollback, set-webhook, tracker webhooks, client re-add and drop-alias.
- `.github/skills/otto-factory-*` renamed to `otto-tower-*`, together with the symlink check and the skill path in `ci.yml`.
- `fly.toml`: comments only.
- `.env.example` prose, but not the `OF_LEGACY_*` lines.
- The D5 allow-list recorded in `CLAUDE.md`.

### R1. Plugin becomes otto-tower (rbh-plugins, batch 0)

**Scope:**
- `git mv plugins/otto-factory plugins/otto-tower`.
- The skills `tower-scanner` and `tower-worker`.
- `plugin.json`: name, description and keywords, version 2.0.0.
- `marketplace.json`.
- `README.md`, including a reinstall note: `otto-factory@rbh-plugins` is replaced by `otto-tower@rbh-plugins`, and the MCP server should be re-added as `otto-tower`.
- `mcp__otto-tower__*` is preferred. During the deprecation window, the skills also accept `mcp__otto-factory__*` when only that prefix is present.
- dev-workflow references in `creating-tickets`, `epic-development` and `workflow-section.md`, with dev-workflow bumped to 2.3.1.
- The scanner writes `tower-scanner:` keys and treats existing `factory-scanner:` keys as the same ticket.
- `claude plugin validate --strict .` passes.

## Out of scope (tickets)

- otto-factory#232 — rename the GitHub App `otto-factory` that users see when installing. This needs a human admin and a code change to the slug.
- otto-factory#233 — decide whether the tracker trigger-label default becomes `otto-tower`. That is a behaviour change, so it is a non-goal here.

## Human hand-offs

- The GitHub repo rename (D6).
- D4 steps 3 through 11 in production: the preflight read, `rename-service`, certificates and DNS, the Worker route, `resource rename --alias-until --name`, registering the console client, the Fly env flip, `set-webhook`, customer notices, and `drop-alias` after the sunset.
- Choosing the sunset date.
- FamilySearch client re-adds.
