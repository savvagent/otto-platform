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

It is deployed at `https://otto.savvagent.com`. otto-factory is its first
resource server: it depends on `otto-tenant` and `otto-resource` from this repo,
validates bearer tokens through introspection, and its console signs in here
with OAuth. otto-flags is meant to be the second, needing nothing from the
platform beyond registering itself.

`otto-platform-server` serves the identity HTTP surface — the OAuth 2.1
authorization server, sign-in (passkeys and enterprise SSO), and the
account/org API — for every registered resource server, plus the
resource-server API (introspection, usage ingest, member lookup, lifecycle
webhooks) and the public plan catalog, `GET /api/plans` (no credential;
each plan's name, list price and allowlisted features, plus the metered prices
in effect this month as `meters`; cached in-process for a minute and sent with
`max-age=300`). With `OTTO_STATIC_DIR` set, as on Fly, it also serves the
bundle built from `web/` (see `web/README.md`): the public marketing pages,
prerendered (`/`, `/pricing`, a page per product, each in every language),
and the account/org console, whose home is `/home`.

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
│                         the org API (members, invites, teams, SSO
│                         admin, tokens, usage, audit), and the public
│                         plan catalog (/api/plans). Routes and the
│                         OpenAPI document come from one catalog. Built on
│                         otto-tenant, otto-core, otto-billing, otto-auth.
├── otto-resource/        what a resource server (otto-factory, otto-flags)
│                         links: introspection, usage and lookup clients
│                         with 60 s caches, webhook signature verification.
│                         No database dependency.
└── otto-platform-server/ binary: loads config, connects, runs migrations,
                          verifies tenant isolation, then serves /healthz,
                          /readyz, otto-web's router, the
                          resource-server API (`POST /oauth/introspect`,
                          `/internal/*`), and, with OTTO_STATIC_DIR, the
                          web/ bundle. Delivers lifecycle webhooks and
                          provisions resource servers, first-party
                          OAuth clients and the price book, and syncs
                          the price book to Stripe
                          (`otto-platform-server resource ...`,
                          `client ...`, `pricebook ...`, `stripe sync`).
```

Dependency direction: `otto-tenant` ← `otto-core` ← `otto-billing`,
`otto-auth` ← `otto-web` ← `otto-platform-server`. The server also uses
`otto-resource` for the wire types it shares with resource servers.

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

## Running it locally

Requires a local Postgres. Point `DATABASE_URL` at it and set the two
required settings (see `.env.example`, which documents every variable):

```sh
cp .env.example .env
# edit .env: DATABASE_URL=postgres://postgres:postgres@localhost:5432/otto_platform
#            OTTO_ENCRYPTION_KEY=$(openssl rand -base64 32)

cargo run -p otto-platform-server
```

Configuration is all `OTTO_*` (plus `DATABASE_URL`, `RUST_LOG` and the two
Stripe secrets):

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | Postgres connection string. |
| `OTTO_PUBLIC_URL` | required | Public origin, e.g. `https://otto.savvagent.com`. The OAuth issuer and every link are built from it, and its **host is the WebAuthn relying party id** — changing it invalidates every passkey. |
| `OTTO_ENCRYPTION_KEY` | required | 32 bytes, base64. Encrypts secrets at rest (SSO IdP client secrets). |
| `OTTO_BIND` | `0.0.0.0:8080` | Listen address. |
| `OTTO_STATIC_DIR` | unset | The built `web/` bundle (`/srv/console` in the image). Set, the server serves the marketing pages and the console beside the API; the bundle must contain `200.html` or it refuses to start. |
| `OTTO_CLIENT_IP_HEADER` | unset | Header a trusted proxy *overwrites* with the client address (`fly-client-ip` on Fly). Keys rate limits and audit IPs; leave unset without such a proxy. |
| `OTTO_ENFORCE_QUOTAS` | `0` | Reporting only: whether resource servers enforce hard-stop plans, echoed as `enforced` by the usage endpoint. |
| `OTTO_RUN_MIGRATIONS` | `1` | Apply migrations at startup. |
| `OTTO_LOG_FORMAT` | `text` | `json` for structured logs. |
| `OTTO_SMTP_URL` | unset | Secret. SMTP server for notification email, credentials in the URL: `smtps://user:pass@host:465` or `smtp://user:pass@host:587?tls=required` (plain `smtp://` only to a loopback host). Set together with `OTTO_EMAIL_FROM`; exactly one of the two refuses to start. With neither, email is disabled (logged at boot) and messages stay queued in `notification_outbox`. |
| `OTTO_EMAIL_FROM` | unset | Secret. The `From:` mailbox for notification email, e.g. `otto <alerts@savvagent.com>`. Set together with `OTTO_SMTP_URL`. |
| `STRIPE_SECRET_KEY` | unset | Secret. Billing's Stripe API key (`sk_...`, or a restricted `rk_...`). Set together with `STRIPE_WEBHOOK_SECRET`; exactly one of the two refuses to start. With neither, billing is disabled (logged at boot): `GET /api/orgs/{org}/billing` reports `billingEnabled: false`, and `POST /api/orgs/{org}/billing/setup` and `POST /api/stripe/webhook` answer `503 billing_disabled`. |
| `STRIPE_WEBHOOK_SECRET` | unset | Secret. The Stripe webhook endpoint's signing secret (`whsec_...`). Set together with `STRIPE_SECRET_KEY`. |

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

Each scope can carry a human-readable description, which the consent screen
shows in place of the bare scope name (the name stays alongside it; a scope
with no description is shown as its name). A service sets them with
`otto_auth::resources::set_scope_descriptions`, and an operator with the CLI:

```sh
otto-platform-server resource register https://otto-factory.example/mcp \
  --name otto-factory --scopes jobs:read,jobs:write \
  --scope-description 'jobs:read=View your jobs and their results' \
  --scope-description 'jobs:write=Create, change, and cancel jobs'

# Replace the set later, or remove it with --clear.
otto-platform-server resource describe https://otto-factory.example/mcp \
  --scope-description 'jobs:read=View your jobs and their results'
```

Descriptions are plain text (at most 200 characters), single-language, and
must name scopes the resource server defines. `describe` replaces the whole
set; re-registering keeps descriptions of scopes it still lists.

On the consent screen each requested scope (or each default scope, when the
client asked for none) is a checkbox, checked by default. The person can
uncheck any of them, or press **Read only** to keep only the scopes whose
names end in `:read`. The code, the access token and every refresh carry only
what was left checked, and a form naming a scope the client did not request is
refused. Unchecking everything refuses the request with `access_denied`.
"Read only" relies on that naming convention, so name a resource server's
read scopes `<thing>:read`: any other name is treated as one that can change
something.

### Service slugs and value meters

A resource server bills by value meters it declares itself, each keyed
`<service>/<meter>` (for example `otto-flags/evaluations`). The `<service>`
part is the resource server's **service slug**, which only an operator
assigns, so one service can never declare or ship meters under another's
name:

```sh
otto-platform-server resource set-service https://otto-flags.example/mcp otto-flags

# Or at registration time:
otto-platform-server resource register https://otto-flags.example/mcp \
  --name otto-flags --scopes flags:read,flags:write --service otto-flags
```

A slug matches `^[a-z][a-z0-9-]{0,62}$` and is unique. Re-registering without
`--service` keeps it, and it cannot be changed once the service has declared
meters under it. `resource list` and `resource describe` show it
(`service=-` when none is set).

At startup the service declares its meters with
`otto_resource::PlatformClient::declare_meters` (`PUT /internal/meters`, at
most 50 per request, upserted idempotently), and only then starts its usage
shipper. A meter outside its own namespace, or a malformed one (meter name
`^[a-z][a-z0-9_]{0,62}$`, display name up to 80 characters, unit up to 32), is
refused per meter in the receipt. A resource server with no slug gets
`409 service_not_set`.

**Operator ordering:** run `set-service` in production *before* each service
releases a version that declares meters. Otherwise its declarations are
refused, its metered events are rejected as unknown meters, and the shipper
drops them: that usage is lost, not delayed.

### The price book

Plans buy features, not usage: usage is priced per value meter, the same on
every plan, by the price book. A meter's price is a version of graduated tiers
that takes effect at 00:00 UTC on the first of a month and lasts until the
meter's next version. Unit amounts are millionths of a US cent (`ucents`); a
meter's monthly line is rounded to whole cents once, half up. A meter with no
price in effect charges nothing and is reported as unpriced. Prices are set by
the owner; the repository ships none.

```sh
# Illustrative only: the first 1,000 units each month free, then 0.15 cents each.
otto-platform-server pricebook set example-service/requests --effective 2026-12 \
  --tier 1000:0 --tier inf:150000
otto-platform-server pricebook list
```

Each `--tier` is `<up_to>:<ucents>`, with strictly increasing bounds and the
last one `inf`. The meter must already be declared by its service. Only a
future month can be priced, judged by the database's clock: the current month
and earlier ones are refused, so a period being billed, or already billed,
never changes price, and a meter with no price gets its first one from next
month. Running `set` again for a future month replaces that version with a new
one (a new id). `list` marks each version `in-effect`, `scheduled` or
`superseded`, lists declared meters with no price in effect as `unpriced` (or
`unpriced (scheduled YYYY-MM)`), and shows a stored version that cannot be
priced as `corrupt: <reason>`. Like `resource ...`, it needs only
`DATABASE_URL`, pointed at a database a server has already migrated.
`GET /api/plans` can show the previous month's prices for up to about six
minutes after a month begins, because of its caches.

### Stripe billing

An org's owner puts a card on file through `POST
/api/orgs/{org}/billing/setup`, which returns a Stripe Checkout URL in setup
mode, for cards only. When Stripe reports the card on the webhook (`POST
/api/stripe/webhook`, signature-verified and idempotent by event id), the org
gets a Stripe subscription with one metered item per priced meter, anchored to
00:00 UTC on the first of next month with no proration, so usage is invoiced
monthly in arrears. A canceled subscription stops billing until the owner puts
a card on file again.

`stripe sync` makes Stripe match the price book. With billing enabled the
server runs it itself, at boot, every 15 minutes and just after each month
starts (one machine at a time); the command runs it now and prints what it did:

```sh
otto-platform-server stripe sync
```

It creates a Stripe billing meter for every declared meter and a Stripe Price
for every price-book version (Stripe prices are immutable), subscribes orgs
that have a card on file and no subscription, and puts each subscription on a
Stripe subscription schedule that switches it to a new version's prices at
exactly 00:00 UTC on the first of that version's month. It adopts a Stripe
meter, customer or subscription left by an interrupted earlier attempt rather
than making a second. It is idempotent (`nothing to do` when Stripe already
matches), warns as a subscription nears Stripe's 20 items, and exits non-zero
after listing what it could not do. It needs `DATABASE_URL` and
`STRIPE_SECRET_KEY`. The Stripe account, the restricted key and the webhook
endpoint are set up by hand: see
[`docs/deploy/fly.md`](docs/deploy/fly.md#stripe-setup).

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
