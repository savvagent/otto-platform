# The console on Cloudflare (optional)

> **This is not how production runs.** `otto.savvagent.com` resolves straight to Fly and
> `otto-platform-server` serves the console itself; see [`fly.md`](fly.md). This document
> describes an optional alternative: a Worker in front, for a deployment whose DNS is on
> Cloudflare. Using it means switching `OTTO_CLIENT_IP_HEADER` to `cf-connecting-ip` and
> unsetting `OTTO_STATIC_DIR`. Nothing in the primary path depends on it.

**One Worker serves the built SPA and proxies everything dynamic to
`otto-platform-server`.** The browser sees one hostname, `otto.savvagent.com`.
`web/wrangler.jsonc` and `web/worker/index.ts` are the whole of it; this file is the
account-side setup neither can express, and the traps a first deploy hits.

Cloudflare is a deployment choice, not an architecture: with `OTTO_STATIC_DIR` set,
`otto-platform-server` serves `web/build` itself and nothing here is required.

## Why a Worker rather than two origins

The console's session is an `HttpOnly`, `__Host-`-prefixed cookie
(`__Host-otto_session`). `__Host-` means the browser refuses to store it unless it is
`Secure`, has `Path=/`, and carries **no `Domain`**, so it is bound to exactly one origin.
Hosting the SPA on one hostname and the API on another does not need a CORS header; it
needs a different authentication transport. So whatever fronts the console must _proxy_ the
API rather than point at it.

The same single hostname is what makes **passkeys** work. The WebAuthn relying party id is
the host of `OTTO_PUBLIC_URL` (`otto.savvagent.com`), and a browser only completes a
ceremony whose rp_id is a suffix of the page's own origin. The page's origin is the Worker's
hostname, which is that host. The origin server's own hostname (`otto-platform.fly.dev`)
never appears in a ceremony, and `GET /api/auth/webauthn` reports `rpId` from the same
setting, so the console and the ceremonies cannot disagree.

## What is proxied

| Path                  | Where it goes                      | Notes                                                                                                                                                              |
| --------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/api/*`              | origin                             | Sessions, accounts, orgs, members, teams, SSO admin, usage, audit, `openapi.json`.                                                                                 |
| `/oauth/*`            | origin                             | Authorization server: `authorize` (consent screen is server-rendered), `token`, `register`, `revoke`.                                                              |
| `/sso/*`              | origin                             | `/sso/callback`, the enterprise IdP's redirect back.                                                                                                               |
| `/.well-known/*`      | origin                             | Authorization-server discovery.                                                                                                                                    |
| `/healthz`, `/readyz` | origin                             | Real routes on the server; at the edge, anything not proxied is answered from the asset bundle, so leaving them out would make `/readyz` return HTML with a `200`. |
| `/oauth/introspect`   | **refused at the edge (JSON 404)** | RFC 7662, called by resource servers.                                                                                                                              |
| `/internal/*`         | **refused at the edge (JSON 404)** | Usage ingest and identity lookups, called by resource servers.                                                                                                     |
| everything else       | the SPA                            | `not_found_handling: single-page-application`.                                                                                                                     |

Matching is on **segment boundaries**, after percent-decoding and collapsing repeated
slashes. `/apiary` is a legal org slug and stays with the console; `/oauth//introspect` and
`/oauth/%69ntrospect` are `/oauth/introspect` and are refused.

**Why `/internal/*` and `/oauth/introspect` are refused rather than proxied** (Worker
deployment only; served directly they are reachable on the public hostname, which is fine
because they are credential-authenticated). They are server-to-server: they authenticate
with a resource server's own credential and are called at `https://otto-platform.fly.dev`,
never by a browser. Proxying them would be harmless in
the sense that the credential check is the same either way, but it is a second public path
to a credential check for no caller, and the Worker's `cf-connecting-ip` header means
nothing to a client that is not a browser. Resource servers should be configured with
`https://otto-platform.fly.dev` as the platform origin for introspection, usage ingest and
lifecycle webhooks. Note that the OAuth _issuer_ they validate against is still
`https://otto.savvagent.com`, because that is `OTTO_PUBLIC_URL`.

The list mirrors `API_PREFIXES` in `crates/otto-platform-server/src/lib.rs` (plus the two
health routes, minus the server-to-server paths). `web/worker/index.test.ts` is the half of
that check that lives here; nothing mechanically ties the two lists together, so a change to
one is a change to both.

## Deploying

```bash
cd web
npm run build                          # adapter-static -> web/build
npx wrangler deploy --env production   # or: npm run deploy, which does both
```

**Naming the environment is load-bearing.** The default configuration is the development
one: a different Worker (`otto-platform-console-dev`) whose `OTTO_ORIGIN` is
`http://127.0.0.1:8080`. A bare `wrangler deploy` therefore cannot overwrite the Worker the
console runs on, and cannot silently point a staging build at production. It deploys
something that proxies to an origin nobody is running, which fails immediately and visibly.
`--env production` is the only path to the real hostname, and it deploys the Worker named
`otto-platform-console`, proxying to `https://otto-platform.fly.dev`, with a custom domain
on `otto.savvagent.com`.

Another environment is a block in `wrangler.jsonc` beside `production`, or a one-off
override: `npx wrangler deploy --var OTTO_ORIGIN:https://other.fly.dev`.

### Account-side setup (once)

1. **The `savvagent.com` zone must be on this Cloudflare account.** A Worker custom domain
   (`"custom_domain": true` in `wrangler.jsonc`) creates the DNS record and certificate
   itself, but only inside a zone Cloudflare serves. If `savvagent.com` DNS is still at
   Namecheap, moving it is a nameserver change that affects every record on the domain
   (including `otto-factory.savvagent.com`). Copy the existing records across first. If
   that is not wanted, see "Without Cloudflare" below.
2. Authenticate wrangler (`npx wrangler login`) as a user who can edit that zone.
3. Deploy with `--env production`. Wrangler attaches `otto.savvagent.com` to the Worker.
4. **No `fly certs add otto.savvagent.com` is needed** in this topology: the browser's TLS
   terminates at Cloudflare, and the Worker reaches Fly at `otto-platform.fly.dev`, which
   already has a certificate. (Add the cert only if you choose the no-Worker path below.)

## What must be true on the origin

For the Worker deployment, `fly.toml` must be changed from its primary-path values (`OTTO_CLIENT_IP_HEADER=fly-client-ip`, `OTTO_STATIC_DIR=/srv/console`). This is why each one is what it is.

| Variable                | Value                        | Why                                                                                                                        |
| ----------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `OTTO_PUBLIC_URL`       | `https://otto.savvagent.com` | The Worker's hostname, never the origin's. The OAuth issuer, discovery documents and the WebAuthn rp_id are built from it. |
| `OTTO_CLIENT_IP_HEADER` | `cf-connecting-ip`           | See below. Previously `fly-client-ip`.                                                                                     |

### The CSRF guard needs nothing, because the Worker leaves `Origin` alone

`crates/otto-web/src/csrf.rs` refuses any non-`GET` that carries the session cookie unless
its `Origin` equals the origin of `OTTO_PUBLIC_URL` (or, with no `Origin`, it carries
`Sec-Fetch-Site: same-origin`). The browser is on the Worker's hostname, so it sends
`Origin: https://otto.savvagent.com`, and the Worker forwards every request header as it
found it. It rewrites exactly one: `cf-connecting-ip`.

### Rate limiting needed a change: `fly-client-ip` -> `cf-connecting-ip`

Per-IP throttles (`signup:{ip}`, `login:ip:{ip}`, claim) and the audit trail's `ip` key on
`OTTO_CLIENT_IP_HEADER`. With `fly-client-ip`, Fly's proxy overwrites the header with the
address it sees, and behind the Worker that is a **Cloudflare egress address**: every
visitor to the console would share a handful of throttle buckets, and one attacker could
lock out everyone. Cloudflare overwrites `CF-Connecting-IP` before the Worker runs, so that
is the value to key on, and the Worker forwards it (deleting it when absent, so a missing
header cannot become one shared bucket).

### Trap: the origin must refuse traffic that did not come through Cloudflare

`cf-connecting-ip` is trustworthy only because Cloudflare writes it. Anyone who reaches
`otto-platform.fly.dev` directly sets the header themselves, and then every per-IP throttle
counts a value the attacker chose, which is worse than no throttle because it looks like it
is working. Verified locally: a direct request carrying `cf-connecting-ip: 9.9.9.9` was
recorded under the bucket `signup:9.9.9.9`.

Resource servers legitimately reach the origin directly (`/oauth/introspect`, `/internal/*`),
and neither route reads the client address, so they are unaffected. But browser-facing
routes (`/api/auth/*`) are also reachable at `otto-platform.fly.dev` until the origin is
locked down. In rough order of strength:

1. **Cloudflare Tunnel** (`cloudflared` alongside the server) for browser traffic, with the
   resource-server paths left on Fly.
2. **Authenticated Origin Pulls**, so the origin accepts browser-path TLS clients only if
   they present Cloudflare's certificate.
3. A shared-secret header added by the Worker and checked by the server before it trusts
   `OTTO_CLIENT_IP_HEADER` (not implemented; the smallest code change).

None of these is wired up. The deploy works without them; the throttles are only as strong
as the origin's reachability until one is.

## Verified locally

`wrangler dev` in front of `cargo run -p otto-platform-server`, the same shape as the real
thing minus Cloudflare's own edge:

```bash
# origin (a scratch database)
DATABASE_URL=postgres://… OTTO_PUBLIC_URL=http://localhost:8788 OTTO_BIND=127.0.0.1:8080 \
OTTO_CLIENT_IP_HEADER=cf-connecting-ip OTTO_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  cargo run -p otto-platform-server

# edge
cd web && npm run build
npx wrangler dev --port 8788 --var OTTO_ORIGIN:http://127.0.0.1:8080
```

What that run established:

- **Routing.** `/`, `/o/acme/members` and `/apiary` render the SPA; `/readyz` answers JSON
  from the origin; `/.well-known/oauth-authorization-server` names the edge as the issuer
  (`http://localhost:8788`); `/api/auth/webauthn` reports `rpId: localhost`, the host the
  browser is on.
- **Server-to-server paths are refused.** `/oauth/introspect`, `/oauth//introspect`,
  `/oauth/%69ntrospect` and `/internal/usage` each answered the edge's JSON `404`.
- **The CSRF guard works through the proxy.** A `POST /api/auth/logout` with the session
  cookie and `Origin: https://evil.test` answered `403 cross_site_request`; with
  `Origin: http://localhost:8788` it reached the handler (`204`); with the cookie and no
  `Origin` it answered `403`.
- **The client address is Cloudflare's value, never the caller's.** Two signups, one
  carrying a forged `cf-connecting-ip: 9.9.9.9`, were both recorded under
  `signup:127.0.0.1`; the forged value was discarded on the way into the Worker.
- **Redirects pass through.** The Worker sets `redirect: 'manual'`, without which Cloudflare
  would follow `/oauth/authorize`'s `303` to the client's loopback callback itself, burn the
  single-use code, and leave the agent waiting forever.

## Caching

The Worker forwards origin paths with `cf: { cacheTtlByStatus: { '200-599': -1 } }`, a
negative TTL, the documented way to say "never", where `cacheTtl: 0` only means "already
expired". Nothing under `/api`, `/oauth`, `/sso` or `/.well-known` is cacheable and some of
it is per-session: a heuristically cached `GET /api/me` is one user's identity served to
another. Static assets need no configuration: `adapter-static` emits content-hashed
filenames under `_app/immutable/`.

## What is still open

- The origin lock (above) is documented, not implemented.
- There is no CI step that deploys the Worker. The Worker's copy of the bundle and the copy
  inside the image are built separately, so they can drift; whoever wires up deployment
  should ship both from one commit.
- The Worker's prefix list and the server's `API_PREFIXES` are two copies of one rule.
