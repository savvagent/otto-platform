# `web/` — the Otto platform console

SvelteKit 2 · Svelte 5 (runes) · Tailwind v4 · TypeScript, strict.

The account and organization console: signing in with a passkey (or enterprise SSO),
creating an account, managing passkeys and sessions, reviewing the account's own security
activity, and, per organization, members, invitations, teams, SSO, the usage meter and the
audit log. It talks to
`otto-platform-server`'s API (`crates/otto-web`; the contract is `GET /api/openapi.json`).

What it does **not** hold is any product's own domain: queues, repositories, trackers and
agent connection live in each service's own console (Otto Factory's, for one), which signs
in here with OAuth. The header links to those consoles from a small list in
[`src/lib/services.ts`](src/lib/services.ts); a new service is one entry there.

```bash
npm install
npm run dev      # Vite on :5173, proxying /api /oauth /sso /.well-known to OTTO_API_ORIGIN
npm run check    # compile messages, check completeness, then svelte-check + tsc (incl. worker/)
npm run lint     # prettier --check
npm test         # vitest: the Worker's routing rule, locale resolution, the error map, pages
npm run build    # static bundle in build/
npm run deploy   # build, then deploy the production Worker — docs/deploy/cloudflare.md
```

`npm run dev` needs a server behind it. Set `OTTO_API_ORIGIN` if it is not on
`http://127.0.0.1:8080`, and start that server with `OTTO_PUBLIC_URL=http://localhost:5173`:
the server's CSRF guard compares the browser's `Origin` with the public URL, and its
WebAuthn relying party id is that URL's host, so a mismatch fails every sign-in.

## Why it is a single-page app

Not a performance choice. The session is an `HttpOnly`, `__Host-`-prefixed cookie, which the
browser refuses to store unless it is `Secure`, has `Path=/`, and carries no `Domain`. It is
bound to one origin and cannot be sent anywhere else. A SvelteKit server rendering these
pages would have to hold that credential to fetch on the user's behalf: a second process
with the keys to every console session, for pages behind a login that cannot be cached
anyway. Static files served beside `/api` keep the cookie in exactly one place, the browser,
and make CORS a non-question.

## What holds across the app

**No credential is spent on a `GET`.** Invitation and claim links point at pages here
(`/invite/{org}`, `/claim`) which render a button that `POST`s the token. Mail scanners and
link-preview fetchers follow every URL in every message, and a single-use `GET` is burned
before the human clicks it.

**An org you are not in renders as "no such organization".** The API answers `404` for both
a nonexistent org and one the caller is not in, so the two cannot be told apart.

**Roles decide what is _shown_, never what is _allowed_.** `OrgContext.isAdmin` hides buttons
that would fail; the server refuses them on every request.

## Pages

| Route                                                | What                                                                                                     |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `/login`, `/signup`, `/claim`                        | Passkey sign-in, account creation, re-registration after an admin reset. Sign in with SSO from `/login`. |
| `/invite/[org]`                                      | Redeem an invitation (needs a session).                                                                  |
| `/orgs/new`                                          | Create an organization.                                                                                  |
| `/settings`                                          | Profile and language, passkeys, browser sessions, linking an SSO identity.                               |
| `/settings/activity`                                 | The account's own sign-ins and passkey changes (`GET /api/me/audit`); events outside any org only.       |
| `/o/[org]`                                           | Overview: counts, plan, usage meter, links to services.                                                  |
| `/o/[org]/members`, `teams`, `sso`, `usage`, `audit` | Admin-only: `sso`, `audit`.                                                                              |

Org pages live under `/o/[org]` so no org slug can collide with a page name. `/` forwards to
the last org visited.

## Messages, and what a new string costs

The console ships in English, Spanish, German, French, Italian and Hindi. Messages are
compiled, not looked up at runtime: [Paraglide JS](https://inlang.com/m/gerre34r) turns
`messages/{locale}.json` into tree-shaken functions under `src/lib/paraglide/`.

```
project.inlang/settings.json         the six locales and the base locale
messages/{en,es,de,fr,it,hi}.json    the catalogs
scripts/check-messages.mjs           the completeness gate, wired into `npm run check`
src/lib/locale.ts                    which language this document is in, and how it got there
src/lib/errors.ts                    ApiError.code / WebauthnError.code -> a sentence
src/lib/paraglide/**                 generated; git-ignored, prettier-ignored, never edited
```

**Adding a user-visible string costs six catalog entries, not one.** `npm run check` fails if
any locale is missing a key, has a key the base locale does not, drops a `{placeholder}`, or
gets its plural categories wrong. Paraglide silently falls back to the base locale for a
missing key, so without the check a half-translated release looks fine in development.

Plurals use the variant form, not the ICU one-liner, and the required categories differ per
locale (`es`, `fr`, `it` also need `many`). `--emit-ts-declarations` is what makes a
misspelled key a type error. `src/lib/paraglide/` is generated, so `check` and `build` compile
it first; a bare `npx svelte-check` in a fresh clone reports missing modules until
`npm run paraglide:compile` has run once.

Not translated, on purpose: product names, wire values and commands. The server-rendered
consent and error pages for `/oauth/authorize` are localized by a table in
`crates/otto-web/src/i18n.rs`, which shares no keys with these catalogs.

A change of language **reloads the document**: Paraglide's `m.*()` are plain calls, not
reactive reads, so Svelte has nothing to invalidate. The account's choice (`users.locale`) is
authoritative, `localStorage['otto.locale']` is a first-paint cache, and `null` means "never
chose", not "English".

## Layout

| Path                        | What it is                                                                     |
| --------------------------- | ------------------------------------------------------------------------------ |
| `src/lib/api.ts`            | The only place that talks to `otto-web`. `ApiError` carries the stable `code`. |
| `src/lib/types.ts`          | The wire types, transcribed from the OpenAPI document.                         |
| `src/lib/session.svelte.ts` | Who is signed in. A rune module, not a store.                                  |
| `src/lib/org.svelte.ts`     | The org the current route is about, via context.                               |
| `src/lib/webauthn.ts`       | The browser side of the passkey ceremonies.                                    |
| `src/lib/services.ts`       | The other Otto consoles linked from the header.                                |
| `worker/index.ts`           | The Cloudflare Worker: serves this bundle, proxies the API.                    |
| `wrangler.jsonc`            | That Worker's config. `worker/tsconfig.json` type-checks it separately.        |

## Deploying

Production serves this bundle from `otto-platform-server` on Fly (`OTTO_STATIC_DIR=/srv/console`
in `fly.toml`; the Dockerfile builds it), at `otto.savvagent.com`:
[`docs/deploy/fly.md`](../docs/deploy/fly.md).

`worker/index.ts` and `wrangler.jsonc` are an **optional** Cloudflare Worker alternative
(`npm run deploy`, `--env production`; a bare `wrangler deploy` lands on the separate
`otto-platform-console-dev` Worker). It needs the domain's DNS on Cloudflare and a different
client-IP header; see [`docs/deploy/cloudflare.md`](../docs/deploy/cloudflare.md).
