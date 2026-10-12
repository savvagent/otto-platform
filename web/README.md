# `web/` — the Otto platform console and public site

SvelteKit 2 · Svelte 5 (runes) · Tailwind v4 · TypeScript, strict.

One static bundle, two things in it. The **public marketing pages**: what Otto is, a page
per product, and pricing read live from the plan catalog, in every language the console
speaks. And the **account and organization console**: signing in with a passkey (or
enterprise SSO), creating an account, managing passkeys and sessions, reviewing the
account's own security activity, and, per organization, members, invitations, teams, SSO,
the usage meter and the audit log. Both talk to `otto-platform-server`'s API
(`crates/otto-web`; the contract is `GET /api/openapi.json`).

What it does **not** hold is any product's own domain: queues, repositories, trackers and
agent connection live in each service's own console (Otto Factory's, for one), which signs
in here with OAuth. The products are a small list in
[`src/lib/services.ts`](src/lib/services.ts), which the console header links from and the
marketing pages describe; see "Adding a product" below.

```bash
npm install
npm run dev      # Vite on :5173, proxying /api /oauth /sso /.well-known to OTTO_API_ORIGIN
npm run check    # compile messages, check completeness, then svelte-check + tsc (incl. worker/)
npm run lint     # prettier --check
npm test         # vitest: the Worker's routing rule, locale resolution, the error map, pages
npm run build    # static bundle in build/, then check:build on it
npm run check:build  # the build check alone: every marketing page exists, in its language, indexable
npm run deploy   # build, then deploy the production Worker — docs/deploy/cloudflare.md
```

`npm run dev` needs a server behind it. Set `OTTO_API_ORIGIN` if it is not on
`http://127.0.0.1:8080`, and start that server with `OTTO_PUBLIC_URL=http://localhost:5173`:
the server's CSRF guard compares the browser's `Origin` with the public URL, and its
WebAuthn relying party id is that URL's host, so a mismatch fails every sign-in.

## Two halves: a prerendered site and a single-page console

Neither half has a server at runtime; they differ in when their HTML is made.

**The console is a single-page app** (`src/routes/(console)`, `ssr = false`), and not for
performance. The session is an `HttpOnly`, `__Host-`-prefixed cookie, which the browser
refuses to store unless it is `Secure`, has `Path=/`, and carries no `Domain`. It is bound to
one origin and cannot be sent anywhere else. A SvelteKit server rendering these pages would
have to hold that credential to fetch on the user's behalf: a second process with the keys
to every console session, for pages behind a login that cannot be cached anyway. Static
files served beside `/api` keep the cookie in exactly one place, the browser, and make CORS
a non-question. Every console URL is answered with the same shell, `200.html`, and the
client router takes it from there.

**The marketing pages are prerendered** (`src/routes/(marketing)`, `prerender = true`) to
`.html` files at build time, one per page per language, because they are the same for
every visitor and should be indexable, which an empty shell is not. They hold no session
and render none: the file is the signed-out page. After mount, in the browser only, the
layout calls `GET /api/me` for one reason, to swap "Create account" for "Open console";
any failure leaves the signed-out link, which still works. `/pricing` also fetches
`GET /api/plans` after mount, so a price is never baked into a file and a change to the
`plans` table needs no rebuild.

**Language lives in different places.** A marketing page's language is its URL: English
unprefixed (`/pricing`), every other locale under its code (`/es/pricing`, matched by
`src/params/lang.ts`, which refuses `/en/…` so English has one URL). Each page declares
itself canonical and lists every language version as an `hreflang` alternate, with
`x-default` on English; the sitemap repeats the set. `src/hooks.server.ts` writes the
locale into `<html lang>` of each file as it is built. The console has one URL per page
whatever the language, and keeps reading it from the account and the browser (see
"Messages" below).

**Every link that crosses between the halves, or changes language, is a full document
load** (`data-sveltekit-reload`). The marketing layout pins Paraglide's locale to the URL
and never puts back the console's getter, and the console resolves its locale once, at
boot. A client-side link from one half to the other would carry the wrong getter across:
the console speaking the URL's language, or a marketing page the account's. A full load
lets each half boot as if its URL had been typed. A language switch reloads for the same
reason the console's does: `m.*()` are plain calls Svelte cannot invalidate. Any new link
across that line needs the attribute too.

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

The public pages, prerendered, `index, follow`:

| Route              | What                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------- |
| `/`                | Landing: what Otto is, the products, the way into the console.                                      |
| `/products/[slug]` | One per product in `services.ts`, with its own title and description.                               |
| `/pricing`         | How plans and usage work, prerendered; the plans themselves fetched live from `GET /api/plans`.     |
| `/{lang}/…`        | Each of the above in `es`, `de`, `fr`, `it` and `hi` (`/es`, `/es/pricing`). English is unprefixed. |
| `/sitemap.xml`     | Every page in every language, with its alternates. Built from `src/lib/sitemap.ts`.                 |
| `/robots.txt`      | `static/robots.txt`: disallows the console, API and OAuth paths, and points at the sitemap.         |

The console, browser-only, `noindex`:

| Route                                                | What                                                                                                     |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `/home`                                              | The console home: forwards to the last org visited, or to `/orgs/new` for an account with none.          |
| `/login`, `/signup`, `/claim`                        | Passkey sign-in, account creation, re-registration after an admin reset. Sign in with SSO from `/login`. |
| `/invite/[org]`                                      | Redeem an invitation (needs a session).                                                                  |
| `/orgs/new`                                          | Create an organization.                                                                                  |
| `/settings`                                          | Profile and language, passkeys, browser sessions, linking an SSO identity.                               |
| `/settings/activity`                                 | The account's own sign-ins and passkey changes (`GET /api/me/audit`); events outside any org only.       |
| `/o/[org]`                                           | Overview: counts, plan, usage meter, links to services.                                                  |
| `/o/[org]/members`, `teams`, `sso`, `usage`, `audit` | Admin-only: `sso`, `audit`.                                                                              |

Org pages live under `/o/[org]` so no org slug can collide with a page name. `/home` is the
console's own home (the logo, the default after signing in); `/` is the public landing page,
and a `next=/` from an old link is read as `/home`.

The console pages are the `src/routes/(console)` group: rendered only in the browser, behind
the session guard, and marked `noindex`. The public pages are the `src/routes/(marketing)`
group, prerendered at build time to `.html` files. Anything without a prerendered file gets
the SPA shell, `200.html`.

### Adding a product

A new product is one entry in [`src/lib/services.ts`](src/lib/services.ts) (slug, name,
console URL, optional MCP endpoint, and its copy as message functions) plus those copy keys in
all six catalogs. From that entry alone it gets a link in the console and marketing headers,
a card on the landing page, a prerendered `/products/{slug}` in every language, and its
sitemap entries. The build check is the one place that does not follow by itself:
`scripts/check-build.mjs` runs in plain Node, without `$lib`, so it keeps its own copy of
the slugs, and `scripts/check-build.test.mjs` fails until the new slug is added there too.
`services.test.ts` pins the shipped list as well.

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

**Marketing copy follows the same rule**: every `marketing_*`, `landing_*`, `pricing_*` and
`product_*` key is in all six catalogs, and `check:build` reads the built pages to confirm
each one's text is in its own language, not just its `<html lang>`. German addresses the
reader as "du", the informal register, on the marketing pages as in the console.

Not translated, on purpose: product names, wire values and commands. The server-rendered
consent and error pages for `/oauth/authorize` are localized by a table in
`crates/otto-web/src/i18n.rs`, which shares no keys with these catalogs.

A change of language **reloads the document**: Paraglide's `m.*()` are plain calls, not
reactive reads, so Svelte has nothing to invalidate. In the console, the account's choice
(`users.locale`) is authoritative, `localStorage['otto.locale']` is a first-paint cache, and
`null` means "never chose", not "English". On a marketing page the URL decides and nothing
is stored; an English page only offers a link to the visitor's apparent language.

## Layout

| Path                            | What it is                                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| `src/lib/api.ts`                | The only place that talks to `otto-web`. `ApiError` carries the stable `code`.                |
| `src/lib/types.ts`              | The wire types, transcribed from the OpenAPI document.                                        |
| `src/lib/session.svelte.ts`     | Who is signed in. A rune module, not a store.                                                 |
| `src/lib/org.svelte.ts`         | The org the current route is about, via context.                                              |
| `src/lib/webauthn.ts`           | The browser side of the passkey ceremonies.                                                   |
| `src/lib/services.ts`           | The product catalog: header links, product pages, sitemap. See "Adding a product".            |
| `src/lib/site.ts`               | The public origin, and `localizedPath`: the one rule for spelling a page's URL in a language. |
| `src/lib/sitemap.ts`            | The marketing page list and `sitemap.xml`.                                                    |
| `src/lib/pricing.ts`            | A plan from `GET /api/plans` put into words, in the page's language, not the console's.       |
| `src/lib/routing.ts`            | The console's routing guard, as a pure decision.                                              |
| `src/lib/next.ts`               | The safe reading of an attacker-supplied `next`, and `CONSOLE_HOME` (`/home`).                |
| `src/params/lang.ts`            | The `[[lang=lang]]` matcher: every locale but English.                                        |
| `src/hooks.server.ts`           | Writes each prerendered page's `<html lang>`. Runs at build time only.                        |
| `src/routes/(console)`          | The console: `ssr = false`, the session guard, `noindex`.                                     |
| `src/routes/(marketing)`        | The public pages: prerendered, the locale pinned to the URL.                                  |
| `src/lib/components/Seo.svelte` | A marketing page's head: canonical, `hreflang` alternates, Open Graph.                        |
| `src/lib/components/marketing/` | The marketing header, footer, product and plan cards, and `ConsoleLink`, the way in.          |
| `scripts/check-build.mjs`       | The build check, chained into `npm run build`.                                                |
| `worker/index.ts`               | The Cloudflare Worker: serves this bundle, proxies the API.                                   |
| `wrangler.jsonc`                | That Worker's config. `worker/tsconfig.json` type-checks it separately.                       |

## Deploying

Production serves this bundle from `otto-platform-server` on Fly (`OTTO_STATIC_DIR=/srv/console`
in `fly.toml`; the Dockerfile builds it), at `otto.savvagent.com`:
[`docs/deploy/fly.md`](../docs/deploy/fly.md).

Whatever serves it must follow the same few rules, and the server and the Worker both do. An
extensionless path is a page: `/pricing` is `pricing.html`, `/es` is `es.html`, `/` is
`index.html`, and `/pricing.html`, `/index.html` and a trailing slash each `308` to that one
URL. Anything else extensionless is a console route and gets the shell, `200.html`, with
`X-Robots-Tag: noindex, nofollow`: it is the same empty HTML for every route it stands in
for, and an indexed shell is a search result that renders a login prompt. The shell is
`200.html` rather than adapter-static's usual `index.html` because `index.html` is the
landing page; without `200.html` the server refuses to start, and the Worker answers every
deep link with a JSON `500` (`misconfigured`). A missing asset stays a `404`.

`npm run build` ends with `check:build`, so a bundle that would deploy without a page is a
failed build, not a quiet gap. The prerender crawler writes only what something links to
and is content to write nothing, so a broken `entries`, a matcher that stops matching or a
hook that stops running would otherwise ship. It checks that every page exists in every
language, with the right `<html lang>`, body text in that language, its canonical URL and
`index, follow`; that `200.html`, `sitemap.xml` and `robots.txt` exist; and that the shell
is English and not indexable.

`worker/index.ts` and `wrangler.jsonc` are an **optional** Cloudflare Worker alternative
(`npm run deploy`, `--env production`; a bare `wrangler deploy` lands on the separate
`otto-platform-console-dev` Worker). It needs the domain's DNS on Cloudflare and a different
client-IP header; see [`docs/deploy/cloudflare.md`](../docs/deploy/cloudflare.md).
