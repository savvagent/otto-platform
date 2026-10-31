# Rebrand allow-list: what still says "otto", and why

The product is Savvagent (#128). Everything a person reads (the console, the
marketing pages in all six locales, the consent page, emails, the passkey
prompt, the OpenAPI document) says Savvagent, and the products are Savvagent
Tower, Savvagent Flags and Savvagent CXP.

Some identifiers keep "otto" on purpose. Each one below is stored data, a wire
contract another system reads, or a name that changes in a later phase. Renaming
any of them would break something or belongs to another story, so the rebrand
leaves them alone.

The check `web/scripts/check-rebrand.mjs` (run by `npm test` in `web/`, as
`check-rebrand.test.mjs`) reads the patterns at the bottom of this file. It
fails on any "otto" in a user-visible surface that no pattern accounts for.

## Kept identifiers

| Identifier | Where | Why it stays | Until |
| --- | --- | --- | --- |
| `_otto-verify` TXT record name and `otto-verify=<token>` value | SSO domain verification (`otto-auth` `dns.rs`, `otto-web` `routes/sso.rs`) | Customers have published these records in their own DNS. A new name would un-verify every domain. | Never, without a migration plan for customer DNS |
| Stripe idempotency keys `otto-{scope}-{hash}`: `otto-meter-`, `otto-customer-`, `otto-default-pm-`, `otto-cancel-`, `otto-cancel-pm-`, `otto-mev-` | `otto-billing`, `otto-platform-server` | Stripe deduplicates retries by key. A renamed key makes a retried request look new and can bill twice. | Never |
| Webhook headers `Otto-Signature`, `Otto-Event-Id`, `Otto-Event-Type` | `otto-resource` `webhook.rs`, `otto-platform-server` `webhooks.rs` | Every service verifies and routes deliveries by these names. | A coordinated change with every service |
| Meter event names `otto_flags__…`, `otto_factory__…` | Stripe billing meters | Stripe meters are keyed by event name, and existing meters hold billed history. | Never |
| Billing service slugs `otto-tower`, `otto-flags`, `otto-cxp`, `otto-factory`, and meter keys such as `otto-flags/evaluations` | Usage rows, budgets, price book, the console's `connectorName`, which is the billing slug | Stored on every usage, budget and price row and in Stripe. Only display names change: the console maps a slug to "Savvagent Flags" and so on, and budget emails do too. | Never (a #128 non-goal) |
| MCP server names `otto-tower`, `otto-flags`, `otto-cxp` in the console's "Add to Claude Code" command | `web/src/lib/services.ts` `connectorName` | They match each service's own docs and the billing slug. They change with each service's MCP server name. | Rebrand phase 3 (#135) |
| Services' resource URIs `https://otto-{tower,flags,cxp}.savvagent.com/mcp` | `web/src/lib/services.ts` `mcpUrl`, the CLI page's `savctl login --resource` examples, the resource registry | An MCP client signs in for exactly this URL (RFC 8707), and each service still names it in its protected-resource metadata. The console's web links already use the new hosts. | Rebrand phase 3 (#135) |
| The `otto.savvagent.com` legacy host | Fly certificates, services' introspection and token calls | Services keep calling the old issuer host until each one is repointed. | Rebrand phase 3 (#135), which makes it redirect-only |
| The `otto_app` Postgres role and the `otto_platform` database | `otto-tenant`, deploy config | Renaming a live role and database needs downtime and buys nothing. | Never (a #128 non-goal) |
| Every migration file | `crates/*/migrations` | Applied migrations are checksummed. Editing one breaks every existing database. | Never |
| Crate and package names (`otto-core`, `otto-web`, `otto-auth`, `otto-billing`, `otto-tenant`, `otto-resource`, `otto-client`, `otto-platform-server`, `ottoctl`, `otto-flags-cli`, the `otto-platform-console` npm package) and their Rust paths (`otto_core::…`) | Everywhere in code, including the `cargo install … ottoctl otto-flags-cli` line on the CLI page | A mechanical rename across the workspace is its own story. The installed binaries are already `savctl` and `savctl-flags`. | #136 |
| The repository `savvagent/otto-platform` | GitHub links on the landing and CLI pages | The repo is renamed in the last phase, and GitHub redirects old links after that. | #136 |
| The Fly app `otto-platform` and its `otto-platform.fly.dev` host | `fly.toml`, the Worker's origin | Renaming a Fly app means a new app. | Never (a #128 non-goal) |
| Retired token prefixes `otto_at_`, `otto_rt_`, `otto_ac_`, `otto_ss_`, `otto_pat_`, and kept secret prefixes `otto_rs_`, `otto_whsec_`, `otto_client_`, `otto_inv_`, `otto_sst_`, `otto_ssb_` | `otto-auth` `crypto.rs`, `otto-resource` `types.rs` | The rejection list must name the old prefixes to refuse them. Kept secrets were issued to services and customers and stay valid. | Until no secret with the old prefix is in use |
| The `otto.locale` browser storage key | `web/src/lib/locale.ts` | A visitor's saved language would be forgotten. Nobody sees the key. | #136 |
| `CHANGELOG.md`, and dated docs in `docs/specs` and `docs/plans` | Docs | They record what was true at the time. | Never |

Code comments, log lines and test fixtures may still say "otto" until #136.
They are not user-visible, and the check does not read them except where it
reads whole files (see below).

## What the check reads

- `web/messages/*.json`: every key and every message, in all six locales.
- `web/src/**`, except tests (`*.test.*`, `test-fixtures.ts`) and the
  generated `web/src/lib/paraglide/`. Comments are included, so a comment that
  names a crate needs a pattern below.
- `web/static/**` text files, such as `robots.txt` and the SVGs.
- `web/worker/index.ts`.
- String literals outside test modules in the Rust files that render copy:
  `otto-web` `i18n.rs` (the consent page), `routes/sso.rs` and `openapi.rs`;
  `otto-core` `i18n.rs`; `otto-platform-server` `email.rs`; `otto-billing`
  `budgets.rs` (budget alert emails); and `otto-auth` `passkeys.rs`
  (`RP_NAME`).

Words that merely contain the letters, such as Italian "prodotto" and
"sottocomandi", are not hits: a hit is "otto" with no letter before it.

## Patterns the check accepts

One JavaScript regular expression per line, matched case-insensitively. Text
a pattern matches is removed before the check looks for "otto". Lines starting
with `#` are comments.

```allowlist
# Crate and package names and Rust paths, until #136.
\botto[-_](?:core|web|auth|billing|tenant|resource|client|platform[-_]server)\b
\bottoctl otto-flags-cli\b
# The repository and the Fly app.
savvagent/otto-platform\b
\botto-platform\.fly\.dev\b
# Services' resource URIs (the MCP connector address), until phase 3 (#135).
https://otto-(?:tower|flags|cxp)\.savvagent\.com/mcp
# Billing service slugs and meter keys, never renamed. The console's
# connectorName is the billing slug.
\botto-(?:tower|flags|cxp|factory)(?![\w.-])
\botto-\{slug\}
\botto-\$\{service\.slug\}
# SSO domain verification records in customers' DNS.
_otto-verify\b
\botto-verify=
# The saved-language browser storage key, until #136.
'otto\.locale'
```
