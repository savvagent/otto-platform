# Value meters, pay-as-you-go, and spend budgets

**Epic:** savvagent/otto-platform#55
**Status:** IMPLEMENTED (#84)

## Goal

Bill each otto-* service by the value it delivers, not by counting agent tool
calls. An org pays as it goes, metered per service, with no minimum for
production use. Owners set spend budgets per service. Agents' management calls
are covered by the org's plan under fair use and are never charged.

## Success criteria (from the epic)

1. A resource server declares its meters (`<service>/<meter>`, display name,
   unit) and ships usage events carrying `service`, `meter` and `quantity`. The
   platform refuses an event for an undeclared meter, per event in the receipt.
2. Each service's usage counts in its own pool. Usage in one service can never
   stop work in another.
3. An org with a card on file and no paid subscription can use any metered
   service and is invoiced monthly in arrears, through Stripe billing meters,
   for quantity × rate from a price book with graduated tiers. Rates are data,
   not code.
4. Owners and admins can set a monthly budget per service. Alerts fire at
   50/80/100% (console, email, and the `usage` tool). An opt-in hard stop makes
   billable calls fail with `budget_exceeded` while free calls keep working.
   Agents can read budgets but cannot change them.
5. Every otto-* service ships under the new model (coordinated issues:
   savvagent/otto-factory#222, savvagent/otto-flags#140, savvagent/otto-cxp#52,
   savvagent/otto-1033#1).

## Non-goals

- Choosing prices. Rates, free allowances and the subscription price are
  price-book data, set by the owner.
- Grandfathering. There are no paying orgs.
- Sales tax/VAT, invoicing outside Stripe, multi-currency.

## Design decisions made for this run

- **A service is a named resource server.** `resource_servers` gains a
  `service` slug (operator-assigned, unique). A meter key is
  `<service>/<meter>`; a resource server may declare and ship only meters under
  its own `service`. Every per-service pool, budget and status is keyed by this
  slug.
- **Wire compatibility with pinned clients.** Production resource servers pin
  older `otto-resource` revs. Every field they deserialize from `/internal/*`
  stays present, and their requests (no `service`/`meter`/`quantity`) keep
  working: an event with no meter is recorded as unmetered (free). The legacy
  family-wide fields stay in usage-status, marked deprecated, until every
  service has bumped (follow-up ticket).
- **The price book is the source of rates.** Graduated tiers per meter,
  versioned by an effective month, read-only to `otto_app`, written by an
  operator CLI. Exact integer/decimal arithmetic, never floats. Stripe meters
  and prices are synced from it; Stripe computes the invoice.
- **Stripe is optional at boot.** With no Stripe keys, pay-as-you-go is
  unavailable and the server boots normally (production stays up until the
  owner configures Stripe).
- **Budgets are evaluated where usage is counted** (ingest), in the same
  transaction, so an alert fires exactly once per threshold per period.
- **Enforcement stays in resource servers and fails open**, as
  `*_ENFORCE_QUOTAS` does today. The platform reports `blocked` with reason
  `budget_exceeded`; it never refuses ingest of work already done.
- **Budget writes are console-only** (session cookie, owner/admin). Agents hold
  only resource-server tokens, which cannot reach the console API; they read
  budget state through each service's usage-status.
- **Email** goes through a new notifications outbox and SMTP; unset SMTP config
  means email is disabled (logged at boot), never silently dropped.

## Stories

| # | Story | Criteria | Depends on | Batch | Migration |
|---|---|---|---|---|---|
| S1a | Service slugs and meter declarations | 1, 5 | — | 0 | 0017 |
| S2 | Stripe API client library | 3 | — | 0 | — |
| S3 | Email notifications outbox | 4 | — | 0 | 0018 |
| S1b | Metered usage ingest and per-service pools | 1, 2, 5 | S1a | 1 | 0019 |
| S4 | Price book and public catalog reshape | 3 | S1a | 1 | 0020 |
| S5a | Card on file, Stripe sync, subscriptions and webhooks | 3 | S1a, S2, S4 | 2 | 0021 |
| S6 | Marketing and pricing copy for value meters | 3, 5 | S4 | 2 | — |
| S7 | Per-service budgets, alerts and hard stop | 2, 4 | S1b, S3, S4, S5a (shared files) | 3 | 0022 |
| S5b | Metered usage to Stripe meter events | 3 | S5a, S7 (shared ingest) | 4 | 0023 |
| S8 | Console usage, budgets and billing pages | 3, 4 | S5a, S7 | 4 | — |
| ext | Service adoption: otto-factory#222, otto-flags#140, otto-cxp#52 | 5 | platform release | after release | (their repos) |

Migration numbers are reserved per story so parallel stories never collide.

Cross-cutting rules:

- Global tables with no `org_id` (meters, price book, Stripe ledgers) follow the
  `plans` pattern: read-only to `otto_app`, covered by the rls_registry
  read-only test, written through `Db::begin_unpinned`.
- Anything added to ingest runs in the per-org ingest transaction, never
  rejects or fails an otherwise valid event, and keeps working when Stripe or
  SMTP is down.
- Money is integer: unit prices are `bigint` millionths of a cent, and amounts
  round to whole cents per meter line, as Stripe rounds per line item.
- During rollout the legacy usage-status `hard_stop` is always `false`, so an
  old pinned client never blocks one service on another's usage. Free orgs lose
  the legacy 500-operation cap until fair-use rate limits land.
- Stripe subscriptions anchor to the 1st of the month (UTC) with proration off,
  so invoices line up with the platform's periods and budgets.

## Out of scope (filed separately)

- Fair-use rate limits for management calls.
- Verified card before the first billable call, and a default budget for new
  orgs.
- Removing the legacy usage-status fields and `plans.included_ops` once every
  service has bumped its pin.
- otto-1033#1: otto-1033 has no service code yet (its Phase 2); it adopts the
  meters when it does.
