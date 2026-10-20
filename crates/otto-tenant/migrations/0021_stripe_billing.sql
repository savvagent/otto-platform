-- Card on file, Stripe sync, subscriptions and webhooks
-- (savvagent/otto-platform#61, epic #55). An org puts a card on file through a
-- Stripe Checkout session in setup mode and gets a Stripe subscription that
-- invoices its metered usage monthly in arrears. The Stripe API calls and every
-- statement against these tables live in `otto_billing::billing`.
--
-- Additive only: new columns on `subscriptions` (0003), six new global
-- tables and one new tenant table (`stripe_held_invoices`).

-- Fail fast rather than queue: a migration waiting for a lock on a busy table
-- makes every later query on that table wait behind it. Failing the boot lets
-- the next boot retry. SET LOCAL ends with this migration's transaction (sqlx
-- runs each migration in one).
SET LOCAL lock_timeout = '5s';

-- ------------------------------------------------------------ subscriptions
--
-- 0003 already holds `stripe_customer_id`, `stripe_subscription_id` and
-- `status`. From here `status` is the Stripe subscription's own status
-- (`active`, `past_due`, `canceled`, ...) and means nothing while
-- `stripe_subscription_id` is NULL; it is not CHECKed, because Stripe adds
-- statuses and a webhook must not fail on one it has not seen before.
--
-- `payment_method_status` is ours, a small closed vocabulary:
--   none      no card has ever been put on file
--   active    a card is on file and is the customer's default
--   failed    Stripe could not collect an invoice with it
--   detached  it was removed from the customer
--
-- The two `*_event_at` columns hold the `created` time of the Stripe event that
-- last set the matching status. Stripe does not deliver events in order, and
-- may redeliver an old one; a handler applies an event only when it is not
-- older than the one already applied, so a late `invoice.payment_failed` cannot
-- overwrite the card the owner put on file after it.
--
-- Adding a NOT NULL column with a constant default is a catalog-only change;
-- the CHECK scans `subscriptions`, one row per org at most.
ALTER TABLE subscriptions
  ADD COLUMN payment_method_status    text        NOT NULL DEFAULT 'none',
  -- `pm_...`: the card `payment_method_status` describes.
  ADD COLUMN stripe_payment_method_id text,
  ADD COLUMN payment_method_event_at  timestamptz,
  ADD COLUMN subscription_event_at    timestamptz,
  -- Set when Stripe reports the subscription deleted (canceled in the
  -- dashboard, or by dunning). A stopped org is never re-subscribed by sync;
  -- only the owner putting a card on file again clears it.
  ADD COLUMN billing_stopped_at       timestamptz,
  -- `sub_sched_...`: the schedule that switches the subscription's prices at
  -- the start of each month a new price-book version takes effect, while one
  -- is needed.
  ADD COLUMN stripe_schedule_id       text,
  -- What sync last made Stripe hold for this org: the price ids of each phase,
  -- by month. Sync calls Stripe for an org only when the price book's answer
  -- differs from this.
  ADD COLUMN stripe_plan              text,
  -- A short per-org lease, so two workers (an owner's setup, a webhook, sync)
  -- never act on one org's Stripe state at once, without a database lock or
  -- connection held across a Stripe call.
  ADD COLUMN lease_until              timestamptz,
  ADD COLUMN lease_token              uuid;

ALTER TABLE subscriptions
  ADD CONSTRAINT subscriptions_payment_method_status
    CHECK (payment_method_status IN ('none', 'active', 'failed', 'detached'));

-- One org per Stripe customer and per Stripe subscription. Under the tenant
-- policy a pinned transaction cannot see another org's row, but a unique index
-- is checked across every row regardless, so two orgs can never share either.
CREATE UNIQUE INDEX subscriptions_stripe_customer_id
  ON subscriptions (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE UNIQUE INDEX subscriptions_stripe_subscription_id
  ON subscriptions (stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;

-- ------------------------------------------------------------ global tables
--
-- None of these is tenant data, and `otto_app` never writes any of them: the
-- server and the operator CLI write through `Db::begin_unpinned`, as the
-- connecting role, as the price book (0020) is written.

-- Which org a Stripe customer belongs to. Webhook events name a customer, not
-- an org (`invoice.payment_failed`, `payment_method.detached`), and the org has
-- to be known before a transaction can be pinned to it, so this is resolved
-- unpinned. Cross-tenant, so `otto_app` gets no access at all, like
-- `usage_event_ids` (0009). Cascades with the org: an event for a deleted
-- org's customer finds no org and is acknowledged with no action.
CREATE TABLE stripe_customers (
  stripe_customer_id text        PRIMARY KEY,
  org_id             uuid        NOT NULL UNIQUE REFERENCES orgs (id) ON DELETE CASCADE,
  created_at         timestamptz NOT NULL DEFAULT now()
);

-- The webhook idempotency ledger: one row per Stripe event id that has been
-- handled. A redelivery of a recorded event is acknowledged and does nothing.
-- A row is written only after the event's effects commit, so an event whose
-- handling failed is retried by Stripe and handled again (every effect is
-- itself idempotent; see `otto_billing::billing`). No org_id: nothing here is
-- tenant data, and `otto_app` gets no access.
CREATE TABLE stripe_events (
  event_id          text        PRIMARY KEY,
  event_type        text        NOT NULL,
  -- The event's own `created`.
  stripe_created_at timestamptz NOT NULL,
  processed_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT stripe_events_id_len CHECK (char_length(event_id) BETWEEN 1 AND 255),
  CONSTRAINT stripe_events_type_len CHECK (char_length(event_type) BETWEEN 1 AND 255)
);

-- What `otto_billing::billing::sweep_events` deletes by: ledger rows older than
-- the retention window, oldest first, a bounded batch at a time.
CREATE INDEX stripe_events_processed_at ON stripe_events (processed_at);

-- The Stripe billing meter (and the Stripe product its prices hang off) for
-- each platform meter, written by `stripe sync`.
CREATE TABLE stripe_meters (
  -- Restricted, not cascaded: meters are never removed (0017).
  meter             text        PRIMARY KEY REFERENCES meters (key),
  stripe_meter_id   text        NOT NULL UNIQUE,
  -- `otto_billing::stripe::meter_event_name(meter)`: what meter events name.
  event_name        text        NOT NULL UNIQUE,
  -- `prod_...`, set with the meter's first price.
  stripe_product_id text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- The Stripe Price for each price-book version, written by `stripe sync`.
-- Stripe prices are immutable and a version is never edited (0020), so this is
-- one row per version for the life of the version. Cascades: a future version
-- replaced before its month (`pricebook set`) takes its row with it, and its
-- Stripe price, which no subscription item can be on yet, is simply unused.
CREATE TABLE stripe_prices (
  price_version_id uuid        PRIMARY KEY REFERENCES price_versions (id) ON DELETE CASCADE,
  meter            text        NOT NULL REFERENCES meters (key),
  stripe_price_id  text        NOT NULL UNIQUE,
  created_at       timestamptz NOT NULL DEFAULT now()
);

-- Who is running `stripe sync` (the server's background loop on any
-- machine, or an operator's CLI), so only one runs at a time. A lease, not a
-- held lock: it expires on its own if its holder dies.
CREATE TABLE stripe_sync_lease (
  name  text        PRIMARY KEY,
  token uuid        NOT NULL,
  until timestamptz NOT NULL
);

-- Which Stripe mode (`live` or `test`) this database's Stripe objects were
-- made in. One row, written at the first boot (or `stripe sync`) with a Stripe
-- key, from the key's prefix; every later boot compares its key's mode with it
-- and refuses to start on a mismatch, because the customer, subscription,
-- meter and price ids recorded here do not exist in the other mode. Resetting
-- it is a deliberate operator act (docs/deploy/fly.md, "Stripe setup").
-- `otto_app` gets no access.
CREATE TABLE stripe_account_mode (
  singleton   boolean     PRIMARY KEY DEFAULT true,
  mode        text        NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT stripe_account_mode_one_row CHECK (singleton),
  CONSTRAINT stripe_account_mode_mode CHECK (mode IN ('live', 'test'))
);

-- ------------------------------------------------------------ held invoices
--
-- Stripe makes a subscription's invoice for month M at 00:00 UTC on the
-- first of M+1, as a draft that it would finalize about an hour later. Usage
-- for M can still reach Stripe after that: the meter outbox sends an hour's
-- usage after the hour ends, and M stays open for late events until 02:00 UTC
-- (`otto_billing::period`). Usage that reaches Stripe after M's invoice is
-- finalized is never invoiced. So the `invoice.created` webhook turns
-- `auto_advance` off for each subscription-cycle invoice of an org's recorded
-- subscription and records it here, and `stripe sync` finalizes it (turning
-- `auto_advance` back on, so Stripe collects it) once M has closed and none of
-- the org's usage before the end of M is still waiting to be sent, or after a
-- maximum hold. See `otto_billing::billing` ("Invoices wait for their usage").
--
-- TENANT-scoped, with the standard policy: the webhook and sync write it in
-- the org's pinned transaction, under the org's billing lease, so a write
-- after a Stripe call is refused once the lease is lost.
CREATE TABLE stripe_held_invoices (
  stripe_invoice_id      text        PRIMARY KEY,
  org_id                 uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  stripe_subscription_id text        NOT NULL,
  -- The first day of the month the invoice bills.
  period_month           date        NOT NULL,
  held_at                timestamptz NOT NULL DEFAULT now(),
  -- When sync first saw no usage of the period waiting to be sent, and has
  -- seen none since. Cleared whenever some is seen again.
  clear_since            timestamptz,
  -- When sync let the invoice go, and how:
  --   finalized       finalized once its usage had been sent
  --   finalized_late  finalized at the maximum hold with usage still waiting
  --                   (logged at error: that usage is not on it)
  --   not_draft       already finalized or voided by someone else; left alone
  released_at            timestamptz,
  outcome                text,

  CONSTRAINT stripe_held_invoices_id_len
    CHECK (char_length(stripe_invoice_id) BETWEEN 1 AND 255),
  CONSTRAINT stripe_held_invoices_sub_len
    CHECK (char_length(stripe_subscription_id) BETWEEN 1 AND 255),
  CONSTRAINT stripe_held_invoices_month CHECK (extract(day FROM period_month) = 1),
  CONSTRAINT stripe_held_invoices_outcome
    CHECK (outcome IN ('finalized', 'finalized_late', 'not_draft')),
  CONSTRAINT stripe_held_invoices_released CHECK ((released_at IS NULL) = (outcome IS NULL))
);

-- What sync looks for: each org's invoices still held.
CREATE INDEX stripe_held_invoices_open_idx
  ON stripe_held_invoices (org_id) WHERE released_at IS NULL;

ALTER TABLE stripe_held_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE stripe_held_invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY stripe_held_invoices_tenant_isolation ON stripe_held_invoices
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

-- `otto_app` may read the meter and price ids (what a price is in Stripe is
-- not a secret, and a tenant transaction shipping meter events needs the event
-- names) but not change them. The customer map, the event ledger, the sync
-- lease and the account mode are cross-tenant and get nothing. The held
-- invoices are tenant rows and keep 0004's default grants, under RLS. Conditional because a managed
-- deployment has no such role (0004).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    -- 0004's default privileges granted the new tables to otto_app.
    EXECUTE 'REVOKE ALL ON stripe_customers, stripe_events, stripe_meters, stripe_prices, '
         || 'stripe_sync_lease, stripe_account_mode FROM otto_app';
    EXECUTE 'GRANT SELECT ON stripe_meters, stripe_prices TO otto_app';
  END IF;
END $$;
