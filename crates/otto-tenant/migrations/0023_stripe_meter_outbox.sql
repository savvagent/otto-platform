-- Metered usage to Stripe meter events (savvagent/otto-platform#64, epic #55).
--
-- Usage ingest (`otto_billing::usage`) writes one row here for every accepted
-- metered event of an org with a live Stripe subscription, in the same
-- statement that counts the event, so the row commits or aborts with the
-- usage it bills. The server's shipper loop (`stripe_shipper`, only when
-- billing is enabled) sends each row to Stripe as one meter event and records
-- the outcome; the SQL it needs is `otto_billing::stripe_outbox`.
--
-- Every parameter of the meter event is fixed at enqueue and never changes,
-- so a retry sends exactly what the first attempt sent:
--
--   identifier          `<service>:<event_id>`. Resource servers mint event
--                       ids, which are unique only per server, so the service
--                       slug is part of it. Stripe dedupes meter events on it
--                       for at least 24 hours. At most 63 + 1 + 36 = 100
--                       characters, Stripe's limit.
--   event_name          `otto_billing::stripe::meter_event_name` of the meter.
--   stripe_customer_id  the org's customer when the event was ingested. If the
--                       org's customer later changes, the row keeps the one
--                       whose live subscription the usage accrued under.
--   value               the event's quantity.
--   occurred_at         when the work happened, as ingest counted it.
--
-- `status` is a closed vocabulary:
--   pending   waiting to be sent (or being sent, under a claim lease)
--   sent      Stripe accepted it
--   rejected  Stripe (or the client, before sending) refused it for good: a
--             4xx other than 429. Never retried.
--   expired   not sent in time: older than Stripe accepts (35 days), or still
--             failing when its retry window closed (12 h after the first
--             attempt, well inside Stripe's 24 h identifier dedupe window, so
--             no retry can ever be counted twice). Never retried.
-- `rejected` and `expired` rows are revenue that did not reach Stripe. They
-- are kept with `last_error` for an operator, never swept, and logged at
-- error level when they happen.
--
-- TENANT-scoped, with the standard `<table>_tenant_isolation` policy, so a
-- pinned transaction (ingest) writes and sees its own org's rows only. The
-- shipper has no org to pin and reaches every org's rows the way the email
-- outbox's delivery task does (0018): per-command policies that admit a row
-- only when no org is pinned AND the transaction opted in with
-- `set_config('app.stripe_meter_delivery', 'on', true)`, which only
-- `otto_billing::stripe_outbox`'s delivery functions do. There is no delivery
-- INSERT policy: rows are only ever created by a pinned ingest transaction.

CREATE TABLE stripe_meter_outbox (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  identifier         text        NOT NULL,
  event_name         text        NOT NULL,
  stripe_customer_id text        NOT NULL,
  value              bigint      NOT NULL,
  occurred_at        timestamptz NOT NULL,
  status             text        NOT NULL DEFAULT 'pending',
  attempts           integer     NOT NULL DEFAULT 0,
  -- Next time the shipper may pick this row up. Also the claim lease: claiming
  -- pushes it forward, so two machines never send the same row at once.
  next_attempt_at    timestamptz NOT NULL DEFAULT now(),
  -- Set by the first claim. The retry window is measured from it.
  first_attempt_at   timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  -- When it became sent, rejected or expired.
  finished_at        timestamptz,
  -- Stripe's error (already scrubbed of the secret key by the client), or why
  -- the row expired. Never a credential.
  last_error         text,

  CONSTRAINT stripe_meter_outbox_identifier UNIQUE (identifier),
  CONSTRAINT stripe_meter_outbox_identifier_len
    CHECK (char_length(identifier) BETWEEN 1 AND 100),
  CONSTRAINT stripe_meter_outbox_event_name_len
    CHECK (char_length(event_name) BETWEEN 1 AND 100),
  CONSTRAINT stripe_meter_outbox_customer_len
    CHECK (char_length(stripe_customer_id) BETWEEN 1 AND 255),
  -- `otto_billing::usage::MAX_METER_QUANTITY`, as 0019's CHECK.
  CONSTRAINT stripe_meter_outbox_value_range CHECK (value BETWEEN 1 AND 1000000000),
  CONSTRAINT stripe_meter_outbox_status
    CHECK (status IN ('pending', 'sent', 'rejected', 'expired')),
  CONSTRAINT stripe_meter_outbox_finished
    CHECK ((status = 'pending') = (finished_at IS NULL))
);

CREATE INDEX stripe_meter_outbox_due_idx
  ON stripe_meter_outbox (next_attempt_at) WHERE status = 'pending';

CREATE INDEX stripe_meter_outbox_org_idx ON stripe_meter_outbox (org_id, created_at);

ALTER TABLE stripe_meter_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE stripe_meter_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY stripe_meter_outbox_tenant_isolation ON stripe_meter_outbox
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

CREATE POLICY stripe_meter_outbox_delivery_select ON stripe_meter_outbox
  FOR SELECT
  USING (current_org() IS NULL AND current_setting('app.stripe_meter_delivery', true) = 'on');

CREATE POLICY stripe_meter_outbox_delivery_update ON stripe_meter_outbox
  FOR UPDATE
  USING (current_org() IS NULL AND current_setting('app.stripe_meter_delivery', true) = 'on')
  WITH CHECK (current_org() IS NULL AND current_setting('app.stripe_meter_delivery', true) = 'on');

CREATE POLICY stripe_meter_outbox_delivery_delete ON stripe_meter_outbox
  FOR DELETE
  USING (current_org() IS NULL AND current_setting('app.stripe_meter_delivery', true) = 'on');
