-- Metered usage to Stripe meter events (savvagent/otto-platform#64, epic #55).
--
-- Usage ingest (`otto_billing::usage`) adds every accepted metered event of an
-- org with a live Stripe subscription to an outbox row here, in the same
-- statement that counts the event, so the row commits or aborts with the
-- usage it bills. The server's shipper loop (`stripe_shipper`, only when
-- billing is enabled) sends each row to Stripe as one meter event and records
-- the outcome; the SQL it needs is `otto_billing::stripe_outbox`.
--
-- AGGREGATED. A row is not one usage event but the sum of many: ingest adds
-- an event's quantity to the org's OPEN row for (event_name,
-- stripe_customer_id, bucket_start), creating it if there is none
-- (`INSERT ... ON CONFLICT ... DO UPDATE SET value = value + EXCLUDED.value`
-- against `stripe_meter_outbox_open_idx`). A row is open while it is pending,
-- has never been claimed (`attempts = 0 AND sending_since IS NULL`) and is
-- not full (`NOT is_full`: `is_full` is the stored generated column
-- `value > 500000000000000`, `stripe_outbox::OPEN_ROW_MAX_VALUE`).
-- The first claim closes it for good: from then on its value, and every other
-- parameter of its meter event, is fixed, so every retry sends exactly what
-- the first attempt sent, and an event counted after the claim opens a new
-- row. Replays never reach here: ingest's ledger claim (`claim_usage_event`)
-- refuses an event already counted before this statement runs.
--
--   identifier          `agg:<uuid>`, minted when the row is created (40
--                       characters; Stripe's limit is 100). Stripe dedupes
--                       meter events on it for at least 24 hours.
--   event_name          `otto_billing::stripe::meter_event_name` of the meter.
--   stripe_customer_id  the org's customer when the usage was ingested. If the
--                       org's customer later changes, the row keeps the one
--                       whose live subscription the usage accrued under.
--   value               the sum of the quantities added, 1 to 10^15
--                       (`stripe_outbox::MAX_OUTBOX_VALUE`; exact as a JSON
--                       number). A row stops taking additions once past half
--                       of that (`is_full`), and one addition is at most the
--                       other half, so a sum can never overflow the check,
--                       and ingest can never fail on it.
--   bucket_start        the start of the UTC hour holding the instant the
--                       usage was billed at (`otto_billing::period`): the
--                       meter event's timestamp. Every event in a row lies in
--                       that hour, so in the same UTC month as the timestamp.
--
-- A row is first due when its hour has ended (`next_attempt_at` starts at
-- `bucket_start + 1 hour`), so a busy org and meter sends one meter event per
-- hour rather than one per event.
--
-- `status` is a closed vocabulary:
--   pending   waiting to be sent (or being sent, under a claim lease)
--   sent      Stripe accepted it
--   rejected  Stripe (or the client, before sending) refused it for good: a
--             4xx other than 429. Never retried.
--   expired   not sent in time: older than Stripe accepts (35 days), or still
--             failing when its retry window closed (12 h after the first
--             attempt Stripe may have received, well inside Stripe's 24 h
--             identifier dedupe window, so no retry can ever be counted
--             twice). Never retried.
-- `sent` means Stripe accepted the event for processing; Stripe validates
-- meter events asynchronously and reports failures as separate events.
--
-- A row is only sent once its `event_name` has a Stripe meter (`stripe_meters`,
-- written by `stripe sync`); until then it waits (and stays open), and
-- expires by age only.
-- Deleting an org deletes its rows, shipped or not.
-- `rejected` and `expired` rows are revenue that did not reach Stripe. They
-- are kept with `last_error` for an operator, never swept, and logged at
-- error level when they happen. `sent` rows are swept in bounded batches
-- through `stripe_meter_outbox_sent_idx`.
--
-- TENANT-scoped, with the standard `<table>_tenant_isolation` policy, so a
-- pinned transaction (ingest) writes and sees its own org's rows only. The
-- shipper has no org to pin and reaches every org's rows the way the email
-- outbox's delivery task does (0018): per-command policies that admit a row
-- only when no org is pinned AND the transaction opted in with
-- `set_config('app.stripe_meter_delivery', 'on', true)`, which only
-- `otto_billing::stripe_outbox`'s delivery functions do. There is no delivery
-- INSERT policy: rows are only ever created by a pinned transaction.

CREATE TABLE stripe_meter_outbox (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  identifier         text        NOT NULL DEFAULT ('agg:' || gen_random_uuid()::text),
  event_name         text        NOT NULL,
  stripe_customer_id text        NOT NULL,
  value              bigint      NOT NULL,
  bucket_start       timestamptz NOT NULL,
  status             text        NOT NULL DEFAULT 'pending',
  attempts           integer     NOT NULL DEFAULT 0,
  -- Next time the shipper may pick this row up: the end of its hour at first
  -- (ingest sets it), then the backoff. Also the claim lease: claiming pushes
  -- it forward, so two machines never send the same row at once.
  next_attempt_at    timestamptz NOT NULL DEFAULT now(),
  -- When the first attempt Stripe may have received started (a timeout, a
  -- 5xx, or an answer that was never recorded). The retry window is measured
  -- from it. Definite refusals before processing (401, 403, 429) leave it
  -- unset, so they are bounded by the row's age (its hour) alone.
  window_started_at  timestamptz,
  -- Set by a claim, cleared when the attempt's result is recorded. A claim
  -- that finds it still set knows the previous attempt's answer was lost, and
  -- starts the window from it.
  sending_since      timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  -- When it became sent, rejected or expired.
  finished_at        timestamptz,
  -- Stripe's error (already scrubbed of the secret key by the client), or why
  -- the row expired. Never a credential.
  last_error         text,
  -- Past `stripe_outbox::OPEN_ROW_MAX_VALUE`: the row takes no more
  -- additions. A stored generated column rather than `value <= ...` in the
  -- open index's predicate, so that adding to an open row changes no column
  -- any index depends on (`value` is in none): the upsert ingest makes for
  -- every metered event can then be a HOT update, which writes no index
  -- entry. With `value` in the predicate every addition wrote a new entry
  -- into each index (measured: a 500-event batch into one row, 317 ms
  -- against 41 ms). `is_full` itself changes only once, when a row fills.
  is_full            boolean     GENERATED ALWAYS AS (value > 500000000000000) STORED,

  CONSTRAINT stripe_meter_outbox_identifier UNIQUE (identifier),
  CONSTRAINT stripe_meter_outbox_identifier_len
    CHECK (char_length(identifier) BETWEEN 1 AND 100),
  CONSTRAINT stripe_meter_outbox_event_name_len
    CHECK (char_length(event_name) BETWEEN 1 AND 100),
  CONSTRAINT stripe_meter_outbox_customer_len
    CHECK (char_length(stripe_customer_id) BETWEEN 1 AND 255),
  -- `otto_billing::stripe_outbox::MAX_OUTBOX_VALUE`: a sum of quantities.
  CONSTRAINT stripe_meter_outbox_value_range CHECK (value BETWEEN 1 AND 1000000000000000),
  -- A whole UTC hour (epoch seconds are UTC, whatever the session's zone).
  CONSTRAINT stripe_meter_outbox_bucket_hour
    CHECK (extract(epoch FROM bucket_start) % 3600 = 0),
  CONSTRAINT stripe_meter_outbox_status
    CHECK (status IN ('pending', 'sent', 'rejected', 'expired')),
  CONSTRAINT stripe_meter_outbox_finished
    CHECK ((status = 'pending') = (finished_at IS NULL))
)
-- Free space in each page for the new row version a HOT update writes next
-- to the old one (an open row is updated once per event of its hour).
WITH (fillfactor = 70);

CREATE INDEX stripe_meter_outbox_due_idx
  ON stripe_meter_outbox (next_attempt_at) WHERE status = 'pending';

-- The one open row per org, meter event name, customer and hour that ingest
-- adds to. Its predicate is repeated verbatim by the ON CONFLICT clauses in
-- `otto_billing::usage` and `otto_billing::stripe_outbox` (a test checks it).
CREATE UNIQUE INDEX stripe_meter_outbox_open_idx
  ON stripe_meter_outbox (org_id, event_name, stripe_customer_id, bucket_start)
  WHERE status = 'pending' AND attempts = 0 AND sending_since IS NULL AND NOT is_full;

-- What holds a Stripe invoice (`otto_billing::stripe_outbox::invoice_shipping`):
-- one org's pending rows of one month, by hour. Small: rows leave it as they
-- are sent.
CREATE INDEX stripe_meter_outbox_pending_period_idx
  ON stripe_meter_outbox (org_id, bucket_start) WHERE status = 'pending';

-- The sweep's: sent rows by age, deleted in bounded batches.
CREATE INDEX stripe_meter_outbox_sent_idx
  ON stripe_meter_outbox (finished_at) WHERE status = 'sent';

-- Deleting an org (ON DELETE CASCADE), and one org's rows.
CREATE INDEX stripe_meter_outbox_org_idx ON stripe_meter_outbox (org_id);

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
