-- Cancel an org's Stripe billing when the org is deleted
-- (savvagent/otto-platform#73, epic #55).
--
-- Deleting an org (`otto_core::orgs::delete_org`) used to leave its Stripe
-- subscription running, so Stripe went on invoicing the card on file. Now the
-- deletion queues a row here, in the same transaction, for each org that has a
-- Stripe subscription, and a loop in the server's Stripe shipper
-- (`otto_billing::billing::cancel`) cancels the subscription in Stripe,
-- retrying until it has. A Stripe outage can neither block nor roll back the
-- deletion, and the row outlives everything else about the org.
--
-- POLICY: the subscription is canceled with `invoice_now`, so the usage
-- accrued up to the deletion is invoiced at once, and is not prorated. A row
-- waits until the org has no meter event left to ship (`stripe_meter_outbox`
-- pending rows go out when their hour ends), so the final invoice includes
-- them. The customer is kept, so its invoices stay readable in Stripe, but
-- its card is detached.
--
-- GLOBAL, with no foreign key to `orgs`, following `lifecycle_events` (0011):
-- the row is written from inside the org's pinned deletion transaction as
-- `otto_app` (INSERT only), and read and updated by the shipper, which has no
-- org to pin. `org_id` is a plain column.
--
-- `status` is a closed vocabulary:
--   pending  waiting to be canceled (or being canceled, under a claim lease)
--   done     the subscription is canceled in Stripe, or was already gone
--   failed   Stripe refused for good (a 4xx other than 401, 403, 409, 429):
--            the row is kept with `last_error` for an operator. Never retried.

CREATE TABLE stripe_cancellations (
  id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 uuid        NOT NULL,
  stripe_customer_id     text        NOT NULL,
  stripe_subscription_id text        NOT NULL,
  -- The card on file at deletion, detached once the subscription is canceled.
  stripe_payment_method_id text,
  status                 text        NOT NULL DEFAULT 'pending',
  attempts               integer     NOT NULL DEFAULT 0,
  -- Next time the shipper may pick this row up. Also the claim lease:
  -- claiming pushes it forward, so two machines never cancel one row at once.
  next_attempt_at        timestamptz NOT NULL DEFAULT now(),
  last_error             text,
  created_at             timestamptz NOT NULL DEFAULT now(),
  finished_at            timestamptz,

  CONSTRAINT stripe_cancellations_status CHECK (status IN ('pending', 'done', 'failed')),
  CONSTRAINT stripe_cancellations_finished CHECK ((status = 'pending') = (finished_at IS NULL)),
  -- A subscription is canceled once: a redelivered deletion cannot queue it
  -- twice.
  CONSTRAINT stripe_cancellations_once UNIQUE (stripe_subscription_id)
);

CREATE INDEX stripe_cancellations_due_idx
  ON stripe_cancellations (next_attempt_at) WHERE status = 'pending';

-- The shipper reads and updates every org's rows through the connecting role;
-- tenant-pinned code may only append (the INSERT in `delete_org`). 0004's
-- default privileges granted all four verbs, so take back the three it does
-- not need, as 0011 does for the lifecycle outbox.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE SELECT, UPDATE, DELETE ON stripe_cancellations FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not adjust otto_app privileges on stripe_cancellations';
END $$;

-- A deleted org's held draft invoice is deleted in Stripe by the cancellation
-- (it would otherwise stay a draft forever, with automatic collection off),
-- and recorded released as `deleted`.
ALTER TABLE stripe_held_invoices DROP CONSTRAINT stripe_held_invoices_outcome;
ALTER TABLE stripe_held_invoices ADD CONSTRAINT stripe_held_invoices_outcome
  CHECK (outcome IN ('finalized', 'finalized_late', 'not_draft', 'deleted'));
