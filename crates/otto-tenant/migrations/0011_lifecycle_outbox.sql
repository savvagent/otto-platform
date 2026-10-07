-- Transactional outbox for lifecycle webhooks (savvagent/otto-platform#3).
--
-- Resource servers hold domain rows keyed by org, team, and user ids but, once
-- split from this database, no foreign key reaches them. They learn that an
-- org was deleted, a team was deleted, or a member was removed from a webhook.
--
-- The event row and its per-resource-server delivery rows are written in the
-- SAME transaction as the mutation that caused them (otto-core's `lifecycle`
-- module, called from `delete_org`, `delete_team`, and `remove_member`). A
-- crash between the delete and the notification therefore cannot lose the
-- notification, and a rolled-back delete cannot send one. A background task in
-- otto-platform-server delivers the rows and retries with backoff.
--
-- Fan-out happens at write time, to the resource servers registered, enabled,
-- and holding a webhook at that moment. A resource server registered later
-- does not receive history, which is right: it has no data about those orgs.
--
-- Both tables are GLOBAL, not tenant-scoped, following `resource_servers`
-- (0007): they are written from inside tenant-pinned transactions as well as
-- unpinned ones, and read by a delivery task that has no org to pin. They are
-- not registered in 0004's tenant_tables (see the privilege revocation at the
-- end for how tenant-pinned code is kept out of them). `org_id` is a plain
-- column rather than a foreign key so an event outlives a hard delete of the org it
-- describes, and so a pinned policy never hides it from the delivery task.

CREATE TABLE lifecycle_events (
  -- Also the idempotency key the resource server dedupes on (the `id` field
  -- of the webhook body): the same event is retried with the same id.
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind       text        NOT NULL,
  org_id     uuid        NOT NULL,
  -- The event-specific fields of the webhook body, e.g. {"org_id": ..., "team_id": ...}.
  data       jsonb       NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT lifecycle_events_known_kind
    CHECK (kind IN ('org.deleted', 'team.deleted', 'member.removed'))
);

CREATE TABLE webhook_deliveries (
  event_id        uuid        NOT NULL REFERENCES lifecycle_events (id) ON DELETE CASCADE,
  resource_uri    text        NOT NULL REFERENCES resource_servers (resource_uri)
                                ON UPDATE CASCADE ON DELETE CASCADE,
  attempts        integer     NOT NULL DEFAULT 0,
  -- Next time a delivery task may pick this row up. Also the lease: claiming a
  -- row pushes this forward, so two replicas never deliver the same row at once.
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  -- Set after the retry budget is spent. A failed row stays for an operator to
  -- read `last_error` and decide.
  failed_at       timestamptz,
  last_status     integer,
  last_error      text,
  PRIMARY KEY (event_id, resource_uri)
);

CREATE INDEX webhook_deliveries_due_idx
  ON webhook_deliveries (next_attempt_at)
  WHERE delivered_at IS NULL AND failed_at IS NULL;

-- These hold every org's events, so tenant-pinned code (running as otto_app)
-- must not read them. The only tenant-pinned access is the INSERT that
-- `otto_core::lifecycle::enqueue` performs inside a mutating transaction; the
-- delivery task reads and updates through the connecting role. 0004's default
-- privileges granted all four verbs, so take back the three it does not need.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE SELECT, UPDATE, DELETE ON lifecycle_events, webhook_deliveries FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not adjust otto_app privileges on the lifecycle outbox';
END $$;
