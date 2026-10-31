-- Idempotent usage ingest (savvagent/otto-platform#3).
--
-- Resource servers now live in their own databases and ship usage to
-- `POST /internal/usage` from an outbox, which retries. A retry after a lost
-- response must not bill twice, so each shipped event carries a UUID the
-- resource server minted when it wrote its outbox row, and the platform
-- remembers the first one it sees of each.
--
-- The ledger is a GLOBAL table, not a column on `usage_events`, because the
-- dedupe key must be checked across tenants: an event id replayed under a
-- *different* org is a bug or an attack, and has to be told apart from a
-- harmless retry. Under `usage_events`' row-level security a pinned
-- transaction cannot see another org's row, so it could not tell.
--
-- That makes the ledger a cross-tenant table that tenant-pinned code (running
-- as `otto_app`) must not read. Its only access path is
-- `claim_usage_event`, a SECURITY DEFINER function, and `otto_app` gets no
-- privilege on the table itself. The claim runs in the caller's transaction,
-- so it commits or aborts together with the `usage_events` row and the
-- `org_period_usage` increment it guards.
--
-- Scoped per resource server because two services pick their own UUIDs and
-- nothing coordinates them. No foreign keys: billing history must outlive both
-- the registry row and the org.

CREATE TABLE usage_event_ids (
  resource_uri text        NOT NULL,
  event_id     uuid        NOT NULL,
  org_id       uuid        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (resource_uri, event_id)
);

-- Returns 'new' (first sighting: the caller counts the event), 'duplicate'
-- (seen before for this org: the caller does nothing), or 'org_mismatch' (seen
-- before for another org: the caller rejects it).
CREATE FUNCTION claim_usage_event(p_resource_uri text, p_event_id uuid, p_org_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  existing uuid;
BEGIN
  INSERT INTO usage_event_ids (resource_uri, event_id, org_id)
  VALUES (p_resource_uri, p_event_id, p_org_id)
  ON CONFLICT DO NOTHING;
  IF FOUND THEN
    RETURN 'new';
  END IF;

  SELECT org_id INTO existing
    FROM usage_event_ids
   WHERE resource_uri = p_resource_uri AND event_id = p_event_id;
  IF existing = p_org_id THEN
    RETURN 'duplicate';
  END IF;
  RETURN 'org_mismatch';
END
$$;

REVOKE ALL ON FUNCTION claim_usage_event(text, uuid, uuid) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    -- 0004's default privileges granted the new table to otto_app.
    EXECUTE 'REVOKE ALL ON usage_event_ids FROM otto_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION claim_usage_event(text, uuid, uuid) TO otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not adjust otto_app privileges on the usage ledger';
END $$;
