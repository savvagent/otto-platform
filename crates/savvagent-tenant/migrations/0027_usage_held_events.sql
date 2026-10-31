-- Who may bill whom, and usage held for review (savvagent/otto-platform#79).
--
-- A resource server's usage is billed through Stripe, so a buggy or
-- compromised one must not be able to bill an org that never dealt with it, or
-- bill one without limit. Usage ingest (`otto_billing::usage`) therefore
--
--   * refuses an event for an org that has not AUTHORIZED the calling
--     resource server: `org_resource_grants` below, and
--   * holds, instead of counting, a metered event that would take an org's
--     total of one meter in one billing month past a sanity threshold
--     (`otto_billing::usage::DEFAULT_HOLD_THRESHOLD`, or the server's
--     `OTTO_USAGE_HOLD_THRESHOLD`): `usage_held_events` below.
--
-- AUTHORIZED means a token of any kind was ever issued in the org for the
-- resource server, active or not. Usage is shipped from an outbox, possibly
-- hours after the work, so the token that did the work has often expired or
-- been revoked by then, and that usage is still owed. Token rows cannot answer
-- "ever" (`otto_auth::tokens::sweep` deletes them a week after they expire),
-- so the fact is recorded here, by a trigger on both token tables, and kept.

CREATE TABLE org_resource_grants (
  org_id        uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  -- The canonical URI of the resource server when the first token was issued
  -- (`canonical_resource_uri`, 0026). No foreign key to `resource_servers`:
  -- a rename moves the server to a new canonical URI and leaves this one an
  -- alias of it, which the lookup follows, and a key would put a lock on the
  -- server's row into every token issuance (`otto_auth::resources`, "Lock
  -- order").
  resource_uri  text        NOT NULL,
  first_granted timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, resource_uri)
);

-- Everything issued so far.
INSERT INTO org_resource_grants (org_id, resource_uri, first_granted)
SELECT org_id, canonical_resource_uri(resource), min(created_at)
FROM (SELECT org_id, resource, created_at FROM access_tokens
      UNION ALL
      SELECT org_id, resource, created_at FROM refresh_tokens) t
GROUP BY org_id, canonical_resource_uri(resource)
ON CONFLICT DO NOTHING;

CREATE FUNCTION record_org_resource_grant() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO org_resource_grants (org_id, resource_uri)
  VALUES (NEW.org_id, canonical_resource_uri(NEW.resource))
  ON CONFLICT DO NOTHING;
  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION record_org_resource_grant() FROM PUBLIC;

CREATE TRIGGER access_tokens_record_grant
  AFTER INSERT ON access_tokens
  FOR EACH ROW EXECUTE FUNCTION record_org_resource_grant();

CREATE TRIGGER refresh_tokens_record_grant
  AFTER INSERT ON refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION record_org_resource_grant();

-- Whether `p_org` has authorized the resource server whose canonical URI is
-- `p_resource_uri`: a grant recorded under it or under any alias of it
-- (aliases are tombstones that only ever name their own server).
-- SECURITY DEFINER, as `claim_usage_event` (0009) is, because `otto_app`,
-- which ingest runs as, may not read this cross-tenant table.
CREATE FUNCTION org_authorized_resource(p_org uuid, p_resource_uri text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1 FROM org_resource_grants g
     WHERE g.org_id = p_org
       AND (g.resource_uri = p_resource_uri
            OR EXISTS (SELECT 1 FROM resource_server_aliases a
                        WHERE a.alias_uri = g.resource_uri
                          AND a.resource_uri = p_resource_uri)))
$$;

REVOKE ALL ON FUNCTION org_authorized_resource(uuid, text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    -- 0004's default privileges granted the new table to otto_app.
    EXECUTE 'REVOKE ALL ON org_resource_grants FROM otto_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION org_authorized_resource(uuid, text) TO otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not adjust otto_app privileges on org_resource_grants';
END $$;

-- ------------------------------------------------------- held usage events
--
-- A held event keeps its dedupe claim (`usage_event_ids`, 0009): the shipper
-- is told it was refused and drops it, and a resend is a duplicate, so it is
-- held once. Nothing about it is counted, billed or queued for Stripe. This
-- table keeps everything needed to count it later, and
-- `otto-platform-server usage held` lists it.
--
-- TENANT-scoped with the standard `<table>_tenant_isolation` policy, so the
-- pinned ingest transaction writes and sees its own org's rows only. The
-- operator command has no org to pin: a SELECT policy admits it when no org
-- is pinned AND the transaction opted in with
-- `set_config('app.usage_held_review', 'on', true)`, which only
-- `otto_billing::usage::list_held` does. Nothing outside ingest writes here.

CREATE TABLE usage_held_events (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  -- The canonical URI of the shipping resource server, as for `usage_events`.
  resource_uri text        NOT NULL,
  event_id     uuid        NOT NULL,
  user_id      uuid,
  tool         text        NOT NULL,
  billable     boolean     NOT NULL,
  occurred_at  timestamptz NOT NULL,
  service      text,
  meter        text        NOT NULL,
  quantity     bigint      NOT NULL,
  -- First day of the UTC billing month the event would have counted in.
  period_start date        NOT NULL,
  -- The total the event would have reached and the threshold it passed.
  reason       text        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT usage_held_events_once UNIQUE (resource_uri, event_id),
  CONSTRAINT usage_held_events_quantity_range CHECK (quantity BETWEEN 1 AND 1000000000)
);

CREATE INDEX usage_held_events_org_idx ON usage_held_events (org_id, created_at);

ALTER TABLE usage_held_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_held_events FORCE ROW LEVEL SECURITY;

CREATE POLICY usage_held_events_tenant_isolation ON usage_held_events
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

CREATE POLICY usage_held_events_review_select ON usage_held_events
  FOR SELECT
  USING (current_org() IS NULL AND current_setting('app.usage_held_review', true) = 'on');
