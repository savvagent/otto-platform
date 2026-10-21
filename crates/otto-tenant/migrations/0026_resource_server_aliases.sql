-- Moving a resource server to a new canonical URI, with the old one kept as a
-- time-boxed alias (savvagent/otto-platform#88, epic #81: otto-factory becomes
-- otto-tower).
--
-- `resource rename <old> <new>` changes `resource_servers.resource_uri` (the
-- foreign keys that name it follow by ON UPDATE CASCADE) and records `<old>`
-- here, pointing at the server. Until `sunset_at`, and unless dropped, the old
-- URI still authenticates the resource server at introspection; past either,
-- it behaves exactly like a URI that was never registered.
--
-- Rows are tombstones and are never deleted (a trigger below refuses it).
-- `register` and `rename` refuse any URI found here, live, expired or dropped,
-- as well as any canonical URI, so a retired URI can never be handed to a
-- different resource server. `otto_auth::resources` checks that under a
-- transaction-level advisory lock that every writer of either namespace takes.
--
-- Global, not tenant-scoped, like `resource_servers`.

SET LOCAL lock_timeout = '5s';

CREATE TABLE resource_server_aliases (
  -- The retired resource indicator, compared by exact string match like the
  -- canonical one.
  alias_uri    text        PRIMARY KEY,
  -- The server it names. Cascades, so a later rename carries older aliases to
  -- the newest canonical URI instead of leaving a chain.
  resource_uri text        NOT NULL REFERENCES resource_servers (resource_uri)
                             ON UPDATE CASCADE,
  -- When the alias stops working on its own.
  sunset_at    timestamptz NOT NULL,
  -- When an operator ended it early (`resource drop-alias`). Never cleared.
  dropped_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX resource_server_aliases_resource_uri
  ON resource_server_aliases (resource_uri);

CREATE FUNCTION resource_server_aliases_keep() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'resource server aliases are tombstones and are never deleted; drop one with `resource drop-alias`'
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER resource_server_aliases_never_deleted
  BEFORE DELETE ON resource_server_aliases
  FOR EACH STATEMENT EXECUTE FUNCTION resource_server_aliases_keep();

CREATE TRIGGER resource_server_aliases_never_truncated
  BEFORE TRUNCATE ON resource_server_aliases
  FOR EACH STATEMENT EXECUTE FUNCTION resource_server_aliases_keep();

-- Only the operator CLI and authentication, both connecting as themselves,
-- touch aliases; tenant code (otto_app) has no business with them, and 0004's
-- default privileges would let it mint or end one. It gets nothing, as with
-- `usage_event_ids` (0009): `claim_usage_event` reads them as its definer.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE ALL ON resource_server_aliases FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not revoke otto_app''s access to resource_server_aliases';
END $$;

-- Dedupe is keyed by the canonical URI, and a rename must not let one event
-- be claimed under both URIs. The rename rewrites the ledger in its
-- transaction; this function keeps claims from slipping past that rewrite.
--
-- Every claim first takes the usage-ledger advisory lock (key
-- 8031172057417213031, `otto_auth::resources::USAGE_LEDGER_LOCK`) SHARED,
-- held until the claiming transaction ends. `resource rename` takes it
-- EXCLUSIVE before it reads or writes anything else of the server's, so:
--
--   - it waits for every claim in flight to commit or abort, and its ledger
--     rewrite then sees what they wrote;
--   - a claim arriving while the rename runs waits for it, and only then
--     resolves its URI (next statement, fresh snapshot), finding the new
--     alias and so the new canonical URI.
--
-- The URI is resolved through any alias, live or not (an alias only ever
-- names its own server), so a batch authenticated before a rename, still
-- carrying the old URI, files its later events under the new one.
--
-- No deadlock: while it waits for the lock the rename holds only its other
-- advisory lock (the URI namespace), which no claimer takes, and claimers take
-- this lock before any row the rename will touch. `rename_service` (0024) does
-- not take it, so its lock order with ingest is unchanged.
--
-- Same signature, so 0009's grants stand.
CREATE OR REPLACE FUNCTION claim_usage_event(p_resource_uri text, p_event_id uuid, p_org_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_uri text;
  existing uuid;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(8031172057417213031);

  SELECT a.resource_uri INTO v_uri
    FROM resource_server_aliases a
   WHERE a.alias_uri = p_resource_uri;
  IF NOT FOUND THEN
    v_uri := p_resource_uri;
  END IF;

  INSERT INTO usage_event_ids (resource_uri, event_id, org_id)
  VALUES (v_uri, p_event_id, p_org_id)
  ON CONFLICT DO NOTHING;
  IF FOUND THEN
    RETURN 'new';
  END IF;

  SELECT org_id INTO existing
    FROM usage_event_ids
   WHERE resource_uri = v_uri AND event_id = p_event_id;
  IF existing = p_org_id THEN
    RETURN 'duplicate';
  END IF;
  RETURN 'org_mismatch';
END
$$;
