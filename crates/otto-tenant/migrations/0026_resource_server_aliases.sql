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

-- Only the operator CLI, connecting as itself, writes aliases. Tenant code
-- (otto_app) may read them, as it may read `resource_servers`, but 0004's
-- default privileges would also let it mint or end one.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON resource_server_aliases FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not revoke otto_app''s write access to resource_server_aliases';
END $$;

-- Dedupe is keyed by the canonical URI. The rename rewrites the ledger in its
-- transaction, but a usage batch authenticated before the rename committed
-- still carries the old URI for its remaining events; resolving it here, per
-- claim, files them under the canonical URI too. Any alias resolves, live or
-- not: it only ever names its own server. Same signature, so 0009's grants
-- stand.
CREATE OR REPLACE FUNCTION claim_usage_event(p_resource_uri text, p_event_id uuid, p_org_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_uri text := p_resource_uri;
  existing uuid;
BEGIN
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
