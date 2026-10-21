-- Moving a resource server to a new canonical URI, with the old one kept as a
-- time-boxed alias (savvagent/otto-platform#88, epic #81: otto-factory becomes
-- otto-tower).
--
-- `resource rename <old> <new>` changes `resource_servers.resource_uri` (the
-- foreign keys that name it follow by ON UPDATE CASCADE) and records `<old>`
-- here, pointing at the server. Until `sunset_at`, and unless dropped, the old
-- URI still authenticates the resource server at introspection; past either,
-- a client or resource server naming it is refused exactly like a URI that
-- was never registered. (A grant already stored under it still belongs to its
-- server, see `otto_auth::resources::audience_matches_sql`, until
-- `resource drop-alias` revokes it.)
--
-- Lock order: the canonical statement is the "Lock order" section of
-- `otto_auth::resources`'s module docs; the functions below follow it.
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

-- The revoke above only notices a failure, so prove the outcome: tenant code
-- able to write aliases could point a retired URI at another server.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app')
     AND has_table_privilege('otto_app', 'resource_server_aliases',
                             'SELECT, INSERT, UPDATE, DELETE, TRUNCATE') THEN
    RAISE EXCEPTION 'otto_app still has privileges on resource_server_aliases; revoke them before migrating';
  END IF;
END $$;

-- Dedupe is keyed by the canonical URI, and a rename must not let one event
-- be claimed under both URIs. The rename rewrites the ledger in its
-- transaction; this function keeps claims from slipping past that rewrite.
--
-- Every claim first takes the usage-ledger advisory lock of the URI it names
-- SHARED: the two-key `(5574658, hashtext(uri))`, first key
-- `otto_auth::resources::USAGE_LEDGER_LOCK_NAMESPACE` (0x00551002), apart from
-- the org ingest lock's `0x00551001` (`otto_billing::usage`), held until the
-- claiming transaction ends. `resource rename` takes it EXCLUSIVE for every
-- URI of the server it moves (the old canonical URI, the new one, and every
-- alias) before it touches the server's row, so:
--
--   - it waits for every claim in flight under any of them to commit or
--     abort, and its ledger rewrite then sees what they wrote;
--   - a claim arriving while the rename runs waits for it, and only then
--     resolves its URI (next statement, fresh snapshot), finding the new
--     alias and so the new canonical URI.
--
-- A claim names one of those URIs or none: ingest passes the canonical URI it
-- read when the batch authenticated, which is the server's URI before or
-- after any rename, and the alias set is fixed while the rename holds the URI
-- namespace lock. Claims for every other server take other keys and never
-- wait for it (two URIs whose hashes collide only wait for each other, which
-- is harmless).
--
-- The URI is resolved through any alias, live or not (an alias only ever
-- names its own server), so a batch authenticated before a rename, still
-- carrying the old URI, files its later events under the new one.
--
-- Same signature, so 0009's grants stand, and a binary from before this
-- migration keeps working against it.
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
  PERFORM pg_advisory_xact_lock_shared(5574658, hashtext(p_resource_uri));

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

-- The canonical URI `p_uri` names: the server it is an alias of (live or
-- not, by the same rule as the claim above), or `p_uri` itself. Ingest writes
-- `usage_events.resource_uri` through it, in the statement after the claim,
-- so an event claimed under the new URI by a batch authenticated before the
-- rename is recorded under the new URI too. Rows written before a rename keep
-- the URI they were written under. SECURITY DEFINER because `otto_app`, which
-- ingest runs as, has no access to the alias table; it reveals only which
-- server a URI names, which authorization already answers publicly.
CREATE FUNCTION canonical_resource_uri(p_uri text)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT coalesce(
    (SELECT a.resource_uri FROM resource_server_aliases a WHERE a.alias_uri = p_uri),
    p_uri)
$$;

REVOKE ALL ON FUNCTION canonical_resource_uri(text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION canonical_resource_uri(text) TO otto_app';
  END IF;
END $$;
