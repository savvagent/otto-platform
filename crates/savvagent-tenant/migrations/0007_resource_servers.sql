-- The resource servers this authorization server mints tokens for.
--
-- Until now the AS served exactly one audience (a single configured
-- `resource_uri`) with otto-factory's scope list hard-coded in otto-auth.
-- Every otto-* service is a resource server of its own — otto-factory's
-- `/mcp`, otto-flags', and whatever comes next — so each registers here with
-- the scopes it understands, and the AS validates every authorize, code,
-- refresh, and PAT request against the row for the requested resource.
--
-- Global, not tenant-scoped, for the same reason as oauth_clients: the AS
-- resolves a resource before any org is known. Not registered in
-- 0004_rls.sql's tenant_tables.

CREATE TABLE resource_servers (
  -- RFC 8707 resource indicator: the exact audience a token is bound to, and
  -- the value a client sends as `resource`. Compared by exact string match.
  resource_uri              text        PRIMARY KEY,
  -- Shown on the consent screen next to the requested scopes.
  name                      text        NOT NULL,
  -- Every scope this resource server understands. Scope strings are only
  -- meaningful within one resource server; two may each define `read`.
  scopes                    text[]      NOT NULL,
  -- Granted when a client asks for no scope at all. Kept read-only by
  -- convention, so anything that can change state has to be asked for and
  -- shown to the user.
  default_scopes            text[]      NOT NULL,
  -- SHA-256 of the credential this resource server presents to the
  -- introspection endpoint (Phase 4). NULL until one is issued, and a
  -- resource server without one cannot introspect.
  introspection_secret_hash bytea,
  -- A disabled resource server gets no new codes, tokens, or refreshes.
  -- Tokens already issued expire on their own schedule.
  disabled                  boolean     NOT NULL DEFAULT false,
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT resource_servers_has_scopes CHECK (cardinality(scopes) > 0),
  CONSTRAINT resource_servers_defaults_known CHECK (default_scopes <@ scopes)
);

CREATE UNIQUE INDEX resource_servers_introspection_secret_key
  ON resource_servers (introspection_secret_hash)
  WHERE introspection_secret_hash IS NOT NULL;
