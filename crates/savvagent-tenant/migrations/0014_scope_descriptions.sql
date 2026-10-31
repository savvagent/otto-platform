-- Human-readable descriptions for the scopes a resource server defines.
--
-- The consent screen used to list each requested scope by its raw name
-- (`jobs:write`, `org:admin`), which tells a user nothing they can consent
-- to. Descriptions belong to the resource server that defines the scope, so
-- they live on its `resource_servers` row (0007) rather than in a table of
-- their own: they are read together with `scopes` on every authorize, and a
-- scope has no meaning apart from its resource server.
--
-- A JSON object mapping scope name to description. Optional per scope: a
-- scope with no entry is shown by its bare name. Single-language for now;
-- the consent screen's own chrome is localized, descriptions are not.
-- Existing rows get `{}` and keep rendering as before.
--
-- The length and content of each description are checked in otto-auth, where
-- they can be reported to the operator; the database only guarantees shape
-- and that a description never outlives the scope it describes.

ALTER TABLE resource_servers
  ADD COLUMN scope_descriptions jsonb NOT NULL DEFAULT '{}';

ALTER TABLE resource_servers
  ADD CONSTRAINT resource_servers_descriptions_is_object
    CHECK (jsonb_typeof(scope_descriptions) = 'object'),
  -- `jsonb - text[]` deletes the named keys, so what is left is exactly the
  -- descriptions whose key is not one of `scopes`.
  ADD CONSTRAINT resource_servers_descriptions_known
    CHECK ((scope_descriptions - scopes) = '{}'::jsonb);
