-- Service slugs and value-meter declarations (savvagent/otto-platform#56,
-- epic #55: bill each otto-* service by its own value meters).
--
-- A resource server's `service` is the short name its meters, usage pools and
-- budgets are keyed by (`otto-flags`, `otto-cxp`). An operator assigns it
-- (`otto-platform-server resource set-service`); a service never names
-- itself, so one resource server cannot declare or ship meters under
-- another's name. Nullable because every existing row predates it, and a
-- server with no service simply cannot declare meters (409 service_not_set).
ALTER TABLE resource_servers ADD COLUMN service text
  CONSTRAINT resource_servers_service_key UNIQUE
  CONSTRAINT resource_servers_service_slug CHECK (service ~ '^[a-z][a-z0-9-]{0,62}$');

-- Every value meter a service has declared, keyed `<service>/<meter>`.
--
-- Global, not tenant-scoped: a meter belongs to a service, not to an org, so
-- there is no org_id and no row-level security, and the table is not on
-- rls_registry's GLOBAL_TABLES list (that list is for tables with an org_id).
-- A resource server declares its meters with PUT /internal/meters, which
-- upserts them idempotently through an unpinned transaction.
CREATE TABLE meters (
  -- `<service>/<meter>`: what usage events, prices and budgets name.
  key          text        PRIMARY KEY,
  -- Restricting the slug change while meters exist: renaming a service would
  -- strand every meter (and later every pool and budget) keyed by the old one.
  service      text        NOT NULL REFERENCES resource_servers (service),
  meter        text        NOT NULL,
  -- Shown on usage and billing pages and invoices.
  display_name text        NOT NULL,
  -- What one unit of quantity is, e.g. `request`, `GB-hour`.
  unit         text        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT meters_key_parts CHECK (key = service || '/' || meter),
  CONSTRAINT meters_meter_slug CHECK (meter ~ '^[a-z][a-z0-9_]{0,62}$'),
  CONSTRAINT meters_display_name_len
    CHECK (char_length(display_name) BETWEEN 1 AND 80),
  CONSTRAINT meters_unit_len CHECK (char_length(unit) BETWEEN 1 AND 32)
);

CREATE INDEX meters_service ON meters (service);

-- Meters decide what every org is charged for, so the plans rule (0016)
-- applies: `otto_app` reads them and never writes them. A write from a tenant
-- transaction (a bug, or an injection) cannot invent or rename a meter.
-- Declarations are written through `Db::begin_unpinned`, as the connecting
-- role. Conditional because a managed deployment has no such role (0004).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    -- 0004's default privileges granted the new table to otto_app.
    EXECUTE 'REVOKE ALL ON meters FROM otto_app';
    EXECUTE 'GRANT SELECT ON meters TO otto_app';
  END IF;
END $$;
