-- Metered usage and per-service pools (savvagent/otto-platform#59, epic #55:
-- bill each otto-* service by its own value meters).
--
-- A resource server now ships usage events that may name one of its declared
-- meters (`meters`, 0017) and a quantity. Ingest records the meter on the event
-- and rolls it up per org, meter and month, and counts every event from a
-- service in that service's own pool, so one service's usage is never read as
-- another's. The legacy family-wide `org_period_usage` keeps counting exactly
-- as before, for the console usage page and for resource servers pinned to an
-- older client.
--
-- Everything here is written in the per-org ingest transaction, alongside the
-- `claim_usage_event` ledger claim (0009), so a replayed event can never count
-- twice in any of these totals.

-- Additive and nullable: every existing row predates them, and an unmetered
-- event leaves `meter` and `quantity` NULL. Adding a nullable column with no
-- default is a catalog-only change.
ALTER TABLE usage_events
  -- The shipping resource server. NULL for rows from before this migration
  -- and for `record_usage`, which has no resource server.
  ADD COLUMN resource_uri text,
  -- A `meters.key`. No foreign key, as with the ledger: billing history must
  -- not depend on the registry row it was shipped under.
  ADD COLUMN meter        text,
  ADD COLUMN quantity     bigint;

-- The constraints are added NOT VALID (enforced for new rows, no scan) and
-- validated as separate statements. VALIDATE CONSTRAINT scans the table under
-- SHARE UPDATE EXCLUSIVE rather than the ACCESS EXCLUSIVE an ADD CONSTRAINT
-- scan holds, so where the two run in separate transactions ingest is not
-- stalled behind the scan of `usage_events`, the largest table there is.
ALTER TABLE usage_events
  ADD CONSTRAINT usage_events_meter_quantity
    CHECK ((meter IS NULL) = (quantity IS NULL)) NOT VALID;
ALTER TABLE usage_events
  ADD CONSTRAINT usage_events_quantity_range
    CHECK (quantity IS NULL OR quantity BETWEEN 1 AND 1000000000) NOT VALID;
ALTER TABLE usage_events VALIDATE CONSTRAINT usage_events_meter_quantity;
ALTER TABLE usage_events VALIDATE CONSTRAINT usage_events_quantity_range;

-- Each meter's quantity per org and UTC billing month: what budgets and Stripe
-- metering are computed from.
CREATE TABLE org_meter_period_usage (
  org_id       uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  -- A `meters.key`, `<service>/<meter>`.
  meter        text        NOT NULL,
  -- First day of the UTC billing month.
  period_start date        NOT NULL,
  quantity     bigint      NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, meter, period_start)
);

-- Each service's calls per org and UTC billing month, metered or not: the
-- per-service counterpart of `org_period_usage`.
CREATE TABLE org_service_period_usage (
  org_id         uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  -- A `resource_servers.service` slug.
  service        text        NOT NULL,
  period_start   date        NOT NULL,
  billable_count bigint      NOT NULL DEFAULT 0 CHECK (billable_count >= 0),
  total_count    bigint      NOT NULL DEFAULT 0 CHECK (total_count >= 0),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, service, period_start)
);

-- Tenant tables: the standard isolation policy (0004), which is also how
-- `Db::verify_tenant_isolation` and the rls_registry test discover them.
-- 0004's default privileges already granted both tables to otto_app.
ALTER TABLE org_meter_period_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_meter_period_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY org_meter_period_usage_tenant_isolation ON org_meter_period_usage
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

ALTER TABLE org_service_period_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_service_period_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY org_service_period_usage_tenant_isolation ON org_service_period_usage
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());
