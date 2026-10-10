-- Capabilities a plan unlocks, across every otto-* service.
--
-- 0003 left this out until the first capability it gates shipped (design doc
-- §4: one plan for the whole family; higher tiers unlock functionality, not a
-- separate plan per product). That capability is otto-flags' auto-rollback
-- (savvagent/otto-platform#30, savvagent/otto-flags#11).
--
-- A JSON object, keyed by capability. The keys belong to the services that
-- read them; the platform stores and serves them without interpreting them, so
-- a new service adds a key with an UPDATE rather than a schema change. A
-- capability is on only where its value is JSON `true`
-- (`otto_resource::UsageStatus::feature_enabled`); a missing key is off.
--
-- Served to resource servers in GET /internal/orgs/{org}/usage-status.
ALTER TABLE plans ADD COLUMN features jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(features) = 'object');

UPDATE plans SET features = '{"auto_rollback": true}'::jsonb
 WHERE plan IN ('team', 'business', 'enterprise');
