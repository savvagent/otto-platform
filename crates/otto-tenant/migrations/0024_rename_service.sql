-- Renaming a resource server's billing service slug (savvagent/otto-platform#86,
-- epic #81: otto-factory becomes otto-tower).
--
-- `set-service` refuses to change the slug once meters are declared under it,
-- because everything keyed by the old name would be stranded (0017). Before
-- any usage is metered or anything is sent to Stripe, though, nothing keyed by
-- it records money: the meters, their prices, the per-service pools and the
-- budgets can all simply move to the new name. `rename_service` does that, and
-- refuses while anything that does record money exists:
--
--   - `usage_events` rows naming an `<old>/` meter,
--   - `org_meter_period_usage` rows for one,
--   - `stripe_meters` or `stripe_prices` rows for one (a Stripe object is
--     named after the key and cannot be renamed under it),
--   - `stripe_meter_outbox` rows whose `event_name` encodes one.
--
-- Unmetered usage does not block: ingest counts every event in its service's
-- pool (`org_service_period_usage`), and that pool is service data, not
-- billing data, so it is re-keyed with the rest.
--
-- Why a SECURITY DEFINER function. The blocker counts and the re-keys have to
-- see every org's rows, and five of these tables are FORCE ROW LEVEL SECURITY.
-- An operator transaction running as a role that is neither superuser nor
-- BYPASSRLS (the managed-Postgres shape, see `otto_tenant::isolation`) sees
-- none of their rows, so a plain transaction would find no blockers and move
-- nothing: a vacuous pass. Running as the owner fixes that where the owner is
-- exempt; where it is not, the per-command policies below admit every row,
-- but only to an unpinned transaction that opted in with
-- `set_config('app.service_rename', 'on', true)`, which only this function
-- does, the same shape as the email (0018) and Stripe meter (0023) delivery
-- policies. A pinned transaction never satisfies them, so tenant code gains
-- nothing. The function refuses to run pinned for the same reason: there the
-- tenant policy would show it one org's rows and it would pass vacuously.
--
-- Everything happens in the caller's transaction, so the checks and the
-- re-keys commit or abort together.

-- Fail fast rather than queue: a migration waiting for a lock on a busy table
-- makes every later query on that table wait behind it. Failing the boot lets
-- the next boot retry. SET LOCAL ends with this migration's transaction (sqlx
-- runs each migration in one).
SET LOCAL lock_timeout = '5s';

CREATE POLICY usage_events_service_rename_select ON usage_events
  FOR SELECT
  USING (current_org() IS NULL AND current_setting('app.service_rename', true) = 'on');

CREATE POLICY org_meter_period_usage_service_rename_select ON org_meter_period_usage
  FOR SELECT
  USING (current_org() IS NULL AND current_setting('app.service_rename', true) = 'on');

CREATE POLICY stripe_meter_outbox_service_rename_select ON stripe_meter_outbox
  FOR SELECT
  USING (current_org() IS NULL AND current_setting('app.service_rename', true) = 'on');

-- The three re-keyed tenant tables need UPDATE as well, which reads the rows
-- it changes through the SELECT policies and writes them through WITH CHECK.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_service_period_usage', 'service_budgets', 'budget_alerts'] LOOP
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT '
      'USING (current_org() IS NULL AND current_setting(''app.service_rename'', true) = ''on'')',
      t || '_service_rename_select', t
    );
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR UPDATE '
      'USING (current_org() IS NULL AND current_setting(''app.service_rename'', true) = ''on'') '
      'WITH CHECK (current_org() IS NULL AND current_setting(''app.service_rename'', true) = ''on'')',
      t || '_service_rename_update', t
    );
  END LOOP;
END $$;

-- Re-keys the service of the resource server `p_resource_uri` to `p_new` and
-- returns the slug it had and how many rows of each kind moved. Renaming to
-- the slug it already has is a no-op that moves nothing.
--
-- Errors, by SQLSTATE, so the caller can say which mistake was made:
--   22023 the new slug is not a slug
--   P0002 the resource server is not registered
--   55000 it has no service yet (assign one with set-service instead), or
--         billing data exists under its meters; the message names each
--         blocker and its count
--   23505 the new slug is taken, by another resource server or by rows a
--         past service of that name left behind
--   0A000 called from an org-pinned transaction
CREATE FUNCTION rename_service(p_resource_uri text, p_new text)
RETURNS TABLE (
  previous_service text,
  meters bigint,
  price_versions bigint,
  service_pools bigint,
  service_budgets bigint,
  budget_alerts bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_old text;
  v_prefix text;
  -- `otto_billing::stripe::meter_event_name` maps a key two ways (see
  -- event_name.rs). These match exactly the names it gives an `<old>/` meter:
  -- plain is `<service, - as _>__<meter with no __>`, and exists only for a
  -- service with no `--` that does not end in `-`; escaped is
  -- `<service, - as _h>___<meter, _ as _u>`. Matching the encoding rather
  -- than the declared meters also catches a row for a key never declared.
  v_plain text;
  v_escaped text;
  n_usage bigint;
  n_meter_usage bigint;
  n_stripe_meters bigint;
  n_stripe_prices bigint;
  n_outbox bigint;
  blockers text[] := ARRAY[]::text[];
  n_meters bigint;
  n_prices bigint;
  n_pools bigint;
  n_budgets bigint;
  n_alerts bigint;
BEGIN
  IF current_org() IS NOT NULL THEN
    RAISE EXCEPTION 'rename_service must run in an unpinned transaction'
      USING ERRCODE = '0A000';
  END IF;
  IF p_new IS NULL OR p_new !~ '^[a-z][a-z0-9-]{0,62}$' THEN
    RAISE EXCEPTION 'service % must be a lower-case slug: a letter, then up to 62 letters, digits or hyphens',
      quote_literal(coalesce(p_new, 'NULL'))
      USING ERRCODE = '22023';
  END IF;

  -- Locking the row serializes this against a concurrent rename or
  -- set-service of the same resource server.
  SELECT rs.service INTO v_old
    FROM resource_servers rs
   WHERE rs.resource_uri = p_resource_uri
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION '% is not a registered resource', quote_literal(p_resource_uri)
      USING ERRCODE = 'P0002';
  END IF;
  IF v_old IS NULL THEN
    RAISE EXCEPTION '% has no service to rename; assign one with set-service',
      quote_literal(p_resource_uri)
      USING ERRCODE = '55000';
  END IF;
  IF v_old = p_new THEN
    RETURN QUERY SELECT v_old, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint;
    RETURN;
  END IF;

  PERFORM set_config('app.service_rename', 'on', true);

  IF EXISTS (SELECT 1 FROM resource_servers rs WHERE rs.service = p_new) THEN
    RAISE EXCEPTION 'service % is already assigned to another resource server',
      quote_literal(p_new)
      USING ERRCODE = '23505';
  END IF;
  -- The pools and budgets carry no foreign key to the slug, so a service
  -- once named `p_new` may have left rows that the re-keyed ones would
  -- collide with (or silently merge into).
  IF EXISTS (SELECT 1 FROM org_service_period_usage u WHERE u.service = p_new)
     OR EXISTS (SELECT 1 FROM service_budgets b WHERE b.service = p_new)
     OR EXISTS (SELECT 1 FROM budget_alerts a WHERE a.service = p_new) THEN
    RAISE EXCEPTION 'service % still has usage pools or budgets from an earlier service of that name',
      quote_literal(p_new)
      USING ERRCODE = '23505';
  END IF;

  -- A slug has no LIKE metacharacters (`_` is not allowed in one), so the
  -- prefix needs no escaping.
  v_prefix := v_old || '/';
  SELECT count(*) INTO n_usage FROM usage_events e WHERE e.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_meter_usage
    FROM org_meter_period_usage u WHERE u.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_stripe_meters FROM stripe_meters s WHERE s.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_stripe_prices FROM stripe_prices s WHERE s.meter LIKE v_prefix || '%';

  IF v_old !~ '--' AND v_old !~ '-$' THEN
    v_plain := '^' || replace(v_old, '-', '_') || '__[a-z]([a-z0-9]|_[a-z0-9])*_?$';
  END IF;
  v_escaped := '^' || replace(v_old, '-', '_h') || '___[a-z]([a-z0-9]|_u)*$';
  SELECT count(*) INTO n_outbox
    FROM stripe_meter_outbox o
   WHERE o.event_name ~ v_escaped
      OR (v_plain IS NOT NULL AND o.event_name ~ v_plain);

  IF n_usage > 0 THEN
    blockers := blockers || format('%s usage_events', n_usage);
  END IF;
  IF n_meter_usage > 0 THEN
    blockers := blockers || format('%s org_meter_period_usage', n_meter_usage);
  END IF;
  IF n_stripe_meters > 0 THEN
    blockers := blockers || format('%s stripe_meters', n_stripe_meters);
  END IF;
  IF n_stripe_prices > 0 THEN
    blockers := blockers || format('%s stripe_prices', n_stripe_prices);
  END IF;
  IF n_outbox > 0 THEN
    blockers := blockers || format('%s stripe_meter_outbox', n_outbox);
  END IF;
  IF cardinality(blockers) > 0 THEN
    RAISE EXCEPTION 'service % has billing data under its meters: %',
      quote_literal(v_old), array_to_string(blockers, ', ')
      USING ERRCODE = '55000',
            HINT = 'a service can be renamed only before any of its usage is metered or synced to Stripe';
  END IF;

  -- One statement, because the foreign keys between these three are not
  -- deferrable: `meters.service` references `resource_servers.service` and
  -- `price_versions.meter` references `meters.key`, and no order of separate
  -- updates leaves every row pointing at something that exists. Within one
  -- statement the (NO ACTION) checks run at its end, when all three have
  -- moved. `stripe_meters` and `stripe_prices` also reference `meters.key`,
  -- and were just shown to have no row for these meters.
  WITH rs AS (
    UPDATE resource_servers r SET service = p_new, updated_at = now()
     WHERE r.resource_uri = p_resource_uri
    RETURNING 1
  ), m AS (
    UPDATE meters k SET key = p_new || '/' || k.meter, service = p_new, updated_at = now()
     WHERE k.service = v_old
    RETURNING 1
  ), p AS (
    UPDATE price_versions v SET meter = p_new || '/' || substr(v.meter, length(v_prefix) + 1)
     WHERE v.meter LIKE v_prefix || '%'
    RETURNING 1
  )
  SELECT (SELECT count(*) FROM m), (SELECT count(*) FROM p)
    INTO n_meters, n_prices
    FROM (SELECT count(*) FROM rs) AS rs_done;

  UPDATE org_service_period_usage u SET service = p_new WHERE u.service = v_old;
  GET DIAGNOSTICS n_pools = ROW_COUNT;
  UPDATE service_budgets b SET service = p_new WHERE b.service = v_old;
  GET DIAGNOSTICS n_budgets = ROW_COUNT;
  UPDATE budget_alerts a SET service = p_new WHERE a.service = v_old;
  GET DIAGNOSTICS n_alerts = ROW_COUNT;

  -- Closed again, so the rest of the caller's transaction is as unprivileged
  -- as it was before the call.
  PERFORM set_config('app.service_rename', '', true);

  RETURN QUERY SELECT v_old, n_meters, n_prices, n_pools, n_budgets, n_alerts;
END
$$;

-- An operator action: the CLI calls it as the connecting role. Tenant code
-- (otto_app) must never be able to move another service's meters, so it gets
-- no EXECUTE, and 0004's blanket grant ran before this function existed.
REVOKE ALL ON FUNCTION rename_service(text, text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION rename_service(text, text) FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not revoke otto_app''s access to rename_service';
END $$;
