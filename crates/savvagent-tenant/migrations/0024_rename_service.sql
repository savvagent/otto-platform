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
-- Precondition: pause the service's usage shipping first. The rename is safe
-- against a batch in flight (below), but such a batch is refused with a
-- retriable error, and a metered event under an old key is then rejected as
-- `unknown_meter` on retry, for good.
--
-- Why a SECURITY DEFINER function. The blocker counts have to see every org's
-- rows, and six of these tables are FORCE ROW LEVEL SECURITY. An operator
-- transaction running as a role that is neither superuser nor BYPASSRLS (the
-- managed-Postgres shape, see `otto_tenant::isolation`) sees none of their
-- rows, so a plain transaction would find no blockers: a vacuous pass. Running
-- as the owner fixes that where the owner is exempt; where it is not, the
-- SELECT policies below admit every row, but only to an unpinned transaction
-- that opted in with `set_config('app.service_rename', 'on', true)`, which by
-- convention only this function does. That is the threat model of the email
-- (0018) and Stripe meter (0023) delivery policies: any unpinned session could
-- set it, and a pinned one (all tenant code) never satisfies them. The
-- function refuses to run pinned for the same reason: there the tenant policy
-- would show it one org's rows and it would pass vacuously.
--
-- Everything happens in the caller's transaction, so the checks and the
-- re-keys commit or abort together.
--
-- Racing ingest. Ingest reads the shipper's service and declared meters before
-- its per-org transactions, without locks, so a batch in flight when a rename
-- commits would otherwise write usage, pools and Stripe outbox rows under the
-- old slug afterwards, stranding them. The database rules that out:
--
--   - Foreign keys, added below, tie every new metered row to a declared meter
--     and every new pool, budget and alert to a registered service. An insert
--     under a key the rename has moved away fails. They are NOT VALID: they
--     bind every row written from now on and skip proving the existing ones,
--     which were all written against declared meters and registered services
--     but which nothing needs to rescan (`usage_events` is the largest table
--     there is). So existing data cannot fail this migration.
--   - The function locks the three service-keyed tables against writes
--     (SHARE ROW EXCLUSIVE) before it counts anything. Ingest writes a pool in
--     the same statement as every usage, per-meter and outbox row, and that
--     statement takes its table locks before it writes any of them. So a batch
--     that has written anything commits before the counts are taken (its rows
--     are then counted as blockers, or moved), and one that has not waits
--     until the rename commits and then fails its foreign key. Ingest answers
--     that with a retriable 503 and the shipper resends the batch, which is
--     then judged against the new slug.
--
-- The lock pauses all usage ingest for as long as the rename runs. 0025's
-- index on `usage_events (meter)` keeps that to index lookups rather than full
-- scans of the largest table, and the function refuses to run while that
-- index is missing or invalid. Its own short lock_timeout keeps it from
-- queueing every ingest behind a transaction it would wait on: with shipping
-- paused nothing should hold these tables, so any wait means the precondition
-- was not met.
--
-- Lock order. The canonical statement of every lock order these functions
-- take part in (ingest, rename-service, rename, register, set-service, the
-- user paths) is the "Lock order" section of `otto_auth::resources`'s module
-- docs; keep this function and that section in step.
--
-- A statement timeout. A function's own `SET statement_timeout` does not bound
-- the statement that calls it (Postgres arms the timer when that statement
-- starts), so the callers do: `otto_auth::resources::rename_service` runs it
-- under `SET LOCAL statement_timeout = '30s'`, and so should anyone calling it
-- by hand.
--
-- A change to `set-service` too. The service foreign keys cascade, so a slug
-- changed with `set-service` (only possible while the service has declared
-- no meters, so it has no budgets) now carries the service's unmetered usage
-- pools with it, where before they stayed behind under the old slug. A pool
-- left under the target slug by an earlier service of that name makes the
-- change fail on the pool's primary key, and `set_service` reports that.

-- Fail fast rather than queue: a migration waiting for a lock on a busy table
-- makes every later query on that table wait behind it. Failing the boot lets
-- the next boot retry. SET LOCAL ends with this migration's transaction (sqlx
-- runs each migration in one).
SET LOCAL lock_timeout = '5s';

-- The meter FKs restrict: billing data must never follow a key anywhere, and
-- the rename refuses while any exists. The service FKs cascade: pools,
-- budgets and alerts are service data and move with the slug, both here and
-- under `set-service` (which is only allowed while no meter is declared, so no
-- budget exists, but unmetered pools may). Cascades run as the table owner and
-- bypass row-level security, so they reach every org's rows.
ALTER TABLE usage_events
  ADD CONSTRAINT usage_events_meter_declared
    FOREIGN KEY (meter) REFERENCES meters (key) NOT VALID;
ALTER TABLE org_meter_period_usage
  ADD CONSTRAINT org_meter_period_usage_meter_declared
    FOREIGN KEY (meter) REFERENCES meters (key) NOT VALID;
ALTER TABLE org_service_period_usage
  ADD CONSTRAINT org_service_period_usage_service_registered
    FOREIGN KEY (service) REFERENCES resource_servers (service) ON UPDATE CASCADE NOT VALID;
ALTER TABLE service_budgets
  ADD CONSTRAINT service_budgets_service_registered
    FOREIGN KEY (service) REFERENCES resource_servers (service) ON UPDATE CASCADE NOT VALID;
ALTER TABLE budget_alerts
  ADD CONSTRAINT budget_alerts_service_registered
    FOREIGN KEY (service) REFERENCES resource_servers (service) ON UPDATE CASCADE NOT VALID;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'usage_events', 'org_meter_period_usage', 'stripe_meter_outbox',
    'org_service_period_usage', 'service_budgets', 'budget_alerts'
  ] LOOP
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT '
      'USING (current_org() IS NULL AND current_setting(''app.service_rename'', true) = ''on'')',
      t || '_service_rename_select', t
    );
  END LOOP;
END $$;

-- Counts the rows that record money under the meters of service `p_service`,
-- by table: what makes `rename_service` refuse. Read-only, and the preflight
-- `resource show` prints. SECURITY DEFINER for the same reason as
-- `rename_service` (below): a plain operator transaction would see none of
-- the row-level-secured rows and count nothing. It opens the
-- `app.service_rename` policies for its own reads and puts the setting back as
-- it found it, so `rename_service`, which calls it with them open, keeps them
-- open.
--
-- Errors: 0A000 called from an org-pinned transaction.
CREATE FUNCTION service_rename_blockers(p_service text)
RETURNS TABLE (
  usage_events bigint,
  org_meter_period_usage bigint,
  stripe_meters bigint,
  stripe_prices bigint,
  stripe_meter_outbox bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prev text := coalesce(current_setting('app.service_rename', true), '');
  v_prefix text;
  -- `otto_billing::stripe::meter_event_name` maps a key two ways (see
  -- event_name.rs). These match exactly the names it gives a `<service>/`
  -- meter: plain is `<service, - as _>__<meter with no __>`, and exists only
  -- for a service with no `--` that does not end in `-`; escaped is
  -- `<service, - as _h>___<meter, _ as _u>`. Matching the encoding rather
  -- than the declared meters also catches a row for a key never declared.
  v_plain text;
  v_escaped text;
  n_usage bigint;
  n_meter_usage bigint;
  n_stripe_meters bigint;
  n_stripe_prices bigint;
  n_outbox bigint;
BEGIN
  IF current_org() IS NOT NULL THEN
    RAISE EXCEPTION 'service_rename_blockers must run in an unpinned transaction'
      USING ERRCODE = '0A000';
  END IF;
  PERFORM set_config('app.service_rename', 'on', true);

  -- A slug has no LIKE metacharacters (`_` is not allowed in one), so the
  -- prefix needs no escaping.
  v_prefix := p_service || '/';
  SELECT count(*) INTO n_usage FROM usage_events e WHERE e.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_meter_usage
    FROM org_meter_period_usage u WHERE u.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_stripe_meters FROM stripe_meters s WHERE s.meter LIKE v_prefix || '%';
  SELECT count(*) INTO n_stripe_prices FROM stripe_prices s WHERE s.meter LIKE v_prefix || '%';

  IF p_service !~ '--' AND p_service !~ '-$' THEN
    v_plain := '^' || replace(p_service, '-', '_') || '__[a-z]([a-z0-9]|_[a-z0-9])*_?$';
  END IF;
  v_escaped := '^' || replace(p_service, '-', '_h') || '___[a-z]([a-z0-9]|_u)*$';
  SELECT count(*) INTO n_outbox
    FROM stripe_meter_outbox o
   WHERE o.event_name ~ v_escaped
      OR (v_plain IS NOT NULL AND o.event_name ~ v_plain);

  PERFORM set_config('app.service_rename', v_prev, true);
  RETURN QUERY SELECT n_usage, n_meter_usage, n_stripe_meters, n_stripe_prices, n_outbox;
END
$$;

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
--   55000 also: the `usage_events_meter` index (0025) is missing or invalid
--   55P03 ingest held its tables longer than lock_timeout (shipping not
--         paused); nothing changed
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
SET lock_timeout = '2s'
AS $$
DECLARE
  v_old text;
  v_prefix text;
  n_usage bigint;
  n_meter_usage bigint;
  n_stripe_meters bigint;
  n_stripe_prices bigint;
  n_outbox bigint;
  blockers text[] := ARRAY[]::text[];
  n_servers bigint;
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

  -- Without the index every lookup below is a full scan of `usage_events`,
  -- run while all ingest waits. A CONCURRENTLY build that was cancelled
  -- leaves it invalid, and 0025's IF NOT EXISTS then never retries it.
  IF NOT EXISTS (
    SELECT 1 FROM pg_index i
     WHERE i.indexrelid = to_regclass('usage_events_meter') AND i.indisvalid
  ) THEN
    RAISE EXCEPTION 'index usage_events_meter is missing or invalid, so a rename would scan usage_events while all usage ingest waits; run REINDEX INDEX CONCURRENTLY usage_events_meter (or re-run migration 0025''s CREATE INDEX after dropping it) first'
      USING ERRCODE = '55000',
            HINT = 'run REINDEX INDEX CONCURRENTLY usage_events_meter';
  END IF;

  -- First, before any other lock, so that an ingest transaction that has
  -- written a pool row finishes before anything below looks (see the header).
  -- Taking it later could deadlock: an ingest holding a pool row could be
  -- waiting on the resource server row locked next.
  LOCK TABLE org_service_period_usage, service_budgets, budget_alerts
    IN SHARE ROW EXCLUSIVE MODE;

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
  -- Rows from before the foreign keys above may name a service no longer
  -- registered, so one once named `p_new` may have left rows that the moved
  -- ones would collide with (or silently merge into).
  IF EXISTS (SELECT 1 FROM org_service_period_usage u WHERE u.service = p_new)
     OR EXISTS (SELECT 1 FROM service_budgets b WHERE b.service = p_new)
     OR EXISTS (SELECT 1 FROM budget_alerts a WHERE a.service = p_new) THEN
    RAISE EXCEPTION 'service % still has usage pools or budgets from an earlier service of that name',
      quote_literal(p_new)
      USING ERRCODE = '23505';
  END IF;

  v_prefix := v_old || '/';
  SELECT b.usage_events, b.org_meter_period_usage, b.stripe_meters, b.stripe_prices,
         b.stripe_meter_outbox
    INTO n_usage, n_meter_usage, n_stripe_meters, n_stripe_prices, n_outbox
    FROM service_rename_blockers(v_old) b;

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

  -- Counted now because the cascade below moves them: the tables are locked,
  -- so the counts are exact.
  SELECT count(*) INTO n_pools FROM org_service_period_usage u WHERE u.service = v_old;
  SELECT count(*) INTO n_budgets FROM service_budgets b WHERE b.service = v_old;
  SELECT count(*) INTO n_alerts FROM budget_alerts a WHERE a.service = v_old;

  -- One statement, because the foreign keys between these three are not
  -- deferrable: `meters.service` references `resource_servers.service` and
  -- `price_versions.meter` references `meters.key`, and no order of separate
  -- updates leaves every row pointing at something that exists. Within one
  -- statement the (NO ACTION) checks run at its end, when all three have
  -- moved. The other tables referencing `meters.key` were just shown to have
  -- no row for these meters; the pools, budgets and alerts follow
  -- `resource_servers.service` by cascade.
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
  SELECT (SELECT count(*) FROM rs), (SELECT count(*) FROM m), (SELECT count(*) FROM p)
    INTO n_servers, n_meters, n_prices;
  -- The row is locked above, so anything else is a bug worth stopping for.
  IF n_servers <> 1 THEN
    RAISE EXCEPTION 'rename_service updated % resource servers, expected 1', n_servers;
  END IF;

  -- Closed again, so the rest of the caller's transaction is as unprivileged
  -- as it was before the call.
  PERFORM set_config('app.service_rename', '', true);

  RETURN QUERY SELECT v_old, n_meters, n_prices, n_pools, n_budgets, n_alerts;
END
$$;

-- An operator action: the CLI calls it as the connecting role. Tenant code
-- (otto_app) must never be able to move another service's meters, so it gets
-- no EXECUTE, and 0004's blanket grant ran before this function existed.
-- `service_rename_blockers` reads every org's billing rows, so likewise.
REVOKE ALL ON FUNCTION rename_service(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION service_rename_blockers(text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION rename_service(text, text) FROM otto_app';
    EXECUTE 'REVOKE ALL ON FUNCTION service_rename_blockers(text) FROM otto_app';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not revoke otto_app''s access to rename_service';
END $$;

-- The revoke above only notices a failure, so prove the outcome: a migration
-- that left tenant code able to move every service's meters, or read every
-- org's billing counts, must not boot.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    IF has_function_privilege('otto_app', 'rename_service(text, text)', 'EXECUTE') THEN
      RAISE EXCEPTION 'otto_app can still EXECUTE rename_service(text, text); revoke it (and from PUBLIC) before migrating';
    END IF;
    IF has_function_privilege('otto_app', 'service_rename_blockers(text)', 'EXECUTE') THEN
      RAISE EXCEPTION 'otto_app can still EXECUTE service_rename_blockers(text); revoke it (and from PUBLIC) before migrating';
    END IF;
  END IF;
END $$;
