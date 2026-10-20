-- The price book: what each value meter costs, as data the owner sets
-- (savvagent/otto-platform#60, epic #55). Rates are graduated tiers per meter,
-- versioned by the month they take effect.
--
-- Global, not tenant-scoped, like `plans` (0016) and `meters` (0017): a price
-- belongs to a meter, not to an org, so there is no org_id and no row-level
-- security, and neither table is on rls_registry's GLOBAL_TABLES list (that
-- list is for tables with an org_id).

-- One version of one meter's price, in effect from 00:00 UTC on the first day
-- of `effective_month` until the next version of the same meter. The id is
-- what a Stripe Price is recorded against (Stripe prices are immutable), so a
-- version is never edited in place: `pricebook set` replaces a future version
-- by deleting it and writing a new one, under a new id.
CREATE TABLE price_versions (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Restricted, not cascaded: a meter with prices cannot vanish under them.
  meter           text        NOT NULL REFERENCES meters (key),
  -- Always the first of a month.
  effective_month date        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT price_versions_meter_month UNIQUE (meter, effective_month),
  CONSTRAINT price_versions_first_of_month
    CHECK (effective_month = date_trunc('month', effective_month)::date)
);

-- The graduated tiers of one version, in order. Units 1..up_to of the first
-- tier are charged at its unit amount, the units above that up to the second
-- tier's up_to at the second's, and so on; the last tier is unbounded
-- (`up_to IS NULL`). A free allowance is a first tier priced at 0.
--
-- Strictly increasing bounds and an unbounded last tier are checked by
-- `otto_billing::pricebook::Tiers` before writing and again on every read, so
-- a row edited by hand into a shape the rater cannot price is an error, not a
-- wrong invoice. The constraints here are the ones a row can state alone.
CREATE TABLE price_tiers (
  version_id         uuid     NOT NULL REFERENCES price_versions (id) ON DELETE CASCADE,
  -- 0-based order within the version.
  position           smallint NOT NULL,
  up_to              bigint,
  -- Millionths of a US cent per unit: exact sub-cent prices without floats.
  unit_amount_ucents bigint   NOT NULL,

  PRIMARY KEY (version_id, position),
  CONSTRAINT price_tiers_position CHECK (position >= 0),
  CONSTRAINT price_tiers_up_to_positive CHECK (up_to IS NULL OR up_to > 0),
  CONSTRAINT price_tiers_amount_non_negative CHECK (unit_amount_ucents >= 0)
);

-- At most one unbounded tier per version.
CREATE UNIQUE INDEX price_tiers_one_unbounded ON price_tiers (version_id) WHERE up_to IS NULL;

-- Prices decide what every org is charged, so the plans rule (0016) applies:
-- `otto_app` reads them and never writes them. A write from a tenant
-- transaction (a bug, or an injection) cannot reprice a meter for everyone.
-- The operator CLI writes through `Db::begin_unpinned`, as the connecting
-- role. Conditional because a managed deployment has no such role (0004).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    -- 0004's default privileges granted the new tables to otto_app.
    EXECUTE 'REVOKE ALL ON price_versions, price_tiers FROM otto_app';
    EXECUTE 'GRANT SELECT ON price_versions, price_tiers TO otto_app';
  END IF;
END $$;
