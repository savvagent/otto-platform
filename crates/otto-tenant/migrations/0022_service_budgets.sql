-- Per-service monthly budgets and their alerts (savvagent/otto-platform#63,
-- epic #55: owners and admins set a monthly budget per service; alerts fire at
-- 50/80/100%; a hard stop is opt-in).
--
-- A budget caps what one service's value meters may cost an org in one UTC
-- calendar month, in US cents, as `otto_billing::budgets::service_spend` rates
-- them against the price book (0020). It is keyed by the service slug
-- (`resource_servers.service`, 0017), so a budget on one service never affects
-- another. The platform never refuses ingest over a budget: usage already done
-- is always counted. With `hard_stop` set, the service's own usage-status
-- reports `blocked`, and the resource server refuses new billable calls.

CREATE TABLE service_budgets (
  org_id               uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  -- A `resource_servers.service` slug with declared meters. No foreign key,
  -- like the usage pools (0019): a budget is the org's setting, not the
  -- registry's, and checked against `meters` when it is written.
  service              text        NOT NULL,
  -- Bounded above so no arithmetic on it (percentages, thresholds) can
  -- overflow; `otto_billing::budgets::MAX_MONTHLY_BUDGET_CENTS` is the same
  -- number and is checked before writing.
  monthly_budget_cents bigint      NOT NULL
    CONSTRAINT service_budgets_cents_range
      CHECK (monthly_budget_cents > 0 AND monthly_budget_cents <= 1000000000),
  -- Opt-in: refuse new billable calls once spend reaches the budget.
  hard_stop            boolean     NOT NULL DEFAULT false,
  -- Who last set it. NULL once that account is deleted.
  updated_by           uuid        REFERENCES users (id) ON DELETE SET NULL,
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, service)
);

-- One row per threshold a service's spend has reached in a period: the
-- record that its alert fired, which is what makes it fire exactly once.
-- The primary key is the once-only guarantee. Written in the ingest
-- transaction with `ON CONFLICT DO NOTHING`, so of two events crossing the
-- same threshold only one inserts, and only that one enqueues the email. A
-- row whose emails cannot be queued rolls back with them, so the next ingest
-- retries. Kept when a budget is changed or cleared: a threshold fires at
-- most once per service and period.
CREATE TABLE budget_alerts (
  org_id       uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  service      text        NOT NULL,
  -- First day of the UTC billing month.
  period_start date        NOT NULL
    CONSTRAINT budget_alerts_first_of_month
      CHECK (period_start = date_trunc('month', period_start)::date),
  -- Percent of the budget.
  threshold    smallint    NOT NULL
    CONSTRAINT budget_alerts_threshold CHECK (threshold IN (50, 80, 100)),
  fired_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT budget_alerts_once PRIMARY KEY (org_id, service, period_start, threshold)
);

-- Tenant tables: the standard isolation policy (0004), which is also how
-- `Db::verify_tenant_isolation` and the rls_registry test discover them.
-- 0004's default privileges already granted both tables to otto_app.
ALTER TABLE service_budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_budgets FORCE ROW LEVEL SECURITY;
CREATE POLICY service_budgets_tenant_isolation ON service_budgets
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

ALTER TABLE budget_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE budget_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY budget_alerts_tenant_isolation ON budget_alerts
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());
