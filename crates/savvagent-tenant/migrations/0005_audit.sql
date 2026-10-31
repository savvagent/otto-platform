-- Audit trail.
--
-- Enterprise security review always asks who did what, from where, and
-- when — and that is history you cannot backfill. `auth_attempts` (0002) does
-- not serve this: it is an ephemeral rate-limiting bucket keyed by an opaque
-- string, not an attributable record. So this table exists from the first
-- auth path rather than being retrofitted when the first questionnaire
-- arrives.
--
-- This is otto-platform's own table, scoped to identity/auth/org-admin
-- events (see otto-tenant::audit::action). Each otto-* service's own domain
-- database runs this same pattern for its own domain events, separately —
-- see otto-tenant's crate docs.

CREATE TABLE audit_events (
  id            bigserial PRIMARY KEY,

  -- Nullable on purpose. Most events belong to an org and are readable by
  -- that org's admins under the RLS policy below. Some genuinely precede any
  -- org context — a login attempt, a passkey enrollment — and those are
  -- written with a NULL org.
  --
  -- The consequence is deliberate and fail-closed: `org_id = current_org()`
  -- is NULL for a NULL row, which is not TRUE, so org-scoped rows are the
  -- only ones a tenant can ever see. NULL-org rows are reachable only from
  -- the unpinned control plane (otto-auth), which is exactly the intent.
  org_id        uuid        REFERENCES orgs (id) ON DELETE CASCADE,

  actor_user_id uuid        REFERENCES users (id) ON DELETE SET NULL,
  -- Who acted when it was not a browser session: a PAT name, an OAuth
  -- client_id, or 'system' for background work. The user id above still
  -- attributes it to a human where one exists.
  actor_label   text,

  -- Dotted, stable, and enumerated in otto_tenant::audit::action. Queried by
  -- prefix ('auth.%'), so the namespace ordering matters.
  action        text        NOT NULL,
  target_type   text,
  target_id     text,

  -- Stored as text, not inet: we never do subnet arithmetic on it, and text
  -- avoids a type dependency for zero benefit. Carries IPv4, IPv6, or a
  -- forwarded-for chain equally well.
  ip            text,
  user_agent    text,

  -- Event-specific context. Never secrets: this table is readable by org
  -- admins in the console.
  detail        jsonb       NOT NULL DEFAULT '{}'::jsonb,

  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_time_idx ON audit_events (org_id, created_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_user_id, created_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, created_at DESC);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

-- Read policy, matching every other tenant table. The `<table>_tenant_isolation`
-- name is load-bearing: `Db::verify_tenant_isolation` discovers tenant tables by
-- that convention rather than from a list it would have to be told about.
CREATE POLICY audit_events_tenant_isolation ON audit_events
  FOR SELECT USING (org_id = current_org());

-- Appends. Two writers are legitimate, and they differ by whether a tenant
-- transaction is open:
--
--   * a pinned transaction (`Tx::audit`) may write only its own org's rows;
--   * the control plane runs unpinned — `Db::audit_global` records what
--     happens before any org context exists (logins, passkey enrollment),
--     and `Db::audit_for_org` records org events made during signup, before
--     a tenant transaction is available.
--
-- Writing this as a policy rather than relying on a grant is what makes it
-- survive a deployment with no `otto_app`. Under FORCE ROW LEVEL SECURITY the
-- owner is subject to policies too, so on managed Postgres — where the
-- application connects as the schema owner precisely because the role cannot
-- be created — a `WITH CHECK (org_id = current_org())` that did not allow the
-- unpinned case would reject every login's audit row.
CREATE POLICY audit_events_append ON audit_events
  FOR INSERT WITH CHECK (current_org() IS NULL OR org_id = current_org());

-- **Append-only**, expressed as the deliberate *absence* of a policy. An
-- audit trail an attacker can edit is not an audit trail.
--
-- A command with no matching policy affects zero rows, so under FORCE there
-- is no UPDATE path for anyone — not the tenant role, not the control plane,
-- not the table's owner.
--
-- DELETE is reachable only unpinned, which is the retention job the control
-- plane would run. A tenant transaction always has an org pinned, so nothing
-- reachable from a request can erase a row.
CREATE POLICY audit_events_retention ON audit_events
  FOR DELETE USING (current_org() IS NULL);

-- Privileges as well as policies wherever `otto_app` exists: a policy
-- decides which rows a statement may touch, a grant decides whether it may
-- run at all, and this table is worth both. Conditional because a managed
-- deployment has no such role — see 0004_rls.sql.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_app') THEN
    EXECUTE 'REVOKE UPDATE, DELETE ON audit_events FROM otto_app';
    EXECUTE 'GRANT SELECT, INSERT ON audit_events TO otto_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO otto_app';
  END IF;
END $$;
