-- Transactional outbox for email notifications (savvagent/otto-platform#58).
--
-- `otto_core::notifications::enqueue_email` writes a row here inside the
-- caller's tenant transaction, so a budget alert and the usage that crossed
-- the threshold commit or abort together. A background task in
-- otto-platform-server (`email::run`) sends due rows over SMTP and retries
-- with backoff, the same shape as the lifecycle webhook outbox (0011).
--
-- Unlike 0011's tables this one is TENANT-scoped: every row belongs to one org
-- and is written only from a transaction pinned to that org. It carries the
-- standard `<table>_tenant_isolation` policy, so `Db::verify_tenant_isolation`
-- discovers it and a pinned transaction sees its own org's mail and no one
-- else's.
--
-- The delivery task has no org to pin, and reads across every org through the
-- connecting role, as the webhook task does. Where that role is a superuser
-- (local development, `#[sqlx::test]`, the current Fly deployment) RLS does not
-- apply to it at all. Where it is the non-exempt schema owner (managed
-- Postgres), FORCE ROW LEVEL SECURITY applies the tenant policy, which is
-- never true unpinned, and the task would see nothing. The second policy below
-- is what lets it work there. It admits a row only when BOTH
--
--   * no org is pinned (`current_org()` IS NULL), so a tenant transaction can
--     never use it, whatever else it sets; and
--   * the transaction has opted in with
--     `set_config('app.notification_delivery', 'on', true)`, which only
--     `otto_core::notifications`' delivery functions do.
--
-- The opt-in is why this is not simply "unpinned sees everything": other
-- unpinned control-plane code (sign-in, signup) keeps seeing zero rows of this
-- table, exactly as it does every other tenant table. It is the same trust
-- model as `app.org_id` itself: a transaction-local setting the application
-- sets on purpose.
--
-- Deliberately not named `<table>_tenant_isolation` (see 0015): that suffix is
-- how tenant tables are discovered, and this is not an isolation policy.

CREATE TABLE notification_outbox (
  -- Minted by the caller rather than by RETURNING, following 0011.
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  recipient       text        NOT NULL,
  subject         text        NOT NULL,
  -- Plain text only. There is no HTML part, so nothing here is ever rendered.
  body_text       text        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  attempts        integer     NOT NULL DEFAULT 0,
  -- Next time a delivery task may pick this row up. Also the lease: claiming a
  -- row pushes this forward, so two replicas never send the same row at once.
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  -- Set once the retry budget is spent or the server refused the message
  -- permanently. The row stays for an operator to read `last_error`.
  failed_at       timestamptz,
  -- Never holds the SMTP URL or credentials; the delivery task redacts them.
  last_error      text,

  CONSTRAINT notification_outbox_recipient_present CHECK (length(recipient) BETWEEN 3 AND 254),
  CONSTRAINT notification_outbox_subject_one_line  CHECK (subject !~ '[\r\n]')
);

CREATE INDEX notification_outbox_due_idx
  ON notification_outbox (next_attempt_at)
  WHERE sent_at IS NULL AND failed_at IS NULL;

CREATE INDEX notification_outbox_org_idx ON notification_outbox (org_id, created_at);

ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_outbox_tenant_isolation ON notification_outbox
  USING (org_id = current_org()) WITH CHECK (org_id = current_org());

CREATE POLICY notification_outbox_delivery ON notification_outbox
  USING (
    current_org() IS NULL
    AND current_setting('app.notification_delivery', true) = 'on'
  )
  WITH CHECK (
    current_org() IS NULL
    AND current_setting('app.notification_delivery', true) = 'on'
  );
