-- Where, and how, the platform notifies a resource server of lifecycle
-- events (org deleted, team deleted, member removed).
--
-- Columns on `resource_servers` rather than a side table: a resource server
-- has at most one webhook, and it is provisioned and rotated by the same
-- operator commands as the introspection credential.
--
-- The signing secret is stored *encrypted*, not hashed, unlike the
-- introspection secret next to it. The introspection credential is something
-- the resource server presents to us, so a hash can verify it. The webhook
-- signature runs the other way: the platform has to compute an HMAC with the
-- key, which needs the key itself. It is sealed with `otto_tenant::Cipher`
-- (AES-256-GCM, keyed by OTTO_ENCRYPTION_KEY, which never reaches the
-- database), so a database dump alone yields no usable signing key.
--
-- All three are set together or not at all; clearing the webhook clears all
-- three.

ALTER TABLE resource_servers
  ADD COLUMN webhook_url               text,
  ADD COLUMN webhook_secret_ciphertext bytea,
  ADD COLUMN webhook_secret_nonce      bytea;

ALTER TABLE resource_servers
  ADD CONSTRAINT resource_servers_webhook_complete
  CHECK ((webhook_url IS NULL) = (webhook_secret_ciphertext IS NULL)
     AND (webhook_url IS NULL) = (webhook_secret_nonce IS NULL));
