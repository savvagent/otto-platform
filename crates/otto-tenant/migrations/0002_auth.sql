-- Authentication. Two distinct layers live here and must not be conflated:
--   Layer 2 (who the human is): passkeys, webauthn_ceremonies, account_claims,
--            browser_sessions, auth_attempts.
--   Layer 1 (what a client may do): oauth_clients, authorization_codes,
--            access_tokens, refresh_tokens.
-- Nothing here stores a password. The only factor is a passkey; recovery is a
-- second passkey, or an admin-issued account claim code.
--
-- This is a fresh baseline: otto-factory's original auth migration also
-- created `totp_credentials`, `totp_used_steps`, `recovery_codes`, and
-- `magic_links`, all of which were later dropped there in favor of passkeys.
-- None of that history exists in this schema — it starts from passkeys
-- directly. Enterprise IdP/SSO federation tables (`idp_connections`,
-- `claimed_domains`, `user_identities`, `sso_ceremonies`) are created
-- separately in 0006_sso.sql; `orgs.enforce_sso` (0001_identity.sql) is the
-- flag they build on.

CREATE TYPE token_kind AS ENUM ('oauth', 'pat');

-- ---------------------------------------------------------------- layer 2 ---

-- One row per registered authenticator. A user is *expected* to have
-- several — that is the recovery story, and the console should push for a
-- second one.
CREATE TABLE passkeys (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The raw credential ID, indexed because authentication arrives holding one
  -- and nothing else.
  credential_id bytea       NOT NULL,
  -- webauthn-rs's `Passkey`, serialised. Public key material and a counter;
  -- opaque to SQL on purpose, because its internals are that crate's business
  -- and pulling them into columns would freeze its representation here.
  credential    jsonb       NOT NULL,
  -- "MacBook", "YubiKey". Set by the user so a list of keys is a list they can
  -- act on — an unlabelled set of credential IDs is one nobody dares delete.
  nickname      text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);

CREATE UNIQUE INDEX passkeys_credential_id_key ON passkeys (credential_id);
CREATE INDEX passkeys_user_idx ON passkeys (user_id, created_at DESC);

-- A WebAuthn ceremony is two round trips, and the server must remember the
-- challenge it issued between them.
--
-- **Server-side, always.** The challenge state is what binds a signature to a
-- request this server actually made; handing it to the client to give back
-- would let an attacker replay one they kept. webauthn-rs says as much in
-- capitals, and the `danger-allow-state-serialisation` feature exists so it
-- can be stored somewhere like this rather than held in process memory —
-- which would break the moment a second machine answered the second request.
CREATE TABLE webauthn_ceremonies (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- 'register' or 'authenticate'. Checked on redemption: a registration state
  -- must never be finishable as an authentication.
  kind       text        NOT NULL,
  -- Null for sign-in, which is deliberately usernameless — the whole point is
  -- that no identifier is submitted before the ceremony completes.
  user_id    uuid        REFERENCES users(id) ON DELETE CASCADE,
  state      jsonb       NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies (expires_at);

-- Re-registration after an admin clears someone's passkeys.
--
-- Without this, an account with no passkeys is claimable by whoever reaches
-- signup first — the takeover this table exists to prevent: the reset was
-- supposed to grant nothing, and without a claim code it would instead open a
-- race that any stranger could win. A claim is single-use, expiring, and
-- bound to one account.
--
-- Hashed like every other credential here — the plaintext is returned once,
-- to the admin who asked for it, and never stored.
CREATE TABLE account_claims (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  bytea       NOT NULL,
  issued_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX account_claims_token_key ON account_claims (token_hash);
CREATE INDEX account_claims_user_idx ON account_claims (user_id) WHERE consumed_at IS NULL;

-- Console browser sessions (cookie value hashed at rest, like every other
-- token).
CREATE TABLE browser_sessions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash bytea       NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX browser_sessions_token_key ON browser_sessions (token_hash);
CREATE INDEX browser_sessions_user_idx ON browser_sessions (user_id);

-- Rate limiting / lockout for login attempts. Keyed by an opaque string so the
-- same table serves per-user, per-IP, and per-credential buckets.
CREATE TABLE auth_attempts (
  id         bigserial PRIMARY KEY,
  bucket     text        NOT NULL,
  successful boolean     NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_attempts_bucket_idx ON auth_attempts (bucket, created_at DESC);

-- ---------------------------------------------------------------- layer 1 ---

-- OAuth clients, most of them self-registered through RFC 7591 dynamic client
-- registration so an agent can connect without an admin creating a client by
-- hand.
CREATE TABLE oauth_clients (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id          text        NOT NULL,
  -- NULL for public clients (the normal case for a CLI agent using PKCE).
  client_secret_hash bytea,
  client_name        text,
  redirect_uris      jsonb       NOT NULL DEFAULT '[]'::jsonb,
  grant_types        jsonb       NOT NULL DEFAULT '["authorization_code","refresh_token"]'::jsonb,
  software_id        text,
  registered_via_dcr boolean     NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now(),
  disabled_at        timestamptz
);

CREATE UNIQUE INDEX oauth_clients_client_id_key ON oauth_clients (client_id);

CREATE TABLE authorization_codes (
  code_hash             bytea PRIMARY KEY,
  client_id             text        NOT NULL,
  user_id               uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- The org is bound at authorization time. A token therefore cannot be
  -- pivoted to another org the same user happens to belong to.
  org_id                uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  redirect_uri          text        NOT NULL,
  -- PKCE is mandatory: S256 only, no `plain`, no missing challenge.
  code_challenge        text        NOT NULL,
  code_challenge_method text        NOT NULL DEFAULT 'S256',
  scopes                text[]      NOT NULL DEFAULT '{}',
  -- RFC 8707 resource indicator. The token minted from this code is
  -- audience-bound to it, and each otto-* resource server rejects any token
  -- whose audience is not its own canonical URI. This is the confused-deputy
  -- defense that lets one identity database serve every otto-* service.
  resource              text        NOT NULL,
  expires_at            timestamptz NOT NULL,
  consumed_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now()
);

-- Access tokens are opaque random strings; only the SHA-256 hash is stored, so
-- a database read does not yield a usable credential. PATs share this table
-- because they carry identical claims — the only differences are `kind`, a
-- human-facing `name`, and a longer lifetime.
CREATE TABLE access_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash   bytea       NOT NULL,
  kind         token_kind  NOT NULL DEFAULT 'oauth',
  name         text,
  user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  org_id       uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  client_id    text,
  scopes       text[]      NOT NULL DEFAULT '{}',
  resource     text        NOT NULL,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX access_tokens_token_key ON access_tokens (token_hash);
CREATE INDEX access_tokens_org_user_idx ON access_tokens (org_id, user_id);

-- Refresh tokens rotate: redeeming one consumes it and issues a successor. A
-- replayed (already-consumed) refresh token is treated as theft and revokes
-- the whole chain — see otto-auth::tokens::redeem_refresh.
CREATE TABLE refresh_tokens (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash      bytea       NOT NULL,
  access_token_id uuid        REFERENCES access_tokens (id) ON DELETE SET NULL,
  user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  org_id          uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  client_id       text        NOT NULL,
  scopes          text[]      NOT NULL DEFAULT '{}',
  resource        text        NOT NULL,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  rotated_to      uuid        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX refresh_tokens_token_key ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id, org_id);
