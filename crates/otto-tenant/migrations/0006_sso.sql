-- Enterprise OIDC federation: bound IdP connections, claimed email domains,
-- IdP subject pins, and the state held across the IdP redirect.
--
-- Ported from otto-factory (0005_auth.sql's idp_connections/claimed_domains/
-- user_identities, plus 0031_sso_ceremonies.sql). No later otto-factory
-- migration altered any of these four tables.
--
-- 0002_auth.sql's header still says these tables were left out. That comment
-- is stale but stays: editing an applied migration changes its checksum, and
-- sqlx then refuses to start against any database that already ran it.
--
-- None of the four is registered in 0004_rls.sql's tenant_tables, matching
-- otto-factory: authentication has to resolve them BEFORE an org is known
-- (a person types an email, the domain routes to an IdP; an IdP subject
-- resolves to a user; the callback finds its ceremony by state alone), so an
-- org_id = current_org() policy would make SSO sign-in impossible. Every
-- statement in otto-core's idp/domains modules still carries an explicit
-- org_id predicate (guard 1).

-- One bound IdP per org (v1); SAML is out of scope.
CREATE TABLE idp_connections (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  issuer           text        NOT NULL,
  client_id        text        NOT NULL,
  client_secret_ct bytea       NOT NULL,
  client_secret_nonce bytea    NOT NULL,
  -- Cached OIDC discovery document, refreshed lazily.
  discovery        jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id)
);

-- Email domains an org has claimed. A login for a claimed domain is routed to
-- that org's IdP. Control is proved with a DNS TXT record before verified_at
-- is set: an unverified claim routes nobody, so claiming `gmail.com`
-- accomplishes nothing.
CREATE TABLE claimed_domains (
  org_id             uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  domain             text        NOT NULL,
  verification_token text        NOT NULL,
  verified_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain)
);

CREATE INDEX claimed_domains_org_idx ON claimed_domains (org_id);

-- Pins an IdP subject to a user on first federated login.
CREATE TABLE user_identities (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  idp_connection_id uuid NOT NULL REFERENCES idp_connections (id) ON DELETE CASCADE,
  subject           text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (idp_connection_id, subject)
);

-- State held between "redirect to the IdP" and "the IdP redirects back" for
-- enterprise OIDC federation. Parallel to webauthn_ceremonies (0002_auth.sql)
-- but a distinct shape: an OIDC state/nonce pair, not a serialized WebAuthn
-- challenge. No org_id-based RLS -- like webauthn_ceremonies, this is
-- short-lived correlation data read by state alone, before any session exists
-- to pin an org to. org_id is denormalized onto the row (not re-derived from
-- the domain a second time at callback) so a domain reassigned mid-flow can't
-- retarget an in-flight ceremony.
CREATE TABLE sso_ceremonies (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  idp_connection_id uuid NOT NULL REFERENCES idp_connections (id) ON DELETE CASCADE,
  -- Set only by the authenticated "link my SSO identity" path (an existing
  -- session proving account ownership); NULL for the anonymous "sign in with
  -- SSO" path. The callback links to this user_id directly when set, and
  -- never resolves by email at all in that case -- see the design spec's
  -- Assumptions on why an email match alone must never establish or extend
  -- account access.
  user_id           uuid REFERENCES users (id) ON DELETE CASCADE,
  -- Single-use, bearer-shaped, hashed at rest -- same convention as
  -- sessions/access_tokens.
  state_hash        bytea NOT NULL,
  -- A second secret, distinct from state_hash, carried by an HttpOnly cookie
  -- set at ceremony-start and checked at callback. state travels in a URL and
  -- can be captured and replayed by an attacker into a victim's browser
  -- (login CSRF); this is what proves the browser completing the callback is
  -- the same one that started the ceremony. See the design spec's
  -- Assumptions for the full threat this closes.
  binding_hash      bytea NOT NULL,
  -- Anti-replay on the returned id_token. Not a bearer credential (sent to
  -- the IdP as a plaintext query parameter); no confidentiality property to
  -- protect here.
  nonce             text NOT NULL,
  expires_at        timestamptz NOT NULL,
  consumed_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX sso_ceremonies_state_key ON sso_ceremonies (state_hash);
CREATE INDEX sso_ceremonies_expiry_idx ON sso_ceremonies (expires_at);

-- Deliberately not added to 0004_rls.sql's tenant_tables array -- same
-- reasoning as webauthn_ceremonies: this table must be readable by
-- state_hash alone, before any org is known, and it holds no secret worth an
-- RLS policy protecting (the state token itself is what's confidential, and
-- it's hashed). Every write still carries an explicit org_id/id predicate
-- (guard 1) -- see crates/otto-core/src/ceremonies.rs.
