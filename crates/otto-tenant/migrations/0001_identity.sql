-- Identity and tenancy. `orgs` is THE tenant boundary: every other tenant
-- table carries a NOT NULL org_id referencing it, and RLS (migration
-- 0004_rls.sql) pins each transaction to one org.
--
-- This is a fresh baseline for otto-platform, extracted from otto-factory's
-- of-core migrations. It reflects the *current* shape of that schema after
-- several since-folded amendments, not the original day-one shape:
--   - `users.email` is nullable (a passkey brings the account into existence;
--     the address is set afterwards) and `email_verified_at` does not exist
--     at all (otto-factory dropped it: no mail is ever sent, so nothing can
--     verify an address).
--   - `users.locale` and `users.label` exist from the start.
--   - `orgs` carries no `next_job_seq` counter — that is otto-factory's own
--     per-org job-id sequence, not part of the shared identity substrate.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE org_role AS ENUM ('owner', 'admin', 'member');
CREATE TYPE org_plan AS ENUM ('free', 'team', 'business', 'enterprise');

-- A global human identity. One row per human no matter how many orgs they
-- belong to.
CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Absent until the account sets one. A passkey is what brings an account
  -- into existence, so there is a real moment where an account has no
  -- address at all — see otto-auth's crate docs. Unique when set.
  email       text,
  name        text,
  -- The console language this account chose, or NULL for "never chose" —
  -- not the same thing as "chose English". No CHECK constraint: the valid
  -- set is validated in otto-core rather than enumerated here, so adding a
  -- locale is a one-line code change rather than a migration.
  locale      text,
  -- The `adjective-noun-NN` handle a credential vault shows beside this
  -- account's passkey (see otto-core::labels). A name, not an identifier: no
  -- unique index, because a cosmetic collision must never become a failed
  -- signup. The default covers the narrow window during a rolling deploy
  -- where code older than this migration is still inserting rows; in steady
  -- state every row is written by the Rust generator.
  label       text NOT NULL DEFAULT (
    (ARRAY['amber','brisk','clever','golden','lively','nimble','quiet','rugged'])
      [floor(random() * 8)::int + 1]
    || '-' ||
    (ARRAY['acorn','beacon','cedar','falcon','harbor','meadow','ridge','willow'])
      [floor(random() * 8)::int + 1]
    || '-' ||
    (10 + floor(random() * 90)::int)::text
  ),
  created_at  timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

-- Case-insensitive uniqueness without depending on the citext extension being
-- available on the host. Postgres allows any number of rows to share a NULL
-- here, which is exactly right: several accounts may have no address yet;
-- none may share one.
CREATE UNIQUE INDEX users_email_key ON users (lower(email));

CREATE TABLE orgs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        text        NOT NULL,
  name        text        NOT NULL,
  plan        org_plan    NOT NULL DEFAULT 'free',
  -- When true, this org's members must authenticate through its bound IdP.
  -- (No IdP-connection tables ship in this baseline — see otto-auth's crate
  -- docs for why — but the flag itself is part of the org record and
  -- otto-auth's error type already reserves a refusal for it.)
  enforce_sso boolean     NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);

CREATE UNIQUE INDEX orgs_slug_key ON orgs (lower(slug));

CREATE TABLE org_members (
  org_id     uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role       org_role    NOT NULL DEFAULT 'member',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE INDEX org_members_user_idx ON org_members (user_id);

CREATE TABLE teams (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  slug       text        NOT NULL,
  name       text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug)
);

CREATE TABLE team_members (
  -- org_id is denormalized onto every tenant table so one RLS policy shape
  -- works everywhere and no policy needs a join to establish tenancy.
  org_id     uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  team_id    uuid        NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, user_id)
);

CREATE INDEX team_members_org_user_idx ON team_members (org_id, user_id);

-- Pending invitations. An invite is consumed by whoever proves control of the
-- email address, which may be a user that does not exist yet.
CREATE TABLE org_invites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
  email       text        NOT NULL,
  role        org_role    NOT NULL DEFAULT 'member',
  invited_by  uuid        REFERENCES users (id) ON DELETE SET NULL,
  token_hash  bytea       NOT NULL,
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX org_invites_token_key ON org_invites (token_hash);
CREATE INDEX org_invites_org_email_idx ON org_invites (org_id, lower(email));
