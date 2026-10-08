-- First-party OAuth clients (savvagent/otto-platform#3, Phase 4).
--
-- A first-party client is one the operator registered for a service they
-- run themselves (the otto-factory console signing its users in). The
-- authorization server skips the consent screen for these when the org the
-- token is for is already determined: asking someone whether the product
-- they just signed in to may access itself is not consent, it is friction.
--
-- Operator-only. The only writer is the `client register --first-party`
-- subcommand of otto-platform-server; dynamic client registration inserts
-- with the default and has no way to ask for anything else. Every client
-- that exists today was registered through DCR, so the default is correct
-- for all existing rows.
--
-- Global, like the rest of oauth_clients: not in 0004_rls.sql's tenant_tables,
-- and otto_app already has table-level privileges from 0004.

ALTER TABLE oauth_clients
  ADD COLUMN first_party boolean NOT NULL DEFAULT false;
