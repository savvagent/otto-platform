-- Where to send a user after an SSO sign-in (savvagent/otto-platform#3).
--
-- The SPA sends signed-out visitors to /login?next=..., most importantly
-- when /oauth/authorize needs a session. A password-less passkey sign-in
-- resumes there client-side; the SSO callback is a server-side redirect from
-- the IdP, so the destination has to be carried across the round trip.
--
-- It is stored here, with the ceremony, rather than in the callback URL:
-- the callback's query string is attacker-reachable, this row is not.
-- The value is validated as a same-origin relative path before it is
-- written and again before it is used; NULL means "the console's home".
ALTER TABLE sso_ceremonies
  ADD COLUMN next_path text;
