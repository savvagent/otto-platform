# Deploying the platform on Fly

`otto.savvagent.com` resolves straight to the Fly app `otto-platform`, and
`otto-platform-server` serves everything: the API, the OAuth authorization server, and the
console (`web/build`, baked into the image at `/srv/console`). There is no edge in front,
which is also how `otto-factory.savvagent.com` runs. An optional Cloudflare Worker
alternative is in [`cloudflare.md`](cloudflare.md).

One origin matters here for two reasons. The session is a `__Host-` cookie, which the
browser stores only for exactly the host that set it. And the WebAuthn relying party id is
the host of `OTTO_PUBLIC_URL`, so passkeys only work when the browser is on
`otto.savvagent.com`, not on `otto-platform.fly.dev`.

## Configuration (`fly.toml`)

| Variable                | Value                        | Why                                                                                                                                                                                                      |
| ----------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OTTO_PUBLIC_URL`       | `https://otto.savvagent.com` | OAuth issuer, discovery documents, rp_id, and the origin the CSRF guard compares against.                                                                                                                |
| `OTTO_STATIC_DIR`       | `/srv/console`               | Serve the console from this process, with an `index.html` fallback for client routes. Unknown `/api`, `/oauth`, `/sso`, `/.well-known` and `/internal` paths still answer a JSON `404`, never the shell. |
| `OTTO_CLIENT_IP_HEADER` | `fly-client-ip`              | Fly's proxy overwrites it with the real client address, so per-IP throttles and the audit trail are sound with nothing else to lock down.                                                                |

Secrets (`DATABASE_URL` from `fly postgres attach`, `OTTO_ENCRYPTION_KEY`) are staged by
hand; see the header of `fly.toml`.

## The hostname

DNS is at Namecheap and stays there.

```bash
fly certs add otto.savvagent.com -a otto-platform
fly certs show otto.savvagent.com -a otto-platform   # prints the records to create
```

Create at Namecheap what `fly certs show` prints: an `A` and `AAAA` for `otto` (the
app's IPs, as for `otto-factory`), or a `CNAME` for `otto` to `otto-platform.fly.dev` if you
prefer. Then `fly certs check otto.savvagent.com -a otto-platform` until it reports issued.

**Settle this before the first passkey is registered.** Changing the host later invalidates
every passkey.

## Resource servers

With no edge, `/oauth/introspect` and `/internal/*` are reachable on `otto.savvagent.com`
like everything else. That is fine: they authenticate with the resource server's own
credential. Resource servers can use `https://otto.savvagent.com` for everything, the
issuer, introspection, usage ingest and webhooks, and `https://otto-platform.fly.dev` is
no longer needed by anyone.

## CSRF

`crates/otto-web/src/csrf.rs` refuses a non-`GET` that carries the session cookie unless its
`Origin` equals the origin of `OTTO_PUBLIC_URL` (or, with no `Origin`, it carries
`Sec-Fetch-Site: same-origin`). Served directly the browser sends exactly that origin, so
nothing needs configuring. `the_console_served_directly_keeps_csrf_and_json_404s` pins it.

## Deploying

Deploys run from CI on a release (`flyctl deploy --remote-only -a otto-platform`). The
image builds the console in its own stage, so one commit ships the server and the bundle
together and they cannot drift.
