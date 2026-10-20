# Deploying the platform on Fly

`otto.savvagent.com` resolves straight to the Fly app `otto-platform`, and
`otto-platform-server` serves everything: the API, the OAuth authorization server, and the
`web/` bundle, which is the prerendered marketing pages and the console (`web/build`, baked
into the image at `/srv/console`). There is no edge in front,
which is also how `otto-factory.savvagent.com` runs. An optional Cloudflare Worker
alternative is in [`cloudflare.md`](cloudflare.md).

One origin matters here for two reasons. The session is a `__Host-` cookie, which the
browser stores only for exactly the host that set it. And the WebAuthn relying party id is
the host of `OTTO_PUBLIC_URL`, so passkeys only work when the browser is on
`otto.savvagent.com`, not on `otto-platform.fly.dev`.

## Configuration (`fly.toml`)

| Variable                | Value                        | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OTTO_PUBLIC_URL`       | `https://otto.savvagent.com` | OAuth issuer, discovery documents, rp_id, and the origin the CSRF guard compares against.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `OTTO_STATIC_DIR`       | `/srv/console`               | Serve the console from this process. Prerendered pages answer as themselves (`/pricing` from `pricing.html` and `/` from `index.html`; `/pricing.html`, `/index.html` and a trailing slash are each a `308` to the one URL); any other extensionless path gets the SPA shell, `200.html`, with `X-Robots-Tag: noindex, nofollow`. The bundle must contain `200.html` (adapter-static `fallback: '200.html'`), or the server refuses to start. A missing asset stays a `404`; so does a path with a malformed escape or a `.`/`..` segment, as JSON. Unknown `/api`, `/oauth`, `/sso`, `/.well-known` and `/internal` paths answer a JSON `404`, never the shell. |
| `OTTO_CLIENT_IP_HEADER` | `fly-client-ip`              | Fly's proxy overwrites it with the real client address, so per-IP throttles and the audit trail are sound with nothing else to lock down.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

## Secrets

Never in `fly.toml`. Staged with `fly secrets set -a otto-platform`; see also the header of
`fly.toml`.

| Secret                  | Required                        | What                                                                                                                                                                                                                                                                                                                                               |
| ----------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`          | yes                             | Staged by `fly postgres attach`.                                                                                                                                                                                                                                                                                                                   |
| `OTTO_ENCRYPTION_KEY`   | yes                             | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts secrets at rest; losing it makes them unreadable.                                                                                                                                                                                                                                    |
| `OTTO_SMTP_URL`         | no; together with the next one  | Notification email's SMTP server, credentials in the URL: `smtps://user:pass@host:465` or `smtp://user:pass@host:587?tls=required`. Unset (with `OTTO_EMAIL_FROM` also unset), email is disabled: the boot log says so and budget-alert emails wait in `notification_outbox` until it is set.                                                      |
| `OTTO_EMAIL_FROM`       | no; together with the one above | The `From:` mailbox, e.g. `otto <alerts@savvagent.com>`. Setting exactly one of the two email secrets fails the deploy's health check by refusing to start.                                                                                                                                                                                        |
| `STRIPE_SECRET_KEY`     | no; together with the next one  | Billing's Stripe API key: a restricted key (`rk_live_...`) with the permissions under [Stripe setup](#stripe-setup). Unset (with `STRIPE_WEBHOOK_SECRET` also unset), billing is disabled: the boot log says so, `GET /api/orgs/{org}/billing` reports `billingEnabled: false`, and the setup route and the webhook answer `503 billing_disabled`. |
| `STRIPE_WEBHOOK_SECRET` | no; together with the one above | The webhook endpoint's signing secret (`whsec_...`), shown by Stripe when the endpoint is created. Setting exactly one of the two Stripe secrets fails the deploy's health check by refusing to start.                                                                                                                                             |

Set the two email secrets in one command so no release boots with only one of them:

```bash
fly secrets set -a otto-platform \
  OTTO_SMTP_URL='smtps://USER:PASSWORD@smtp.example.com:465' \
  OTTO_EMAIL_FROM='otto <alerts@savvagent.com>'
```

**Turning email on sends the backlog.** With the secrets unset, every notification is kept
in `notification_outbox`, never dropped. Setting them makes the next release send all of it,
oldest first, including alerts that are long out of date. To start clean instead, mark the
backlog failed before setting the secrets:

```sql
SET app.notification_delivery = 'on';  -- needed only if the role is not a superuser
UPDATE notification_outbox
   SET failed_at = now(), last_error = 'discarded: queued before email was enabled'
 WHERE sent_at IS NULL AND failed_at IS NULL;
```

**Wrong credentials or sender.** When the SMTP server refuses the platform rather than one
message (a rejected login, an `OTTO_EMAIL_FROM` the provider does not let us send as, a
`5.7.x` policy refusal, a refused greeting), the server logs one `error` ("the SMTP server
refused us, not the message") and keeps every message queued, retrying with backoff for
about a day (32 attempts). Fix the secret within that window and nothing is lost. Only a
refusal whose enhanced status code blames that one message (`5.1.x` recipient mailbox,
`5.2.x` mailbox state, `5.3.4` size, `5.6.x` content) is given up at once.

**Duplicates.** Delivery is at-least-once: if the server accepts a message but its reply
does not arrive within 30 s, or the result cannot be recorded, the message is sent again.

**Re-queueing failed messages.** Rows that ran out of attempts stay with `failed_at` and
`last_error` set. After fixing the cause, connect (`fly postgres connect -a otto-db -d
otto_platform`) and put them back in the queue. Narrow the `WHERE` to what you mean to
resend, by age or by error:

```sql
SET app.notification_delivery = 'on';  -- needed only if the role is not a superuser
UPDATE notification_outbox
   SET failed_at = NULL, attempts = 0, next_attempt_at = now()
 WHERE failed_at IS NOT NULL
   AND sent_at IS NULL
   AND created_at > now() - interval '2 days'
   -- AND last_error LIKE 'smtp: permanent error (535)%'
;
```

Set the two Stripe secrets in one command too:

```bash
fly secrets set -a otto-platform \
  STRIPE_SECRET_KEY='rk_live_...' \
  STRIPE_WEBHOOK_SECRET='whsec_...'
```

## Stripe setup

Billing invoices each org's metered usage monthly in arrears through a Stripe
subscription, once the org's owner has put a card on file (`POST
/api/orgs/{org}/billing/setup`, which sends them to Stripe Checkout). It needs
these steps, in this order, all done by a person with access to the Stripe dashboard. None
of them is done by CI or by the server.

1. **Restricted key.** Dashboard → Developers → API keys → Create restricted key, named
   `otto-platform`. Grant **Write** on exactly:
   - Customers (create customers, set the default payment method)
   - Checkout Sessions (setup-mode sessions)
   - Setup Intents (read the card a session collected; Write includes the Read needed)
   - Subscriptions (create subscriptions; add items and change an item's price)
   - Prices and Products (one price per price-book version, one product per meter)
   - Billing Meters, and Billing Meter Events (meters now; meter events for usage
     shipping, #64)

   Everything else stays **None**. Use the live-mode key in production and a test-mode
   key anywhere else.
2. **Webhook endpoint.** Dashboard → Developers → Webhooks → Add endpoint:
   - URL: `https://otto.savvagent.com/api/stripe/webhook`
   - API version: `2025-03-31.basil` (the version the client is pinned to)
   - Events, exactly these five: `checkout.session.completed`,
     `customer.subscription.updated`, `customer.subscription.deleted`,
     `invoice.payment_failed`, `payment_method.detached`

   Copy the endpoint's signing secret (`whsec_...`).
3. **Secrets.** Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` together (above). The
   next release logs `billing enabled: Stripe is configured`.
4. **Prices.** Set the price book (`otto-platform-server pricebook set ...`, see the
   README), then run it on the app's machine, which has `DATABASE_URL` and
   `STRIPE_SECRET_KEY` as secrets:

   ```bash
   fly ssh console -a otto-platform -C "otto-platform-server stripe sync"
   ```

   It creates a Stripe meter per declared meter and a Stripe Price per price-book version,
   subscribes every org that already has a card on file, and prints what it did; a second
   run prints `nothing to do`. It exits non-zero after listing anything it could not do
   (for example a meter key too long to be a Stripe event name), having done the rest.
5. **Every month a new price takes effect**, run `stripe sync` again soon after 00:00 UTC
   on the first: it moves each subscription's items to the version now in effect, and adds
   an item for each newly priced meter. Until it runs, usage keeps being billed at the
   previous version. It warns when a subscription nears Stripe's limit of 20 items.

Notes:

- A Stripe price is immutable, and each price-book version gets its own. A future version
  replaced with `pricebook set` before its month leaves its Stripe price unused; nothing
  is billed at it.
- Stripe is never called with a card number: the owner types it into Stripe Checkout.
- With billing disabled, `GET /api/orgs/{org}/billing` says so and nothing is invoiced;
  usage is still metered and kept.
- Deleting an org does not yet cancel its Stripe subscription. Cancel it in the dashboard.
- The webhook ledger (`stripe_events`) keeps every handled event id; it is not swept.

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
