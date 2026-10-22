# Deploying the platform on Fly

`otto.savvagent.com` resolves straight to the Fly app `otto-platform`, and
`otto-platform-server` serves everything: the API, the OAuth authorization server, and the
`web/` bundle, which is the prerendered marketing pages and the console (`web/build`, baked
into the image at `/srv/console`). There is no edge in front,
which is also how `otto-tower.savvagent.com` runs. An optional Cloudflare Worker
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

| Secret                  | Required                        | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`          | yes                             | Staged by `fly postgres attach`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `OTTO_ENCRYPTION_KEY`   | yes                             | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts secrets at rest; losing it makes them unreadable.                                                                                                                                                                                                                                                                                                                                                                                             |
| `OTTO_SMTP_URL`         | no; together with the next one  | Notification email's SMTP server, credentials in the URL: `smtps://user:pass@host:465` or `smtp://user:pass@host:587?tls=required`. Unset (with `OTTO_EMAIL_FROM` also unset), email is disabled: the boot log says so and budget-alert emails wait in `notification_outbox` until it is set.                                                                                                                                                                                                               |
| `OTTO_EMAIL_FROM`       | no; together with the one above | The `From:` mailbox, e.g. `otto <alerts@savvagent.com>`. Setting exactly one of the two email secrets fails the deploy's health check by refusing to start.                                                                                                                                                                                                                                                                                                                                                 |
| `STRIPE_SECRET_KEY`     | no; together with the next one  | Billing's Stripe API key: a restricted key (`rk_live_...`) with the permissions under [Stripe setup](#stripe-setup). Its mode (live or test) must match the one recorded in the database ([Switching Stripe modes](#switching-stripe-modes)), or the server refuses to start. Unset (with `STRIPE_WEBHOOK_SECRET` also unset), billing is disabled: the boot log says so, `GET /api/orgs/{org}/billing` reports `billingEnabled: false`, and the setup route and the webhook answer `503 billing_disabled`. |
| `STRIPE_WEBHOOK_SECRET` | no; together with the one above | The webhook endpoint's signing secret (`whsec_...`), shown by Stripe when the endpoint is created. Setting exactly one of the two Stripe secrets fails the deploy's health check by refusing to start.                                                                                                                                                                                                                                                                                                      |

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
/api/orgs/{org}/billing/setup`, which sends them to Stripe Checkout, cards only). It needs
these steps, in this order, all done by a person with access to the Stripe dashboard. None
of them is done by CI or by the server.

1. **Account.** Activate the account for live payments (Settings → Business: business
   details, bank account, identity verification) and fill in the public details customers
   see on invoices, receipts and card statements (Settings → Business → Public details:
   business name, statement descriptor, support email and URL). Then set up billing as
   under [Billing settings](#billing-settings).
2. **Restricted key.** Dashboard → Developers → API keys → Create restricted key, named
   `otto-platform`. Grant **Write** on exactly these (Write includes the Read each needs):
   - Customers: create and search customers, set the default payment method
   - Payment Methods: detach the card a new one replaces
   - Checkout Sessions: setup-mode sessions
   - Setup Intents: read the card a session collected
   - Subscriptions: create, read and list subscriptions; list, add and change their
     **subscription items**; create, update and release **subscription schedules** (each
     month's price switch). If your dashboard lists Subscription items or Subscription
     schedules as resources of their own, grant Write on those too.
   - Invoices: read invoices, set `auto_advance` on a draft and **finalize** it (invoices
     are held as drafts until their usage has reached Stripe; see below)
   - Prices and Products: one price per price-book version, one product per meter
   - Billing Meters, and Billing Meter Events: meters, and usage shipping

   Everything else stays **None**. Use the live-mode key (`rk_live_...`) in production and
   a test-mode key (`rk_test_...`) anywhere else. Check the key in test mode first: run
   through [Verify in test mode](#verify-in-test-mode) with the test-mode key made with the
   same permissions; a missing permission shows up as a `403` in `stripe sync`'s errors or
   in the shipper's logs.
3. **Webhook endpoint.** Dashboard → Developers → Webhooks → Add endpoint:
   - URL: `https://otto.savvagent.com/api/stripe/webhook`
   - API version: `2025-03-31.basil` (the version the client is pinned to)
   - Events, exactly these seven: `checkout.session.completed`,
     `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.created`,
     `invoice.paid`, `invoice.payment_failed`, `payment_method.detached`

   Copy the endpoint's signing secret (`whsec_...`). Without `invoice.created` nothing is
   held: Stripe finalizes each invoice about an hour after it makes it, and usage that
   reaches Stripe later (see [How usage reaches an invoice](#how-usage-reaches-an-invoice))
   is never invoiced.
4. **Secrets.** Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` together (above). The
   next release logs `billing enabled: Stripe is configured`, and from then on every
   machine runs `stripe sync` on its own: at boot, every 15 minutes, and 30 seconds after
   00:00 UTC on the first of each month. A lease in the database lets only one machine
   sync at a time. The first boot with a key records the key's mode (live or test) in the
   database; see [Switching Stripe modes](#switching-stripe-modes).
5. **Prices.** Set the price book (`otto-platform-server pricebook set ...`, see the
   README). A price must be set at least 24 hours before the month it takes effect (by
   the database's clock), so **the first billable month is next month at the earliest**,
   or the month after that if you set prices on a month's last day. `set` prints what the
   month cost before and after (and logs it at info). The next automatic sync creates a
   Stripe meter per declared meter and a Stripe Price per price-book version, subscribes
   every org that already has a card on file, and schedules every subscription's switch
   to the new prices. To see it happen, run it by hand on the app's machine, which has
   `DATABASE_URL` and `STRIPE_SECRET_KEY` as secrets:

   ```bash
   fly ssh console -a otto-platform -C "otto-platform-server stripe sync"
   ```

   It prints what it did (a second run prints `nothing to do`), or `another stripe sync is
   running` if a machine is mid-run. It exits non-zero after listing anything it could not
   do (for example a meter key too long to be a Stripe event name), having done the rest;
   the logs show the same for the automatic runs.
6. **Verify once in test mode**, as below, before setting the live secrets.

### Billing settings

Dashboard → Settings → Billing, in live mode (and the same in test mode, so the test
matches):

- **Failed payments** (Subscriptions and emails → Manage failed payments): use Smart
  Retries (or a fixed schedule of a few attempts over two weeks). For the final action
  choose **cancel the subscription**. The platform treats a canceled subscription as
  billing stopped: the org's billable use past its free tiers answers `payment_required`
  until its owner puts a card on file again, which starts a new subscription. "Mark as
  unpaid" or "leave past due" keep the subscription live here: its usage keeps being
  queued for Stripe (so it is invoiced if the card recovers), but billable use past the
  free tiers answers `payment_required` as soon as it is `unpaid`, and 7 days after it
  became `past_due` (`otto_billing::billing::gate::PAYMENT_GRACE`). A card marked
  `failed` or `detached` gets the same 7 days.
- **Invoice finalization**: leave Stripe's automatic finalization of subscription
  invoices on. Stripe makes each month's invoice as a draft at 00:00 UTC on the first and
  would finalize it about an hour later (it waits for a successful answer to the
  `invoice.created` webhook first, up to 72 hours). The platform turns `auto_advance`
  off on each subscription-cycle draft when that webhook arrives and finalizes it itself
  once the month's usage has reached Stripe (about 02:15 to 02:45 UTC on the first, after
  the month closes at 02:00), or after 72 hours at most, turning `auto_advance` back on so
  Stripe collects it. Do not finalize held drafts by hand unless one is stuck: sync then
  finds it no longer a draft and leaves it (`not_draft`).
- **Customer emails** (Settings → Customer emails): turn on emails for finalized
  invoices, successful payments (receipts), failed payments, and expiring or updated
  cards. They go to the customer's email, which is the owner's address when they started
  setup.
- **Customer portal**: not used; owners manage their card through the console.

### How usage reaches an invoice

Metered usage reaches Stripe as one meter event per org, meter, customer and UTC hour, sent after the hour ends (expect up to ~1 h of lag). A billing month closes 2 h after 00:00 UTC on the 1st; usage arriving later is billed in the current month. `otto-platform-server stripe outbox` counts these hourly rows, not individual usage events. Sent rows are swept after 35 days, 5,000 per batch.

Ingest queues the metered usage of every org with a live subscription in
`stripe_meter_outbox`, and every machine runs a shipper that sends it, once `stripe sync`
has made the meter's Stripe meter (a newly declared meter's usage waits for the next
sync). It retries 5xx and timeouts for up to 12 hours from the first attempt Stripe may
have received (inside Stripe's 24-hour identifier dedupe, so nothing is counted twice),
and 429s and 401/403s, which Stripe never processed, until the usage is 34 days old. A
row Stripe refuses (a 4xx) or that could not be sent in time is kept as `rejected` or
`expired` with its error, logged at error level, and not invoiced.

**The first month.** An org's first subscription is backdated to 00:00 UTC on the first
of the month it is made in, and the usage it had already accrued that month (counted,
but not queued while it had no card) is queued as the subscription is recorded, so
Stripe rates the whole month through one set of tiers with one free allowance, as the
platform does. Usage of a month before the subscription is not billed; that includes the
previous month when the card goes on file between 00:00 and 02:00 UTC on the first (that
month is still open for late events, but the org had no card during it). A
re-subscription after a cancellation is backdated only past the earlier subscription
(see `otto_billing::billing`, "The first month").

**Invoices wait for their usage.** See *Invoice finalization* above. A held invoice is
finalized once the month has closed, two sync runs at least 10 minutes apart have seen
none of the usage that can be on it waiting to be sent, and the last of that usage was
sent at least 10 minutes earlier (Stripe applies meter events asynchronously). "Usage
that can be on it" is the org's usage billed in that month, for the invoice's customer,
of meters Stripe knows: a row stuck in an older month, a previous subscription's
customer's row, or a row of a meter `stripe sync` has not made yet never holds it (the
last is logged at warn, "waiting for a meter Stripe does not know yet": run `stripe
sync`). One still waiting after 72 hours is finalized anyway, logged at error
("finalized a Stripe invoice at its maximum hold") and shown by `stripe sync` as
`finalized_late`: that usage is not on it. A draft that had already advanced when the
webhook came to hold it is left to Stripe (`not_draft`); if it is open its automatic
collection is turned back on, and a paid, void or uncollectible one is not touched.

### When a new price takes effect

A price-book version can only be set for a month that starts at least 24 hours later,
and sync puts each live subscription under a Stripe subscription schedule as soon as the
version has its Stripe Price (within 15 minutes): the schedule switches the
subscription's items to the new prices at exactly 00:00 UTC on the first of that month,
without proration, then releases the subscription. The billing period is anchored to the
first, so the closing month is invoiced at the old prices and the new month is rated at
the new ones.

The one way that can fail is for every sync to fail for the whole day before the month
starts (Stripe down, a broken key). Then the subscription carries the previous month's
prices into the new month, and the first sync that succeeds afterwards moves its items to
the new prices in the middle of the month, without proration, and logs that at error
("changed a Stripe subscription's price in the middle of ..."). How Stripe then rates the
month's usage on either side of that change is Stripe's rule for a mid-period price
change on a metered item; check it once in test mode (below) and look at those orgs'
invoices for that month.

Notes:

- A Stripe price is immutable, and each price-book version gets its own. A future version
  replaced with `pricebook set` before its month leaves its Stripe price unused; the
  schedule is updated to the replacement. Sync never removes a subscription item.
- Stripe is never sent a card number: the owner types it into Stripe Checkout. Checkout
  offers cards only, because a bank debit confirms days later and its setup could finish
  in Checkout without ever reaching the platform as a card on file.
- A card that fails to pay is marked `failed`; a later paid invoice marks it `active`
  again. A new card on file replaces and detaches the old one.
- When Stripe cancels a subscription (from the dashboard, or after failed retries),
  billing for that org stops: nothing re-subscribes it until its owner puts a card on file
  again.
- An org has one subscription. Sync adopts a live one it finds (the recorded one, even if
  our copy of its status is stale, or one tagged `metadata[org_id]`) rather than making a
  second, and refuses to make one for a customer that already has another live
  subscription carrying a metered price: Stripe meters count per customer, so both would
  bill the same usage. A future paid plan must be added to this subscription, never
  sold as a second one.
- With billing disabled, `GET /api/orgs/{org}/billing` says so, nothing is invoiced, and
  usage-status never answers `payment_required` (nobody can put a card on file); usage is
  still metered and kept, and budgets still apply.
- Deleting an org does not yet cancel its Stripe subscription, or release its held
  invoices (#73); see [Deleting an org with a subscription](#deleting-an-org-with-a-subscription).
- Deleting an org deletes its queued meter events with it: usage it had not yet shipped
  to Stripe is not invoiced.
- The webhook ledger (`stripe_events`) is swept about once an hour of events handled more
  than 90 days ago.

### Deleting an org with a subscription

Until #73, deleting an org leaves its Stripe side as it was, and deletes the platform's
record of it (the customer map, the subscription row, the held invoices, the queued meter
events). Sync never touches that customer again. So, in the dashboard, for the org's
customer:

1. **Cancel its subscription**, or Stripe keeps invoicing it every month.
2. **Finalize or void its held draft invoices** (Invoices → Drafts, filtered to the
   customer; automatic collection shows as off). The platform turned their automatic
   advance off and would have finalized them; with the org deleted nothing will, and a
   draft with automatic collection off stays a draft forever. Finalize one that should
   be collected (turn automatic collection back on, or collect it by hand); void one
   that should not.

### Monitoring

- `fly ssh console -a otto-platform -C "otto-platform-server stripe outbox"`: rows by
  status and the oldest pending row's age. Any `rejected` or `expired` rows are usage that
  will not be invoiced (each row's `last_error` says why). The oldest pending row should
  be under about two hours old (an hour's usage waits for its hour to end); much older
  means the shipper is failing (look for its errors) or a meter has no Stripe meter yet
  (run `stripe sync`).
- Logs at error level from `stripe sync:` (anything sync could not do), "finalized a
  Stripe invoice at its maximum hold", "changed a Stripe subscription's price in the
  middle of", and the shipper's rejected/expired rows and 401/403s. A 401/403 (the key
  lacks *Billing Meter Events: write*) is retried, backing off to one pass every 5
  minutes; fix the key and nothing is lost.
- `fly ssh console -a otto-platform -C "otto-platform-server usage held"`: usage events
  held for review instead of billed, because they would take an org's total of one meter
  in one billing month past `OTTO_USAGE_HOLD_THRESHOLD` (default 1,000,000,000,000). Each is
  logged at error level when held ("usage held for operator review"), has been refused to
  its shipper (reason `held_for_review`) and is neither counted nor billed. An empty list
  is normal. A held event means a runaway or compromised resource server, or a real org
  that outgrew the threshold; in the second case raise the threshold and ask the
  resource server to resend the work. Events for an org that never authorized the
  calling resource server are refused outright (reason `not_authorized`, logged at warn
  level) and are not held.
- Stripe accepts meter events for processing and validates them asynchronously (an
  unknown customer, an archived meter); `sent` means accepted. Failures appear only as
  the meters' **error reports** (Dashboard → Billing → Meters → a meter → Error reports)
  and `v1.billing.meter.error_report_triggered` events, which the platform does not read
  yet (#76). Check them after a deploy that adds meters, and weekly.

### Verify in test mode

With a test-mode key and webhook (a staging deployment, or a local server reachable by
`stripe listen --forward-to localhost:<port>/api/stripe/webhook`). The tests in this
repository run against a local stand-in for Stripe, not Stripe, so do this once before
going live and after any change to billing.

1. **A customer on a test clock.** In the dashboard, in test mode, create a test clock
   (Billing → Subscriptions → Test clocks; search "test clocks" if it has moved), frozen at **the current time** (the platform computes the subscription's
   start and anchor from the real clock, and Stripe refuses an anchor before the clock's
   time). Add a customer to the clock. Map it to a test org (its id is in the console's
   URL or `SELECT id FROM orgs WHERE slug = '...'`), connected as the database superuser
   (`fly postgres connect -a otto-db -d otto_platform`):

   ```sql
   BEGIN;
   INSERT INTO subscriptions (org_id) VALUES ('<org-id>') ON CONFLICT (org_id) DO NOTHING;
   UPDATE subscriptions SET stripe_customer_id = '<cus_...>' WHERE org_id = '<org-id>';
   INSERT INTO stripe_customers (stripe_customer_id, org_id) VALUES ('<cus_...>', '<org-id>')
     ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id;
   COMMIT;
   ```

   (Setting the customer's metadata `org_id` to the org's id in the dashboard works too:
   setup adopts a customer tagged with the org, once Stripe's search sees it, about a
   minute later.) Have the org's owner put a test card (`4242 4242 4242 4242`) on file in
   the console; the subscription is made on that customer, so it runs on the clock.
2. **Usage.** Ingest metered usage for the org, wait for `stripe outbox` to show it
   `sent`, and check the meter's event summaries and the upcoming invoice. The shipper
   stamps each meter event with the start of its real UTC hour, so send usage before you
   advance the clock past it; to put usage on a clock time the shipper cannot reach, send
   it by hand for that customer, with the meter's event name, `stripe_customer_id` and
   `value` in the payload and a timestamp at the clock's time (the dashboard's meter
   page, or a `POST /v1/billing/meter_events` from the Stripe CLI). Then send one event's identifier twice (reset its outbox
   row to `pending` with `attempts` raised by one) and confirm Stripe counts it once,
   noting whether Stripe answered the repeat with `200` or a duplicate-identifier `400`
   (the shipper treats both as sent).
3. **First-month backdating.** Before step 1's card goes on file, ingest some usage for
   the org. After it subscribes, the subscription's start in the dashboard is 00:00 UTC
   on the first of the month, `stripe sync` printed (or the audit log's
   `billing.subscription.created` shows) the units backfilled, and the upcoming invoice
   carries that usage, with the free tier applied once.
4. **Rounding parity.** Price a test meter `--tier 3:500000 --tier inf:250000` (0.5¢ each
   for the first 3, then 0.25¢). With quantity 5 in a month, the platform says 2¢ (1.5¢ +
   0.5¢ = 2.0¢, rounded once). Check that Stripe's invoice line says 2¢ too, not 3¢ (which
   would mean Stripe rounds each tier on its own); if it differs, record it and file an
   issue before going live.
5. **Month-boundary price switch.** Set a new price for next month (at least 24 hours
   ahead), let sync run, and check the subscription's schedule: one phase to 00:00 UTC on
   the first, the next from then, no proration. Advance the clock past 00:00 UTC on the
   first. Stripe makes the closing month's invoice; the `invoice.created` webhook holds
   it (Dashboard: draft, automatic collection off). The closing month's usage is rated at
   the old price and the new month's at the new one.
6. **Late usage reaches the held invoice (go-live gate).** This is the test that
   invoice holding works at all: that usage Stripe receives after it made a month's
   invoice, timestamped inside that month, still lands on it. With step 5's draft held
   (the clock past 00:00 UTC on the first, the draft's automatic collection off):

   1. Advance the clock **3 more hours** (past the month's 02:00 UTC close, as late usage
      arrives in production).
   2. Send a meter event **by hand** for the test-clock customer (`POST
      /v1/billing/meter_events` from the Stripe CLI, or the meter's page in the
      dashboard): the meter's event name, `stripe_customer_id` set to that customer, a
      `value` you will recognize (say 7), a fresh `identifier`, and a **timestamp inside
      the closed month** (say 23:30 UTC on its last day).
   3. Release the invoice as in step 7, and open the finalized invoice.

   It must include that usage (the meter's line quantity grew by 7). Record the result
   here. **If it does not, invoice holding does not protect late usage, and going live
   must wait** for a different design: adding late usage to the held draft as invoice
   items, or closing the month (and shipping its last hour) before Stripe makes the
   invoice. Owner: Rob.
7. **Release of the held invoice.** The platform releases a held invoice by the real
   clock, so an invoice for a month that has not ended in real time waits for its
   72-hour maximum. To release it in the test, move its hold back and run sync:

   ```sql
   UPDATE stripe_held_invoices SET held_at = now() - interval '72 hours'
    WHERE stripe_invoice_id = '<in_...>';
   ```

   `stripe sync` then prints an `invoice` line for it ending `finalized_late` (and logs
   the expected error); the invoice is open with automatic collection on, and the test card
   is charged.
8. **Mid-period item change.** Simulate a missed switch: write a version for the
   current month straight into the database (`pricebook set` refuses it), as the
   superuser, then run `stripe sync`. It moves the item in the middle of the month and
   prints a `changed price in the middle of` warning (logged at error). Advance the clock
   to the month's end and record here how Stripe rated the usage before and after the
   change.

### Switching Stripe modes

The first boot (or `stripe sync`) with a Stripe key records the key's mode, `live` or
`test` (from its `sk_live_`/`rk_live_` or `sk_test_`/`rk_test_` prefix), in
`stripe_account_mode`. A later boot with a key of the other mode refuses to start ("is a
live-mode key, but this database's Stripe customers ... were made in test mode"), as
does `stripe sync`: the customer, subscription, meter and price ids recorded here do not
exist in the other mode.

To move a database from test mode to live mode on purpose, forget every test-mode
Stripe object, as the database superuser, then deploy with the live key. Owners put
their cards on file again (live), and sync makes meters, prices and subscriptions anew:

```sql
BEGIN;
DELETE FROM stripe_account_mode;
DELETE FROM stripe_held_invoices;
DELETE FROM stripe_meter_outbox WHERE status = 'pending';
DELETE FROM stripe_prices;
DELETE FROM stripe_meters;
DELETE FROM stripe_customers;
UPDATE subscriptions
   SET stripe_customer_id = NULL, stripe_subscription_id = NULL, status = 'active',
       payment_method_status = 'none', stripe_payment_method_id = NULL,
       payment_method_event_at = NULL, subscription_event_at = NULL, past_due_since = NULL,
       billing_stopped_at = NULL, stripe_schedule_id = NULL, stripe_plan = NULL,
       lease_until = NULL, lease_token = NULL;
COMMIT;
```

If the database never held objects of the other mode (the mode was recorded by mistake),
`DELETE FROM stripe_account_mode;` alone lets the next boot record the new one.

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

## Migrations and rolling back

Every machine applies the schema migrations (`crates/otto-tenant/migrations`) when it
boots, under a Postgres advisory lock, so the first machine of a new release migrates and
the rest find nothing to do. There are no down migrations, and the schema is never rolled
back.

**Migrations are additive.** A migration adds tables, nullable columns, constraints and
indexes; it never drops or renames anything a released binary reads. So a newer schema is
always one the previous release can run against, and the migrator is built for it: it
ignores applied migrations it does not know (`otto_tenant::db::MIGRATOR`), instead of
refusing to boot. **To roll back, deploy the previous release's image** (for example
`fly deploy -a otto-platform --image <previous image>`; `fly releases -a otto-platform
--image` lists them). It boots against the newer schema and serves. (A release from
before the epic #55 release does not ignore unknown migrations; rolling back to one needs
`OTTO_RUN_MIGRATIONS=0` on that deploy, see the [release notes](#release-notes).) Do not touch
`_sqlx_migrations`. When the rolled-forward release ships again, it finds its migrations
already applied. Every migration a release does know is still checked against its applied
checksum, so an edited migration is still refused.

A migration that has to remove or rename something needs two releases: one that stops
using it, then one that removes it. Only the second one migrates.

Migrations that lock a busy table set `lock_timeout = '5s'` first. A migration waiting
for such a lock would queue every later query on that table behind it; instead it fails,
the machine's boot fails, Fly restarts it, and the next boot retries. A deploy whose new
machines keep failing their health check stops there, with the previous release's machines
still serving.

## Release notes

### Per-service value meters (epic #55, migrations 0017 to 0023)

- **Usage during the rolling deploy.** Until every machine runs the new release, a machine
  still on the old release keeps ingesting usage events, and those events count only toward
  the legacy family-wide totals (`org_period_usage`, the console usage page). They are not
  counted in the per-service and per-meter pools (`org_service_period_usage`,
  `org_meter_period_usage`), so budgets and Stripe metered billing do not see them, and
  nothing backfills them. The gap is the length of the rollout, usually minutes. The same
  applies after a rollback: events ingested while the previous release serves count only
  toward the legacy totals.
- **Rolling back from this release needs `OTTO_RUN_MIGRATIONS=0`.** The release in
  production before this epic (v0.9.2) predates the migrator's tolerance of unknown
  migrations (`set_ignore_missing`, added in this release): booting with migrations on,
  it finds 0017 to 0023 applied but unknown to it and refuses to start. It does support
  `OTTO_RUN_MIGRATIONS`, and with it off it skips the migrator and serves against the
  newer schema (the migrations are additive). So deploy it with that variable set:

  ```bash
  fly deploy -a otto-platform --image <v0.9.2 image> --env OTTO_RUN_MIGRATIONS=0
  ```

  `--env` applies to that deploy only; the next deploy (rolling forward again) runs
  with migrations on, as normal, and finds them already applied. Do not touch
  `_sqlx_migrations`. Rolling back from a later release to this one, or to any release
  after it, needs nothing special: they ignore unknown migrations (see
  [Migrations and rolling back](#migrations-and-rolling-back)).

  Once billing is live, a rollback to v0.9.2 also costs revenue: that release
  queues no meter events and holds no invoices, and rolling forward does not
  backfill orgs that were already subscribed. Usage counted while it serves is
  not invoiced, and drafts created meanwhile finalize on Stripe's own schedule.
  Do not roll back across a month boundary; if you must, run `stripe sync` and
  check `stripe outbox` after rolling forward, and expect that window's usage
  to be missing from invoices.

### Usage ingest authorization and review (#79, migration 0027)

- `POST /internal/usage` accepts an event only for an org that has authorized the calling
  resource server, meaning a token of any kind was ever issued in the org for it (recorded
  in `org_resource_grants` by a trigger on `access_tokens` and `refresh_tokens`, and
  backfilled from the tokens that exist at migration time). "Ever", not "active", because
  usage is shipped from an outbox after the work. An org that has authorized nothing is
  refused per event with `not_authorized`. Tokens swept more than a week after expiry
  before this release are not in the backfill: an org that has used a resource server
  only through such tokens and still has usage to ship is refused, and is fixed by one new
  token (or by inserting its row into `org_resource_grants`).
- A metered event that would take an org's total of one meter in one UTC billing month past
  `OTTO_USAGE_HOLD_THRESHOLD` is held in `usage_held_events` (`otto-platform-server usage
  held`), not counted and not billed, and reported to its shipper as rejected with a reason
  starting `held_for_review`. There is no release command yet: counting a held event is a
  manual operator step.
