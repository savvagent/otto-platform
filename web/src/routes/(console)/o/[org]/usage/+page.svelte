<script lang="ts">
  import { api } from '$lib/api';
  import { serviceName } from '$lib/billing';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { currentLocale } from '$lib/locale';
  import { useOrg } from '$lib/org.svelte';
  import { day } from '$lib/format';
  import type { BudgetsResponse, UsageStatus } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import BudgetAlerts from '$lib/components/BudgetAlerts.svelte';
  import Card from '$lib/components/Card.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import Meter from '$lib/components/Meter.svelte';
  import PaymentRequiredNotices from '$lib/components/PaymentRequiredNotices.svelte';

  /**
   * Usage, per service: each meter's quantity this month, and what it has
   * cost.
   *
   * Free to read, and readable by an org that has hit a hard stop: an owner
   * who has been stopped must be able to see why. Usage is priced per service
   * by value meter, so there is no family-wide count here, and the legacy
   * bucket fields the server still sends are not read (see `UsageStatus`).
   *
   * The budgets read rides along for its fired thresholds, so an alert shows
   * here as well as on the budgets page. It is optional: if it fails, the
   * usage still shows, with a quiet note that alerts could not be read,
   * rather than a page blanked over a secondary read.
   *
   * A service whose paid usage is paused for want of a card
   * (`paymentRequired`) gets a notice above, and says so beside its meter.
   * That comes from the usage read itself, so it shows even when the budgets
   * read fails.
   */

  const org = useOrg();

  interface Report {
    usage: UsageStatus;
    /** `undefined` when the budgets read failed. */
    budgets: BudgetsResponse | undefined;
  }

  let report = $state<Report | undefined>(undefined);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug) return;

    report = undefined;
    error = undefined;

    void (async () => {
      try {
        const [usage, budgets] = await Promise.allSettled([api.usage(slug), api.budgets(slug)]);
        if (usage.status === 'rejected') throw usage.reason;
        // A fast navigation between two orgs can land the first fetch after the second.
        if (org.slug !== slug) return;
        report = {
          usage: usage.value,
          budgets: budgets.status === 'fulfilled' ? budgets.value : undefined
        };
      } catch (e) {
        if (org.slug === slug) error = messageFor(e, m.usage_load_failed());
      }
    })();
  });

  const count = (n: number) => n.toLocaleString(currentLocale());
</script>

<div class="space-y-5">
  <div class="flex items-start justify-between gap-4">
    <div>
      <h1 class="text-lg font-semibold">{m.usage_title()}</h1>
      <p class="mt-0.5 text-sm text-faint">{m.usage_subtitle()}</p>
    </div>
    <a class="shrink-0 text-xs text-muted underline hover:text-ink" href="/o/{org.slug}/budgets">
      {m.usage_budgets_link()}
    </a>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if !report}
    <Loading what={m.usage_reading_meter()} />
  {:else}
    <PaymentRequiredNotices
      services={report.usage.services}
      owner={org.isOwner}
      billingHref="/o/{org.slug}/billing"
    />

    {#if report.budgets}
      <BudgetAlerts services={report.budgets.services} />
    {:else}
      <p class="text-xs text-faint">{m.usage_alerts_unavailable()}</p>
    {/if}

    <p class="text-xs text-faint">
      {m.usage_period_since({ date: day(report.usage.periodStart) })}
    </p>

    {#if report.usage.services.length === 0}
      <Empty title={m.usage_empty_title()}>{m.usage_empty_hint()}</Empty>
    {:else}
      {#each report.usage.services as service (service.service)}
        <Card title={serviceName(service.service)}>
          <div class="space-y-4">
            <div>
              <div class="sav-label">{m.usage_spend_label()}</div>
              <Meter usage={service} />
              {#if service.spendError}
                <p class="mt-1 text-xs text-faint">{m.usage_spend_unavailable_hint()}</p>
              {/if}
            </div>

            {#if service.meters.length === 0}
              <p class="text-sm text-faint">{m.usage_no_meters()}</p>
            {:else}
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  {m.usage_meters_caption({ service: serviceName(service.service) })}
                </caption>
                <thead class="text-xs text-faint">
                  <tr>
                    <th scope="col" class="py-1 font-medium">{m.usage_col_meter()}</th>
                    <th scope="col" class="py-1 font-medium">{m.usage_col_unit()}</th>
                    <th scope="col" class="py-1 text-right font-medium">
                      {m.usage_col_quantity()}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {#each service.meters as meter (meter.meter)}
                    <tr class="border-t border-edge/60">
                      <th scope="row" class="py-1.5 font-normal text-ink">{meter.displayName}</th>
                      <td class="py-1.5 text-muted">{meter.unit}</td>
                      <td class="py-1.5 text-right text-ink tabular-nums">
                        {count(meter.quantity)}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        </Card>
      {/each}
    {/if}

    <p class="text-xs text-faint">{m.usage_prices_note()}</p>
  {/if}
</div>
