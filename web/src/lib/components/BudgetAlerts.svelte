<script lang="ts">
  import { untrack } from 'svelte';

  import { budgetAlerts, formatPercent, serviceName, type BudgetAlert } from '$lib/billing';
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import type { ServiceBudget } from '$lib/types';

  /**
   * The budget thresholds this month has crossed (50, 80, 100%), as the
   * console's half of the alert an owner or admin also gets by email.
   *
   * Read from `thresholdsReached`, the alerts the server has actually fired,
   * rather than recomputed from spend: the console and the inbox name the
   * same events. A hard-stopped service that is refusing calls is an error;
   * everything else is a warning.
   *
   * **How loudly depends on who caused it.** What is already true when the
   * page loads sits in one polite `status` region: it is the state of things,
   * not news, and a page that opened with three assertive alerts would talk
   * over its own heading. An alert that appears afterwards can only be the
   * result of something the user just did (these pages do not poll), say a
   * lowered budget that now blocks a service, so it is a `role="alert"` and
   * interrupts.
   */
  interface Props {
    services: readonly ServiceBudget[];
  }

  let { services }: Props = $props();

  const key = (a: BudgetAlert) => `${a.service}:${a.threshold}:${a.blocked}`;

  const alerts = $derived(budgetAlerts(services));
  const onLoad = untrack(() => new Set(budgetAlerts(services).map(key)));
  const standing = $derived(alerts.filter((a) => onLoad.has(key(a))));
  const fresh = $derived(alerts.filter((a) => !onLoad.has(key(a))));

  const tone = (a: BudgetAlert) =>
    a.blocked ? 'border-bad/50 bg-bad/10 text-bad' : 'border-warn/50 bg-warn/10 text-warn';

  const text = (a: BudgetAlert) =>
    a.blocked
      ? m.budget_alert_blocked({ service: serviceName(a.service) })
      : m.budget_alert_threshold({
          service: serviceName(a.service),
          percent: formatPercent(a.threshold, currentLocale())
        });
</script>

{#if alerts.length > 0}
  <section class="space-y-2" aria-label={m.budget_alerts_label()}>
    <div role="status" class="space-y-2" class:hidden={standing.length === 0}>
      {#each standing as alert (alert.service)}
        <p class="rounded-md border px-3 py-2 text-sm {tone(alert)}">{text(alert)}</p>
      {/each}
    </div>
    {#each fresh as alert (alert.service)}
      <p role="alert" class="rounded-md border px-3 py-2 text-sm {tone(alert)}">{text(alert)}</p>
    {/each}
  </section>
{/if}
