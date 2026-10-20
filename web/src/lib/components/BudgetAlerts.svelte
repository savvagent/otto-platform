<script lang="ts">
  import { budgetAlerts, formatPercent, serviceName } from '$lib/billing';
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import type { ServiceBudget } from '$lib/types';
  import Alert from './Alert.svelte';

  /**
   * The budget thresholds this month has crossed (50, 80, 100%), as the
   * console's half of the alert an owner or admin also gets by email.
   *
   * Read from `thresholdsReached`, the alerts the server has actually fired,
   * rather than recomputed from spend: the console and the inbox name the
   * same events. A hard-stopped service that is refusing calls is an error;
   * everything else is a warning. Each `Alert` is a live region, so an alert
   * that appears after the page loads is announced.
   */
  interface Props {
    services: readonly ServiceBudget[];
  }

  let { services }: Props = $props();

  const alerts = $derived(budgetAlerts(services));
</script>

{#if alerts.length > 0}
  <section class="space-y-2" aria-label={m.budget_alerts_label()}>
    {#each alerts as alert (alert.service)}
      <Alert tone={alert.blocked ? 'error' : 'warn'}>
        {#if alert.blocked}
          {m.budget_alert_blocked({ service: serviceName(alert.service) })}
        {:else}
          {m.budget_alert_threshold({
            service: serviceName(alert.service),
            percent: formatPercent(alert.threshold, currentLocale())
          })}
        {/if}
      </Alert>
    {/each}
  </section>
{/if}
