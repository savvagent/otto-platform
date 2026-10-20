<script lang="ts">
  import { serviceName } from '$lib/billing';
  import { m } from '$lib/paraglide/messages';
  import type { ServiceUsage } from '$lib/types';
  import LinkButton from './LinkButton.svelte';

  /**
   * One notice per service whose paid usage is paused because the org has no
   * card on file (`paymentRequired` in the usage report): past its free
   * allowance this month, its billable calls are refused with
   * `payment_required` while its free calls keep working.
   *
   * **What it asks of whom.** Only an owner can add a card, so an owner gets
   * a link to the billing page; an admin or member is told an owner must add
   * one, rather than shown a link to a page they cannot open.
   *
   * **How loudly.** Like `BudgetAlerts`' standing alerts, this is the state of
   * things when the page loads, not news: it sits in one polite `status`
   * region. These pages do not poll and nothing on them can clear or cause
   * it, so there is no later alert to interrupt with. Each notice says what
   * is paused in words, so it reads without its colour.
   */
  interface Props {
    services: readonly Pick<ServiceUsage, 'service' | 'paymentRequired'>[];
    /** Whether the viewer is an owner, the one role that can add a card. */
    owner: boolean;
    /** Where an owner adds a card: `/o/<org>/billing`. */
    billingHref: string;
  }

  let { services, owner, billingHref }: Props = $props();

  const paused = $derived(services.filter((s) => s.paymentRequired));
</script>

{#if paused.length > 0}
  <section aria-label={m.payment_required_label()}>
    <div role="status" class="space-y-2">
      {#each paused as service (service.service)}
        <div
          class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-bad/50 bg-bad/10 px-3 py-2 text-sm text-bad"
        >
          {#if owner}
            <p>{m.payment_required_owner({ service: serviceName(service.service) })}</p>
            <LinkButton href={billingHref} size="sm">{m.payment_required_add_card()}</LinkButton>
          {:else}
            <p>{m.payment_required_member({ service: serviceName(service.service) })}</p>
          {/if}
        </div>
      {/each}
    </div>
  </section>
{/if}
