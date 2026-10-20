<script lang="ts">
  import { formatCents, formatPercent, serviceName } from '$lib/billing';
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import type { ServiceUsage } from '$lib/types';

  /**
   * One service's spend this month, against its budget when it has one.
   *
   * Spend is money, per service: the console no longer counts a family-wide
   * bucket of calls. Three states, each said plainly:
   *
   * - **Spend unknown** (`spendCents: null`, the price could not be read):
   *   "Spend unavailable", never `$0`, which would tell an owner close to a
   *   hard stop that they have plenty of room.
   * - **No budget**: the spend, and no bar, since there is nothing to fill.
   * - **A budget**: a bar of spend against it. It can run past 100%; the bar
   *   is clamped for drawing and for `aria-valuenow` (a value above
   *   `aria-valuemax` is invalid ARIA), but not for the words, because an
   *   owner over budget needs to see by how much.
   *
   * A service whose paid usage is paused for want of a card
   * (`paymentRequired`) says so in words beside its spend, so the state sits
   * next to the meter it explains; the page's `PaymentRequiredNotices` says
   * what to do about it.
   *
   * `compact` is the overview's form: the service named on the left, and
   * nothing a glance does not need.
   */
  interface Props {
    usage: Pick<ServiceUsage, 'service' | 'spendCents' | 'budget'> &
      Partial<Pick<ServiceUsage, 'paymentRequired'>>;
    compact?: boolean;
  }

  let { usage, compact = false }: Props = $props();

  const name = $derived(serviceName(usage.service));
  const spend = $derived(
    usage.spendCents === null ? undefined : formatCents(usage.spendCents, currentLocale())
  );
  const budget = $derived(
    usage.budget ? formatCents(usage.budget.monthlyBudgetCents, currentLocale()) : undefined
  );
  const percent = $derived(usage.budget?.percentUsed ?? null);
  const percentLabel = $derived(percent === null ? '' : formatPercent(percent, currentLocale()));
  const width = $derived(percent === null ? 0 : Math.min(100, Math.max(0, percent)));
  const tone = $derived(
    usage.budget?.blocked || (percent ?? 0) >= 100
      ? 'bg-bad'
      : (percent ?? 0) >= 80
        ? 'bg-warn'
        : 'bg-accent'
  );
</script>

<div>
  <div class="flex items-baseline justify-between gap-3">
    {#if compact}
      <span class="truncate text-sm text-ink">{name}</span>
    {/if}
    <span class="text-sm" class:text-muted={spend !== undefined} class:text-warn={!spend}>
      {#if spend === undefined}
        {m.meter_spend_unavailable()}
      {:else if compact}
        {spend}
      {:else}
        {m.meter_spend({ spend })}
      {/if}
    </span>
    {#if usage.budget?.blocked}
      <span class="rounded-full bg-bad/10 px-2 py-0.5 text-xs text-bad">{m.meter_blocked()}</span>
    {/if}
    {#if usage.paymentRequired}
      <span class="shrink-0 rounded-full bg-bad/10 px-2 py-0.5 text-xs text-bad">
        {m.meter_payment_required()}
      </span>
    {/if}
  </div>

  {#if usage.budget && budget && spend !== undefined && percent !== null}
    <div
      class="mt-1.5 h-2 overflow-hidden rounded-full bg-raised"
      role="meter"
      aria-label={m.meter_aria_label({ service: name })}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={width}
      aria-valuetext={m.meter_aria_valuetext({ spend, budget, percent: percentLabel })}
    >
      <div class="h-full rounded-full transition-all {tone}" style="width: {width}%"></div>
    </div>
    <p class="mt-1 text-xs text-faint">
      {m.meter_spend_of_budget({ spend, budget, percent: percentLabel })}
    </p>
  {:else if budget}
    <p class="mt-1 text-xs text-faint">{m.meter_budget({ budget })}</p>
  {:else if !compact}
    <p class="mt-1 text-xs text-faint">{m.meter_no_budget()}</p>
  {/if}
</div>
