<script lang="ts">
  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { featureLabels, formatOps, priceLabel } from '$lib/pricing';
  import { CONTACT_EMAIL } from '$lib/site';
  import type { Plan } from '$lib/types';
  import LinkButton from '$lib/components/LinkButton.svelte';
  import ConsoleLink from './ConsoleLink.svelte';

  /**
   * One plan from `GET /api/plans`, as the pricing page shows it: name,
   * price, monthly allowance, what happens past it, the advertised features,
   * and the way in.
   *
   * `displayName` comes from the server and is a name, so it is shown as
   * given in every language. Everything around it is a message, and every
   * number is formatted in the page's `lang` (see `$lib/pricing`).
   *
   * **The way in depends on the tier, not on the price.** The self-serve
   * tiers get `ConsoleLink`, which follows the session like every other way
   * into the console; Enterprise is agreed with sales, so it is a `mailto:`.
   *
   * **Enterprise's allowance reads "from".** Its list figure is the floor a
   * contract starts at, and a negotiated allowance can be larger; printing it
   * bare would understate what a customer is actually offered.
   *
   * `level` is the name's heading level, as on `ProductCard`: one under the
   * plans section's `<h2>` is an `h3`.
   */
  interface Props {
    plan: Plan;
    lang: Locale;
    level?: 2 | 3;
  }

  let { plan, lang, level = 3 }: Props = $props();

  const price = $derived(priceLabel(plan, lang));
  const features = $derived(featureLabels(plan.features));
  const ops = $derived({ count: plan.includedOps, ops: formatOps(plan.includedOps, lang) });
</script>

<article class="otto-card flex flex-col gap-5 p-5">
  <svelte:element this={`h${level}`} class="text-lg font-semibold tracking-tight text-ink">
    {plan.displayName}
  </svelte:element>

  <p class="flex flex-wrap items-baseline gap-x-2">
    {#if price.kind === 'contact'}
      <span class="text-2xl font-semibold tracking-tight text-ink">{m.pricing_contact_us()}</span>
    {:else if price.kind === 'free'}
      <span class="text-3xl font-semibold tracking-tight text-ink">{m.pricing_free()}</span>
    {:else}
      <span class="text-3xl font-semibold tracking-tight text-ink">{price.amount}</span>
      <span class="text-sm text-muted">{m.pricing_per_month()}</span>
    {/if}
  </p>

  <div class="flex flex-col gap-1.5 text-sm">
    <p class="font-medium text-ink">
      {plan.plan === 'enterprise' ? m.pricing_included_ops_from(ops) : m.pricing_included_ops(ops)}
    </p>
    <p class="text-muted">
      {plan.hardStop ? m.pricing_overage_hard_stop() : m.pricing_overage_metered()}
    </p>
  </div>

  {#if features.length > 0}
    <ul role="list" aria-label={m.pricing_features_label()} class="flex flex-col gap-2 text-sm">
      {#each features as label, i (i)}
        <li class="flex gap-2.5 text-muted">
          <span class="mt-2 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true"></span>
          <span>{label()}</span>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="mt-auto pt-2">
    {#if plan.plan === 'enterprise'}
      <LinkButton href="mailto:{CONTACT_EMAIL}" tone="quiet" size="md">
        {m.pricing_contact_sales()}
      </LinkButton>
    {:else}
      <ConsoleLink tone={plan.plan === 'free' ? 'quiet' : 'primary'} size="md" />
    {/if}
  </div>
</article>
