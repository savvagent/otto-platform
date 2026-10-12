<script lang="ts">
  import { onMount } from 'svelte';

  import { api } from '$lib/api';
  import { m } from '$lib/paraglide/messages';
  import { CONTACT_EMAIL } from '$lib/site';
  import type { Plan } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Seo from '$lib/components/Seo.svelte';
  import PlanCard from '$lib/components/marketing/PlanCard.svelte';

  import type { PageData } from './$types';

  /**
   * Pricing: how plans work, prerendered, and the plans themselves, live.
   *
   * **The prices are never in the HTML file.** They are read from
   * `GET /api/plans` after mount, which answers from the `plans` table the
   * server bills against — so a price change is a database change, not a
   * rebuild, and this page cannot advertise a number the meter does not
   * charge. The prerendered file holds the explanation (which is what a
   * crawler indexes) and the loading placeholders; a visitor without
   * JavaScript gets a `<noscript>` line pointing at sales instead.
   *
   * The explanation is deliberately generic: one plan and one usage bucket
   * per org, what an operation is, and hard stop versus metered overage —
   * each a rule the platform enforces. It names no overage rate, discount or
   * trial, because none exists to point at.
   *
   * Every string is a message call in the markup, as on the landing page:
   * the layout's locale override is only guaranteed while this component
   * renders. Numbers are formatted in `data.lang`, not the console's locale.
   */
  let { data }: { data: PageData } = $props();

  type PlansState =
    { status: 'loading' } | { status: 'error' } | { status: 'loaded'; plans: Plan[] };

  let plans = $state<PlansState>({ status: 'loading' });

  /**
   * Fetch, or fetch again after a failure. Any failure is the same "could
   * not be loaded" with a retry: a visitor cannot act on the difference
   * between an outage and a dropped connection, and the server's message is
   * written in English for the console, not for this page's language.
   */
  async function load(): Promise<void> {
    plans = { status: 'loading' };
    try {
      plans = { status: 'loaded', plans: (await api.plans()).plans };
    } catch {
      plans = { status: 'error' };
    }
  }

  onMount(() => {
    void load();
  });

  const how = [
    { title: () => m.pricing_shared_title(), body: () => m.pricing_shared_body() },
    { title: () => m.pricing_ops_title(), body: () => m.pricing_ops_body() },
    { title: () => m.pricing_overage_title(), body: () => m.pricing_overage_body() }
  ];

  const faq = [
    { q: () => m.pricing_faq_change_q(), a: () => m.pricing_faq_change_a() },
    { q: () => m.pricing_faq_limit_q(), a: () => m.pricing_faq_limit_a() },
    { q: () => m.pricing_faq_enterprise_q(), a: () => m.pricing_faq_enterprise_a() },
    { q: () => m.pricing_faq_shared_q(), a: () => m.pricing_faq_shared_a() }
  ];
</script>

<Seo
  title={m.pricing_title()}
  description={m.pricing_description()}
  path="/pricing"
  lang={data.lang}
/>

{#snippet contact()}
  <a href="mailto:{CONTACT_EMAIL}" class="font-medium break-all text-accent hover:underline"
    >{CONTACT_EMAIL}</a
  >
{/snippet}

<div class="flex flex-col gap-20 pb-10 sm:gap-24">
  <section aria-labelledby="pricing-title" class="max-w-3xl pt-6">
    <p class="otto-label text-accent">{m.pricing_eyebrow()}</p>
    <h1
      id="pricing-title"
      class="mt-3 text-4xl font-semibold tracking-tight text-balance text-ink sm:text-5xl"
    >
      {m.pricing_heading()}
    </h1>
    <p class="mt-6 text-lg text-pretty text-muted">{m.pricing_lead()}</p>
  </section>

  <section aria-labelledby="plans-title">
    <h2 id="plans-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.pricing_plans_heading()}
    </h2>

    <noscript>
      <p class="mt-4 text-muted">{m.pricing_noscript()} {@render contact()}</p>
    </noscript>

    <div id="plans" class="mt-8" aria-busy={plans.status === 'loading' ? 'true' : 'false'}>
      {#if plans.status === 'loading'}
        <div role="status">
          <span class="sr-only">{m.pricing_loading()}</span>
          <ul role="list" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" aria-hidden="true">
            {#each [0, 1, 2, 3] as i (i)}
              <li class="otto-card flex animate-pulse flex-col gap-4 p-5">
                <span class="h-5 w-24 rounded bg-edge/60"></span>
                <span class="h-8 w-20 rounded bg-edge/60"></span>
                <span class="h-4 w-full rounded bg-edge/40"></span>
                <span class="h-4 w-3/4 rounded bg-edge/40"></span>
                <span class="mt-6 h-9 w-32 rounded-md bg-edge/50"></span>
              </li>
            {/each}
          </ul>
        </div>
      {:else if plans.status === 'error'}
        <div class="flex flex-col items-start gap-3">
          <Alert>{m.pricing_error()}</Alert>
          <Button tone="quiet" onclick={() => void load()}>{m.pricing_retry()}</Button>
        </div>
      {:else if plans.plans.length === 0}
        <p class="text-muted">{m.pricing_empty()} {@render contact()}</p>
      {:else}
        <ul role="list" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {#each plans.plans as plan (plan.plan)}
            <li class="grid"><PlanCard {plan} lang={data.lang} level={3} /></li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>

  <section aria-labelledby="how-title">
    <h2 id="how-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.pricing_how_heading()}
    </h2>
    <ul role="list" class="mt-8 grid gap-8 md:grid-cols-3">
      {#each how as item, i (i)}
        <li class="border-l-2 border-accent/60 pl-4">
          <h3 class="font-semibold text-ink">{item.title()}</h3>
          <p class="mt-1.5 text-sm text-muted">{item.body()}</p>
        </li>
      {/each}
    </ul>
  </section>

  <section aria-labelledby="faq-title" class="max-w-3xl">
    <h2 id="faq-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.pricing_faq_heading()}
    </h2>
    <dl class="mt-6 flex flex-col divide-y divide-edge/60">
      {#each faq as entry, i (i)}
        <div class="py-5 first:pt-0">
          <dt class="font-semibold text-ink">{entry.q()}</dt>
          <dd class="mt-2 text-muted">{entry.a()}</dd>
        </div>
      {/each}
    </dl>
    <p class="mt-6 text-muted">{m.pricing_faq_more()} {@render contact()}</p>
  </section>
</div>
