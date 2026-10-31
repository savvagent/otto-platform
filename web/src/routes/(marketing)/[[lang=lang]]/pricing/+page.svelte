<script lang="ts">
  import { onMount, tick } from 'svelte';

  import { api } from '$lib/api';
  import { m } from '$lib/paraglide/messages';
  import { parseCatalog, usageByService } from '$lib/pricing';
  import { CONTACT_EMAIL } from '$lib/site';
  import type { PlansResponse } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Seo from '$lib/components/Seo.svelte';
  import PlanCard from '$lib/components/marketing/PlanCard.svelte';
  import ServiceUsage from '$lib/components/marketing/ServiceUsage.svelte';

  import type { PageData } from './$types';

  /**
   * Pricing: how pricing works, prerendered, and the plans and usage prices
   * themselves, live.
   *
   * **The prices are never in the HTML file.** They are read from
   * `GET /api/plans` after mount, which answers from the `plans` table and the
   * price book the server bills against — so a price change is a database
   * change, not a rebuild, and this page cannot advertise a number the meter
   * does not charge. The prerendered file holds the explanation (which is
   * what a crawler indexes); a visitor without JavaScript gets a `<noscript>`
   * line pointing at sales instead.
   *
   * **Two things are priced, separately.** Plans buy features; usage is
   * billed per service by its value meters, the same on every plan. The
   * explanation states only the rules of that model — pay as you go, monthly
   * in arrears, no minimum, management calls free under fair use, a budget
   * per service — and names no rate, allowance or discount: every number on
   * the page comes from the server. A meter with no price is not listed by
   * the server, so a service with none says "no price published yet", and an
   * empty list says prices are still to come, rather than implying free.
   *
   * Every string is a message call in the markup, as on the landing page:
   * the layout's locale override is only guaranteed while this component
   * renders. Numbers are formatted in `data.lang`, not the console's locale.
   */
  let { data }: { data: PageData } = $props();

  type PlansState =
    { status: 'loading' } | { status: 'error' } | ({ status: 'loaded' } & PlansResponse);

  let plans = $state<PlansState>({ status: 'loading' });

  /**
   * False in the prerendered file and during hydration, true from `onMount`.
   *
   * The placeholders and "Loading plans" exist only once script is running.
   * Built into the HTML, they would pulse forever for a visitor without
   * JavaScript, beside a status claiming a load that is never coming; without
   * them the file holds the static copy and the `<noscript>` line. Flipped in
   * `onMount`, after hydration, so the first client render matches the file.
   */
  let mounted = $state(false);

  /** The plans region, focused after a retry so focus is not dropped on `<body>`. */
  let region = $state<HTMLElement | undefined>(undefined);

  /**
   * Bumped by every `load`, so only the newest request may write `plans`: a
   * slow first answer arriving after a retry's must not overwrite it.
   */
  let sequence = 0;
  let destroyed = false;

  /**
   * Fetch, or fetch again after a failure.
   *
   * Any failure is the same "could not be loaded" with a retry: a visitor
   * cannot act on the difference between an outage and a dropped connection,
   * and the server's message is written in English for the console, not for
   * this page's language. A 200 whose body does not match the contract — no
   * `plans` or `meters` array, or a plan or meter with a missing or mistyped
   * field (see `parseCatalog`) — is a failure too, rather than a render that throws or
   * prints `$NaN`. The error itself still goes to the console, so a real bug
   * is not mistaken for an outage by whoever debugs it. An empty list is not
   * a failure (the page points to sales), but it is warned about: the seeded
   * tiers should never all be gone.
   *
   * `focus` is set by the Retry button. The button unmounts the moment the
   * load starts, so without it focus would fall to `<body>`; once the answer
   * is in — plans or the error again — focus moves to the region holding it.
   */
  async function load({ focus = false }: { focus?: boolean } = {}): Promise<void> {
    const mine = ++sequence;
    plans = { status: 'loading' };
    let next: PlansState;
    try {
      const loaded = parseCatalog(await api.plans());
      if (loaded.plans.length === 0) console.warn('pricing: GET /api/plans listed no plans');
      next = { status: 'loaded', ...loaded };
    } catch (error) {
      console.error('pricing: could not load plans', error);
      next = { status: 'error' };
    }
    if (destroyed || mine !== sequence) return;
    plans = next;
    if (focus) {
      await tick();
      region?.focus();
    }
  }

  onMount(() => {
    mounted = true;
    void load();
    return () => {
      destroyed = true;
    };
  });

  /**
   * What the one live region says. It is always in the document, outside the
   * branches below, so a screen reader is already watching it when its text
   * changes; a region created together with its text is often not announced.
   * The error has its own `role="alert"`, so it is not repeated here.
   */
  const status = $derived.by(() => {
    if (!mounted) return '';
    if (plans.status === 'loading') return m.pricing_loading();
    if (plans.status === 'loaded' && plans.plans.length > 0) return m.pricing_loaded();
    return '';
  });

  /** Usage grouped by service, or `null` until the catalog is in. */
  const usage = $derived(plans.status === 'loaded' ? usageByService(plans.meters) : null);

  const how = [
    { title: () => m.pricing_how_payg_title(), body: () => m.pricing_how_payg_body() },
    { title: () => m.pricing_how_free_title(), body: () => m.pricing_how_free_body() },
    { title: () => m.pricing_how_plans_title(), body: () => m.pricing_how_plans_body() },
    { title: () => m.pricing_how_budgets_title(), body: () => m.pricing_how_budgets_body() }
  ];

  const faq = [
    { q: () => m.pricing_faq_minimum_q(), a: () => m.pricing_faq_minimum_a() },
    { q: () => m.pricing_faq_separate_q(), a: () => m.pricing_faq_separate_a() },
    { q: () => m.pricing_faq_budget_q(), a: () => m.pricing_faq_budget_a() },
    { q: () => m.pricing_faq_change_q(), a: () => m.pricing_faq_change_a() },
    { q: () => m.pricing_faq_enterprise_q(), a: () => m.pricing_faq_enterprise_a() }
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
    <p class="sav-label text-accent">{m.pricing_eyebrow()}</p>
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

    <div role="status" class="sr-only">{status}</div>

    <div
      id="plans"
      bind:this={region}
      tabindex="-1"
      aria-labelledby="plans-title"
      class="mt-8 outline-none"
      aria-busy={mounted && plans.status === 'loading' ? 'true' : 'false'}
    >
      {#if !mounted}
        <!-- Prerendered and hydrating: nothing until script can fetch. -->
      {:else if plans.status === 'loading'}
        <ul role="list" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" aria-hidden="true">
          {#each [0, 1, 2, 3] as i (i)}
            <li class="sav-card flex animate-pulse flex-col gap-4 p-5">
              <span class="h-5 w-24 rounded bg-edge/60"></span>
              <span class="h-8 w-20 rounded bg-edge/60"></span>
              <span class="h-4 w-full rounded bg-edge/40"></span>
              <span class="h-4 w-3/4 rounded bg-edge/40"></span>
              <span class="mt-6 h-9 w-32 rounded-md bg-edge/50"></span>
            </li>
          {/each}
        </ul>
      {:else if plans.status === 'error'}
        <div class="flex flex-col items-start gap-3">
          <Alert>{m.pricing_error()}</Alert>
          <Button tone="quiet" onclick={() => void load({ focus: true })}>
            {m.pricing_retry()}
          </Button>
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

  <section aria-labelledby="usage-title">
    <h2 id="usage-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.pricing_usage_heading()}
    </h2>
    <p class="mt-3 max-w-3xl text-muted">{m.pricing_usage_intro()}</p>

    <!--
      Filled by the same request as the plans. A failure is reported once, in
      the plans region above with its Retry, so this region is empty then
      rather than repeating the alert.
    -->
    <div
      id="usage"
      aria-labelledby="usage-title"
      class="mt-8"
      aria-busy={mounted && plans.status === 'loading' ? 'true' : 'false'}
    >
      {#if !mounted || plans.status === 'error'}
        <!-- Prerendered, hydrating, or failed: nothing to show here. -->
      {:else if plans.status === 'loading'}
        <ul role="list" class="grid gap-4 md:grid-cols-2 lg:grid-cols-3" aria-hidden="true">
          {#each [0, 1, 2] as i (i)}
            <li class="sav-card flex animate-pulse flex-col gap-4 p-5">
              <span class="h-5 w-28 rounded bg-edge/60"></span>
              <span class="h-4 w-full rounded bg-edge/40"></span>
              <span class="h-4 w-2/3 rounded bg-edge/40"></span>
            </li>
          {/each}
        </ul>
      {:else if plans.meters.length === 0}
        <p class="sav-card p-5 text-muted">{m.pricing_usage_empty()}</p>
      {:else if usage}
        <ul role="list" class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {#each usage as service (service.service)}
            <li class="grid"><ServiceUsage usage={service} lang={data.lang} level={3} /></li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>

  <section aria-labelledby="how-title">
    <h2 id="how-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.pricing_how_heading()}
    </h2>
    <ul role="list" class="mt-8 grid gap-8 md:grid-cols-2 lg:grid-cols-4">
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
