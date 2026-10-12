<script lang="ts">
  import { m } from '$lib/paraglide/messages';
  import { SERVICES } from '$lib/services';
  import { localizedPath } from '$lib/site';
  import CopyField from '$lib/components/CopyField.svelte';
  import Seo from '$lib/components/Seo.svelte';
  import ProductCard from '$lib/components/marketing/ProductCard.svelte';

  import type { PageData } from './$types';

  /**
   * One product: what it is, what it does, how to point an agent at it, and
   * the way into its own console.
   *
   * `load` has already turned an unknown slug into a 404, so the lookup here
   * cannot miss; it is repeated rather than passed down because the copy is
   * functions that must be called while this component renders (see
   * `+page.ts`).
   *
   * **"Open {name}" leaves this origin.** The service's console is on its own
   * host, so the link is a full navigation by nature and needs no
   * `data-sveltekit-reload`; `rel="noopener"` keeps the other origin from
   * reaching back through `window.opener`. "Create account" is the console
   * here, and does carry the reload attribute.
   */
  let { data }: { data: PageData } = $props();

  const service = $derived(SERVICES.find((candidate) => candidate.slug === data.slug)!);
  const others = $derived(SERVICES.filter((candidate) => candidate.slug !== data.slug));

  const base =
    'inline-flex items-center justify-center rounded-md px-5 py-2.5 text-sm font-medium transition';
</script>

<Seo
  title={m.product_page_title({ name: service.name, tagline: service.copy.tagline() })}
  description={service.copy.summary()}
  path="/products/{service.slug}"
  lang={data.lang}
/>

<div class="flex flex-col gap-20 pb-10 sm:gap-24">
  <section aria-labelledby="product-title" class="max-w-3xl pt-6">
    <p class="otto-label text-accent">{m.landing_hero_eyebrow()}</p>
    <h1 id="product-title" class="mt-3 text-4xl font-semibold tracking-tight text-ink sm:text-5xl">
      {service.name}
    </h1>
    <p class="mt-4 text-xl text-pretty text-ink">{service.copy.tagline()}</p>
    <p class="mt-4 text-lg text-pretty text-muted">{service.copy.summary()}</p>
    <div class="mt-8 flex flex-wrap items-center gap-3">
      <a
        href={service.url}
        rel="noopener"
        class="{base} bg-accent text-accent-ink hover:brightness-110"
      >
        {m.product_open({ name: service.name })}
      </a>
      <a
        href="/signup"
        data-sveltekit-reload
        class="{base} border border-edge bg-raised/60 text-ink hover:bg-raised"
      >
        {m.marketing_create_account()}
      </a>
    </div>
  </section>

  <div class="grid gap-12 lg:grid-cols-2">
    <section aria-labelledby="features-title">
      <h2 id="features-title" class="text-2xl font-semibold tracking-tight text-ink">
        {m.product_features_heading()}
      </h2>
      <ul class="mt-6 flex flex-col gap-4">
        {#each service.copy.features() as feature, i (i)}
          <li class="flex gap-3 text-muted">
            <span class="mt-2 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true"></span>
            <span>{feature}</span>
          </li>
        {/each}
      </ul>
    </section>

    {#if service.mcpUrl}
      <section aria-labelledby="connect-title" class="otto-card self-start p-6">
        <h2 id="connect-title" class="text-2xl font-semibold tracking-tight text-ink">
          {m.product_connect_heading()}
        </h2>
        <p class="mt-2 text-sm text-muted">{m.product_connect_body()}</p>
        <div class="mt-5">
          <CopyField value={service.mcpUrl} label={m.product_mcp_label()} />
        </div>
      </section>
    {/if}
  </div>

  <p>
    <a href={localizedPath(data.lang, '/pricing')} class="font-medium text-accent hover:underline">
      {m.product_pricing_link()} <span aria-hidden="true">→</span>
    </a>
  </p>

  {#if others.length > 0}
    <section aria-labelledby="others-title">
      <h2 id="others-title" class="text-2xl font-semibold tracking-tight text-ink">
        {m.product_others_heading()}
      </h2>
      <ul class="mt-6 grid gap-4 sm:grid-cols-2">
        {#each others as other (other.slug)}
          <li class="grid"><ProductCard service={other} lang={data.lang} /></li>
        {/each}
      </ul>
    </section>
  {/if}
</div>
