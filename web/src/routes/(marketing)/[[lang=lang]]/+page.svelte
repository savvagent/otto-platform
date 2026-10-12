<script lang="ts">
  import { m } from '$lib/paraglide/messages';
  import { SERVICES } from '$lib/services';
  import Logo from '$lib/components/Logo.svelte';
  import Seo from '$lib/components/Seo.svelte';
  import AccountActions from '$lib/components/marketing/AccountActions.svelte';
  import ProductCard from '$lib/components/marketing/ProductCard.svelte';

  import type { PageData } from './$types';

  /**
   * The landing page: what the otto-* family is, which services are in it,
   * what one account buys you across all of them, and how an agent gets
   * connected.
   *
   * Every string is a message call in the markup, never a constant in the
   * script: the layout's locale override is what makes `m.*()` speak this
   * page's language, and it is only guaranteed in place while this component
   * renders.
   *
   * The family's claims are each one sentence of fact the platform enforces
   * — OIDC SSO (there is no SAML), one plan and one usage bucket per org,
   * audience-bound tokens — so a translation can be checked against the code
   * rather than against a slogan.
   *
   * Lists drawn without bullets carry `role="list"`: Safari drops list
   * semantics from a `<ul>`/`<ol>` whose markers are removed by CSS, and
   * VoiceOver then stops announcing "list, 3 items".
   */
  let { data }: { data: PageData } = $props();

  const family = [
    { title: () => m.landing_family_signin_title(), body: () => m.landing_family_signin_body() },
    { title: () => m.landing_family_org_title(), body: () => m.landing_family_org_body() },
    { title: () => m.landing_family_plan_title(), body: () => m.landing_family_plan_body() },
    { title: () => m.landing_family_tokens_title(), body: () => m.landing_family_tokens_body() }
  ];

  const steps = [
    { title: () => m.landing_how_step1_title(), body: () => m.landing_how_step1_body() },
    { title: () => m.landing_how_step2_title(), body: () => m.landing_how_step2_body() },
    { title: () => m.landing_how_step3_title(), body: () => m.landing_how_step3_body() }
  ];
</script>

<Seo
  title={m.marketing_home_title()}
  description={m.marketing_home_description()}
  path="/"
  lang={data.lang}
/>

<div class="flex flex-col gap-24 pb-10 sm:gap-32">
  <section
    aria-labelledby="hero-title"
    class="grid items-center gap-12 pt-6 lg:grid-cols-[3fr_2fr]"
  >
    <div>
      <p class="otto-label text-accent">{m.landing_hero_eyebrow()}</p>
      <h1
        id="hero-title"
        class="mt-3 text-4xl font-semibold tracking-tight text-balance text-ink sm:text-5xl"
      >
        {m.landing_hero_title()}
      </h1>
      <p class="mt-6 max-w-2xl text-lg text-pretty text-muted">{m.landing_hero_subtitle()}</p>
      <div class="mt-8">
        <AccountActions lang={data.lang} />
      </div>
    </div>

    <!--
      The endpoints themselves, in config-file monospace: the quickest way to
      say "this is a URL you paste into a tool". It is not any particular
      client's config format (each agent spells that differently), only the
      service-to-URL pairs. Decorative — each URL is on its product page with
      a copy button — so hidden from assistive technology rather than read
      out twice.
    -->
    <div class="otto-card relative overflow-hidden p-5" aria-hidden="true">
      <Logo class="absolute -right-8 -bottom-10 size-40 text-accent/10" />
      <div class="flex gap-1.5">
        <span class="size-2.5 rounded-full bg-edge"></span>
        <span class="size-2.5 rounded-full bg-edge"></span>
        <span class="size-2.5 rounded-full bg-edge"></span>
      </div>
      <ul class="relative mt-4 flex flex-col gap-3 font-mono text-xs sm:text-sm">
        {#each SERVICES as service (service.slug)}
          {#if service.mcpUrl}
            <li>
              <span class="text-muted">"{service.slug}":</span>
              <span class="block pl-4 break-all text-accent">"{service.mcpUrl}"</span>
            </li>
          {/if}
        {/each}
      </ul>
    </div>
  </section>

  <section aria-labelledby="products-title">
    <h2 id="products-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.landing_products_heading()}
    </h2>
    <p class="mt-2 max-w-2xl text-muted">{m.landing_products_intro()}</p>
    <ul role="list" class="mt-8 grid gap-4 sm:grid-cols-2">
      {#each SERVICES as service (service.slug)}
        <li class="grid"><ProductCard {service} lang={data.lang} level={3} /></li>
      {/each}
    </ul>
  </section>

  <section aria-labelledby="family-title" class="grid gap-10 lg:grid-cols-[2fr_3fr]">
    <div>
      <h2 id="family-title" class="text-2xl font-semibold tracking-tight text-ink">
        {m.landing_family_heading()}
      </h2>
      <p class="mt-3 text-muted">{m.landing_family_intro()}</p>
    </div>
    <ul role="list" class="grid gap-x-8 gap-y-8 sm:grid-cols-2">
      {#each family as item, i (i)}
        <li class="border-l-2 border-accent/60 pl-4">
          <h3 class="font-semibold text-ink">{item.title()}</h3>
          <p class="mt-1.5 text-sm text-muted">{item.body()}</p>
        </li>
      {/each}
    </ul>
  </section>

  <section aria-labelledby="how-title">
    <h2 id="how-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.landing_how_heading()}
    </h2>
    <ol role="list" class="mt-8 grid gap-4 md:grid-cols-3">
      {#each steps as step, i (i)}
        <li class="otto-card flex flex-col gap-3 p-5">
          <span
            class="flex size-8 items-center justify-center rounded-full border border-accent/60 font-mono text-sm text-accent"
            aria-hidden="true">{i + 1}</span
          >
          <h3 class="font-semibold text-ink">{step.title()}</h3>
          <p class="text-sm text-muted">{step.body()}</p>
        </li>
      {/each}
    </ol>
  </section>

  <section
    aria-labelledby="cta-title"
    class="otto-card flex flex-col gap-6 bg-raised/40 p-8 sm:p-10 lg:flex-row lg:items-center lg:justify-between"
  >
    <div class="max-w-xl">
      <h2 id="cta-title" class="text-2xl font-semibold tracking-tight text-ink">
        {m.landing_cta_heading()}
      </h2>
      <p class="mt-2 text-muted">{m.landing_cta_body()}</p>
    </div>
    <AccountActions lang={data.lang} />
  </section>
</div>
