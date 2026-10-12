<script lang="ts">
  import { m } from '$lib/paraglide/messages';
  import { SERVICES } from '$lib/services';
  import Seo from '$lib/components/Seo.svelte';
  import ProductCard from '$lib/components/marketing/ProductCard.svelte';

  import type { PageData } from './$types';

  /**
   * A placeholder landing page: a heading, one sentence and the products, in
   * the page's language and with its full head. The real page replaces it.
   */
  let { data }: { data: PageData } = $props();
</script>

<Seo
  title={m.marketing_home_title()}
  description={m.marketing_home_description()}
  path="/"
  lang={data.lang}
/>

<h1 class="text-3xl font-semibold tracking-tight text-ink">{m.marketing_home_title()}</h1>
<p class="mt-3 max-w-2xl text-muted">{m.marketing_home_description()}</p>

<div class="mt-8 grid gap-4 sm:grid-cols-2">
  {#each SERVICES as service (service.slug)}
    <ProductCard {service} lang={data.lang} />
  {/each}
</div>
