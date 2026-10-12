<script lang="ts">
  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { MARKETING_LOCALES, OG_LOCALES, SITE_ORIGIN, alternates, localizedPath } from '$lib/site';

  /**
   * A marketing page's head: title, description, canonical URL, every
   * language's alternate, and the Open Graph / Twitter tags a link preview
   * reads.
   *
   * `path` is the page's **English** path (`/pricing`), not the URL it is
   * served at; the canonical and the alternates are derived from it through
   * `localizedPath`, so every language version of a page declares the same
   * set of siblings and each one names itself as canonical.
   *
   * `index, follow` is spelled out rather than left as the default because
   * the console emits `noindex` from its own layout, and an explicit value
   * here is what `scripts/check-build.mjs` asserts on.
   *
   * `og:locale:alternate` lists every *other* language this page exists in,
   * so a link preview can pick the reader's; the page's own is `og:locale`.
   */
  interface Props {
    title: string;
    description: string;
    path: string;
    lang: Locale;
  }

  let { title, description, path, lang }: Props = $props();

  const canonical = $derived(SITE_ORIGIN + localizedPath(lang, path));
  const links = $derived(alternates(path));
  const otherLocales = $derived(MARKETING_LOCALES.filter((locale) => locale !== lang));
</script>

<svelte:head>
  <title>{title}</title>
  <meta name="description" content={description} />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href={canonical} />
  {#each links as link (link.hreflang)}
    <link rel="alternate" hreflang={link.hreflang} href={link.href} />
  {/each}
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Otto" />
  <meta property="og:title" content={title} />
  <meta property="og:description" content={description} />
  <meta property="og:url" content={canonical} />
  <meta property="og:image" content="{SITE_ORIGIN}/favicon-512x512.png" />
  <meta property="og:image:alt" content={m.marketing_og_image_alt()} />
  <meta property="og:locale" content={OG_LOCALES[lang]} />
  {#each otherLocales as locale (locale)}
    <meta property="og:locale:alternate" content={OG_LOCALES[locale]} />
  {/each}
  <meta name="twitter:card" content="summary" />
</svelte:head>
