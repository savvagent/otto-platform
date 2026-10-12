<script lang="ts">
  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import type { Service } from '$lib/services';
  import { localizedPath } from '$lib/site';

  /**
   * One product, as a card that links to its page in the current language.
   *
   * The link text names the product ("More about Otto Flags") rather than a
   * bare "Learn more", so a screen reader's list of links is not five
   * identical entries.
   *
   * `level` is the name's heading level, which depends on where the card is
   * placed: one under the page's `<h1>` is an `h2`, one inside a section
   * with its own `<h2>` is an `h3`. A fixed level would skip one somewhere,
   * and a screen reader's heading list would show a gap.
   */
  interface Props {
    service: Service;
    lang: Locale;
    level?: 2 | 3;
  }

  let { service, lang, level = 3 }: Props = $props();
</script>

<article class="otto-card flex flex-col gap-3 p-5">
  <svelte:element this={`h${level}`} class="text-lg font-semibold tracking-tight text-ink">
    {service.name}
  </svelte:element>
  <p class="flex-1 text-sm text-muted">{service.copy.tagline()}</p>
  <a
    href={localizedPath(lang, `/products/${service.slug}`)}
    class="text-sm font-medium text-accent hover:underline"
  >
    {m.marketing_product_more({ name: service.name })}
    <span aria-hidden="true">→</span>
  </a>
</article>
