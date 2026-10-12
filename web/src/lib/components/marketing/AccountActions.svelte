<script lang="ts">
  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { localizedPath } from '$lib/site';
  import LinkButton from '$lib/components/LinkButton.svelte';
  import ConsoleLink from './ConsoleLink.svelte';

  /**
   * The landing page's pair of calls to action: the way into the console
   * (see `ConsoleLink` for how it follows the session), and pricing.
   *
   * Pricing is a marketing page in this page's language, so it is an
   * ordinary client-side link.
   */
  interface Props {
    lang: Locale;
  }

  let { lang }: Props = $props();
</script>

<div class="flex flex-wrap items-center gap-3">
  <ConsoleLink />
  <LinkButton href={localizedPath(lang, '/pricing')} tone="quiet" size="lg">
    {m.landing_see_pricing()}
  </LinkButton>
</div>
