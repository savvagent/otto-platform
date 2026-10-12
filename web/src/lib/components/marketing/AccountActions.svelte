<script lang="ts">
  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import { localizedPath } from '$lib/site';

  /**
   * The landing page's pair of calls to action: a way into the console, and
   * pricing.
   *
   * **Signed out in the file, signed in after hydration.** The prerendered
   * HTML is built once for everyone, so it can only ever say "Create
   * account"; the marketing layout resolves `session` after mount, and this
   * swaps to "Open console" the moment it does — the same rule, and the same
   * destination, as `MarketingHeader`. A visitor whose session check fails
   * keeps the signed-out links, which still work.
   *
   * The console links are unprefixed and carry `data-sveltekit-reload` for
   * the header's reason: the console is browser-only and must boot from a
   * full load. Pricing is a marketing page in this page's language, so it is
   * an ordinary client-side link.
   */
  interface Props {
    lang: Locale;
  }

  let { lang }: Props = $props();

  const consoleHref = $derived(session.homeOrg ? `/o/${session.homeOrg}` : '/orgs/new');

  const base =
    'inline-flex items-center justify-center rounded-md px-5 py-2.5 text-sm font-medium transition';
  const primary = `${base} bg-accent text-accent-ink hover:brightness-110`;
  const quiet = `${base} border border-edge bg-raised/60 text-ink hover:bg-raised`;
</script>

<div class="flex flex-wrap items-center gap-3">
  {#if session.signedIn}
    <a href={consoleHref} data-sveltekit-reload class={primary}>{m.marketing_open_console()}</a>
  {:else}
    <a href="/signup" data-sveltekit-reload class={primary}>{m.marketing_create_account()}</a>
  {/if}
  <a href={localizedPath(lang, '/pricing')} class={quiet}>{m.landing_see_pricing()}</a>
</div>
