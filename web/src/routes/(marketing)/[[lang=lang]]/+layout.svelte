<script lang="ts">
  import { onMount, type Snippet } from 'svelte';

  import { page } from '$app/state';

  import { LOCALE_NAMES, detect, readCached, type Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { overwriteGetLocale } from '$lib/paraglide/runtime';
  import { session } from '$lib/session.svelte';
  import { localizedPath, stripLocale } from '$lib/site';
  import MarketingFooter from '$lib/components/marketing/MarketingFooter.svelte';
  import MarketingHeader from '$lib/components/marketing/MarketingHeader.svelte';

  import type { LayoutData } from './$types';

  let { data, children }: { data: LayoutData; children: Snippet } = $props();

  /**
   * Every `m.*()` below this layout speaks the URL's language.
   *
   * Top-level, so it is in place before any child renders. The override is a
   * process-wide global, which is safe at build time because Svelte 5 renders
   * a page synchronously from top to bottom: no other page's render can start
   * between this line and the last message call of this one, so every message
   * in this page reads this page's `lang`. That is also why no `load` may call
   * a message (see `+layout.ts`) — loads are async and can interleave.
   *
   * In the browser the closure reads the current prop, and a language change
   * is a full document load anyway (`data-sveltekit-reload` on every link that
   * changes it).
   */
  overwriteGetLocale(() => data.lang);

  /** A language this visitor seems to prefer over English, if any. */
  let hint = $state<Locale | undefined>(undefined);

  onMount(() => {
    /**
     * Signed in? Asked only in the browser, after the prerendered page is
     * showing. Any failure — no server in `vite dev`, an outage, a network
     * error — leaves the signed-out links, which still work.
     *
     * `$lib/session.svelte` and `$lib/api` are imported statically: neither
     * touches a browser global at module scope (one builds a `$state` object,
     * the other defines functions), so both are safe in the build's render.
     */
    session.refresh().catch(() => {});

    // English pages only, and only an offer: nothing is stored, and the next
    // page asks again. The visitor's own choice of URL wins.
    if (data.lang === 'en') {
      const preferred = readCached() ?? detect();
      if (preferred !== 'en') hint = preferred;
    }
  });

  const basePath = $derived(stripLocale(page.url.pathname).path);
</script>

<div class="flex min-h-full flex-col">
  <a
    href="#main"
    class="sr-only z-20 rounded-md bg-accent px-3 py-2 text-sm font-medium text-accent-ink focus:not-sr-only focus:absolute focus:top-2 focus:left-2"
  >
    {m.marketing_skip_to_content()}
  </a>

  {#if hint}
    <!-- In the suggested language, since it is addressed to someone who reads it. -->
    <div class="border-b border-edge/40 bg-raised/50 px-4 py-2 text-sm" lang={hint}>
      <div class="mx-auto flex w-full max-w-6xl items-center gap-3">
        <a
          href={localizedPath(hint, basePath)}
          hreflang={hint}
          data-sveltekit-reload
          class="text-accent hover:underline"
        >
          {m.marketing_locale_hint({ language: LOCALE_NAMES[hint] }, { locale: hint })}
        </a>
        <button
          type="button"
          class="ml-auto text-muted hover:text-ink"
          onclick={() => (hint = undefined)}
        >
          {m.marketing_locale_hint_dismiss({}, { locale: hint })}
        </button>
      </div>
    </div>
  {/if}

  <MarketingHeader lang={data.lang} />

  <main id="main" tabindex="-1" class="mx-auto w-full max-w-6xl flex-1 px-4 py-10">
    {@render children()}
  </main>

  <MarketingFooter lang={data.lang} />
</div>
