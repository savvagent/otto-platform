<script lang="ts">
  import { page } from '$app/state';

  import { LOCALE_NAMES, type Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { CONTACT_EMAIL, MARKETING_LOCALES, localizedPath, stripLocale } from '$lib/site';
  import { APP_VERSION } from '$lib/version';

  /**
   * The marketing pages' footer: the language switcher, the API reference,
   * the version and a contact address.
   *
   * **Each language link is this page in that language**, not that
   * language's home page: the current path is stripped of its prefix and
   * re-localized. Every one carries `data-sveltekit-reload`, because a
   * language change reloads the document (Paraglide's `m.*()` are plain
   * calls, so a client-side navigation would leave the layout speaking the
   * old language).
   *
   * **The API reference is `rel="external"`, and must stay so.** The
   * prerender crawler follows every same-origin link it sees, there is no
   * `/api` at build time, and a 404 fails the build. `rel="external"` is how
   * SvelteKit is told a link leaves the app — which, being served by the
   * Rust server, it does.
   */
  interface Props {
    lang: Locale;
  }

  let { lang }: Props = $props();

  const basePath = $derived(stripLocale(page.url.pathname).path);
</script>

<footer class="border-t border-edge/40 px-4 py-6 text-xs text-muted">
  <div class="mx-auto flex w-full max-w-6xl flex-col gap-4">
    <nav aria-label={m.marketing_footer_language()}>
      <ul class="flex flex-wrap gap-x-3 gap-y-2">
        {#each MARKETING_LOCALES as locale (locale)}
          <li>
            <a
              href={localizedPath(locale, basePath)}
              hreflang={locale}
              lang={locale}
              data-sveltekit-reload
              aria-current={locale === lang ? 'true' : undefined}
              class="hover:text-ink aria-[current=true]:font-medium aria-[current=true]:text-ink"
            >
              {LOCALE_NAMES[locale]}
            </a>
          </li>
        {/each}
      </ul>
    </nav>

    <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
      <a class="hover:text-ink" href="/api/openapi.json" rel="external">{m.nav_api_reference()}</a>
      <span aria-hidden="true">·</span>
      <span>
        {m.marketing_footer_contact()}:
        <a class="hover:text-ink" href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a>
      </span>
      <span aria-hidden="true">·</span>
      <span>v{APP_VERSION}</span>
    </div>
  </div>
</footer>
