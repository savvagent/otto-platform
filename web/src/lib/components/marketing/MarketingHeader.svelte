<script lang="ts">
  import { page } from '$app/state';

  import type { Locale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { SERVICES } from '$lib/services';
  import { session } from '$lib/session.svelte';
  import { localizedPath } from '$lib/site';
  import Logo from '$lib/components/Logo.svelte';
  import ConsoleLink from './ConsoleLink.svelte';

  /**
   * The marketing pages' header: the logo, the products and pricing, and a
   * way into the console.
   *
   * **The console links are unprefixed and carry `data-sveltekit-reload`.**
   * The console has one URL per page whatever the language (it reads the
   * language from the account, not the path), and crossing from a
   * prerendered marketing page into the browser-only console as a full load
   * means the console boots exactly as it would from a typed URL — its
   * `resolveAtBoot` runs, and nothing from this layout's locale override is
   * still in place.
   *
   * The signed-in variant is decided in the browser only: the file a crawler
   * gets is the signed-out one, and `session` is filled in after mount by the
   * layout.
   */
  interface Props {
    lang: Locale;
  }

  let { lang }: Props = $props();

  const products = $derived(
    SERVICES.map((service) => ({
      href: localizedPath(lang, `/products/${service.slug}`),
      label: service.name
    }))
  );
  const pricing = $derived(localizedPath(lang, '/pricing'));
  const cli = $derived(localizedPath(lang, '/cli'));

  /**
   * The small-screen menu's state, owned here rather than left to the
   * `<details>` alone.
   *
   * Its links are client-side navigations, and a `<details>` has no idea a
   * route changed: without this the next page would load under a menu still
   * open over it. Reading `page.url` is what makes the effect re-run on every
   * navigation; the value itself is not needed.
   */
  let menuOpen = $state(false);
  let menuToggle = $state<HTMLElement>();

  $effect(() => {
    void page.url;
    menuOpen = false;
  });

  /**
   * Escape closes the menu, and focus goes back to the toggle that opened it.
   *
   * Listened for on the window rather than on the `<details>`: a key handler
   * on a non-interactive element is invisible to assistive technology, and an
   * open menu is the only thing on these pages Escape could mean.
   */
  function onMenuKeydown(event: KeyboardEvent) {
    if (event.key !== 'Escape' || !menuOpen) return;
    event.preventDefault();
    menuOpen = false;
    menuToggle?.focus();
  }

  function current(href: string): 'page' | undefined {
    return page.url.pathname === href ? 'page' : undefined;
  }

  // The current page is underlined as well as brighter: colour alone is not
  // a cue everyone can see (WCAG 1.4.1).
  const link =
    'rounded-md px-2.5 py-1.5 text-muted transition hover:bg-raised hover:text-ink aria-[current=page]:text-ink aria-[current=page]:underline aria-[current=page]:decoration-accent aria-[current=page]:underline-offset-4';
</script>

<svelte:window onkeydown={onMenuKeydown} />

<header class="border-b border-edge/60 bg-surface/40">
  <div class="mx-auto flex w-full max-w-6xl items-center gap-2 px-4 py-3 sm:gap-4">
    <a href={localizedPath(lang, '/')} class="flex items-center gap-2" aria-label="Otto">
      <Logo class="size-6 text-accent" />
      <span class="text-sm font-semibold tracking-tight text-ink">Otto</span>
    </a>

    <nav
      class="ml-2 hidden items-center gap-1 text-sm md:flex"
      aria-label={m.marketing_nav_label()}
    >
      {#each products as item (item.href)}
        <a href={item.href} class={link} aria-current={current(item.href)}>{item.label}</a>
      {/each}
      <a href={pricing} class={link} aria-current={current(pricing)}>{m.marketing_nav_pricing()}</a>
      <a href={cli} class={link} aria-current={current(cli)}>{m.marketing_nav_cli()}</a>
    </nav>

    <div class="ml-auto flex items-center gap-2 text-sm">
      {#if !session.signedIn}
        <a href="/login" data-sveltekit-reload class="hidden sm:inline-block {link}">
          {m.nav_sign_in()}
        </a>
      {/if}
      <ConsoleLink size="sm" />

      <!--
        The small-screen menu. A `<details>` rather than a scripted toggle, so
        it opens and closes without JavaScript and announces its state for
        free. "Sign in" lives in here below `sm`, so the bar never has to fit
        three buttons in 360px.
      -->
      <details class="relative md:hidden" bind:open={menuOpen}>
        <summary
          bind:this={menuToggle}
          class="cursor-pointer list-none rounded-md border border-edge px-2.5 py-1.5 text-muted transition select-none hover:bg-raised hover:text-ink [&::-webkit-details-marker]:hidden"
        >
          {m.marketing_nav_menu()}
        </summary>
        <nav
          class="otto-card absolute right-0 z-10 mt-2 flex w-56 flex-col gap-1 bg-surface p-2 shadow-lg"
          aria-label={m.marketing_nav_label()}
        >
          <span class="otto-label px-2.5 pt-1">{m.marketing_nav_products()}</span>
          {#each products as item (item.href)}
            <a href={item.href} class={link} aria-current={current(item.href)}>{item.label}</a>
          {/each}
          <hr class="my-1 border-edge/60" />
          <a href={pricing} class={link} aria-current={current(pricing)}>
            {m.marketing_nav_pricing()}
          </a>
          <a href={cli} class={link} aria-current={current(cli)}>{m.marketing_nav_cli()}</a>
          {#if !session.signedIn}
            <a href="/login" data-sveltekit-reload class="sm:hidden {link}">{m.nav_sign_in()}</a>
          {/if}
        </nav>
      </details>
    </div>
  </div>
</header>
