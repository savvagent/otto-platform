<script lang="ts">
  import { onMount } from 'svelte';

  import { m } from '$lib/paraglide/messages';
  import { SERVICES, claudeCodeCommand, serviceBySlug } from '$lib/services';
  import { consoleEntry, session } from '$lib/session.svelte';
  import { localizedPath } from '$lib/site';
  import CopyField from '$lib/components/CopyField.svelte';
  import LinkButton from '$lib/components/LinkButton.svelte';
  import Seo from '$lib/components/Seo.svelte';
  import ConsoleLink from '$lib/components/marketing/ConsoleLink.svelte';
  import ProductCard from '$lib/components/marketing/ProductCard.svelte';

  import type { PageData } from './$types';

  /**
   * One product: what it is, what it does, how to point an agent at it, and
   * the way into its own console, if it has one.
   *
   * `load` has already turned an unknown slug into a 404, so the lookup here
   * cannot miss; it is repeated rather than passed down because the copy is
   * functions that must be called while this component renders (see
   * `+page.ts`). The `{#if}` is for the type checker, not for a real case.
   *
   * **Two consoles, and the page says which is which.** "Open the {name}
   * console" goes to the service's own console on its own host — a full
   * navigation by nature, so it needs no `data-sveltekit-reload` — and its
   * text names the destination, with an arrow (hidden from assistive
   * technology, which already hears the name) marking it as leaving this
   * site. The second button is this site's account console, through
   * `ConsoleLink`, so it follows the session like the header's.
   *
   * **A product with no console of its own says so, rather than linking to
   * its origin.** Otto Flags and Otto CXP answer a browser with a JSON 404:
   * the place a person uses them is their AI assistant. So for a service
   * without `consoleUrl` the primary button is "Add to your AI assistant", an
   * in-page link to the connect card, and one line under the buttons says
   * there is no web console and where usage and billing are instead. That
   * line's "Otto console" goes where `ConsoleLink` goes (`consoleEntry`), with
   * the same `data-sveltekit-reload`. There is no disabled "coming soon"
   * button: a control that does nothing is a dead end with better manners.
   *
   * **Arriving at the connect card moves focus to it.** A fragment link only
   * scrolls, and a keyboard or screen-reader user who followed it would still
   * be on the button, with the next Tab going to whatever came after it. The
   * card is `tabindex="-1"` (focusable by script, not a Tab stop) and is
   * focused on the button's click, on a `hashchange` to `#connect`, and on
   * mount when the page was opened at `#connect` — which is how the console's
   * Services links arrive. The brief accent outline that marks the landing
   * is in the component styles at the end of this file.
   */
  let { data }: { data: PageData } = $props();

  const service = $derived(serviceBySlug(data.slug));
  const others = $derived(SERVICES.filter((candidate) => candidate.slug !== data.slug));
  const ottoConsole = $derived(consoleEntry(session));
  const command = $derived(service ? claudeCodeCommand(service) : undefined);

  /**
   * "Usage and billing are in your {console}." around a link.
   *
   * The sentence is one message, so each language puts the link where its own
   * word order wants it (Hindi's comes before the verb); a sentinel stands in
   * for it and the two halves are rendered either side of the link. A
   * sentence built from "before" and "after" messages would fix the English
   * order in every language.
   */
  const LINK = '\u0000';
  const billing = $derived(m.product_agent_only_billing({ console: LINK }).split(LINK));

  let connect = $state<HTMLElement | undefined>(undefined);

  function focusConnect() {
    connect?.focus();
  }

  function onHashChange() {
    if (location.hash === '#connect') focusConnect();
  }

  onMount(onHashChange);
</script>

<svelte:window onhashchange={onHashChange} />

{#if service}
  <Seo
    title={m.product_page_title({ name: service.name, title: service.copy.title() })}
    description={service.copy.description()}
    path="/products/{service.slug}"
    lang={data.lang}
  />

  <div class="flex flex-col gap-20 pb-10 sm:gap-24">
    <section aria-labelledby="product-title" class="max-w-3xl pt-6">
      <p class="otto-label text-accent">{m.product_eyebrow()}</p>
      <h1
        id="product-title"
        class="mt-3 text-4xl font-semibold tracking-tight text-ink sm:text-5xl"
      >
        {service.name}
      </h1>
      <p class="mt-4 text-xl text-pretty text-ink">{service.copy.tagline()}</p>
      <p class="mt-4 text-lg text-pretty text-muted">{service.copy.summary()}</p>
      <div class="mt-8 flex flex-wrap items-center gap-3">
        {#if service.consoleUrl}
          <LinkButton href={service.consoleUrl} size="lg">
            {m.product_open_console({ name: service.name })}
            <span aria-hidden="true">↗</span>
          </LinkButton>
        {:else if service.mcpUrl}
          <LinkButton href="#connect" size="lg" onclick={focusConnect}>
            {m.product_add_to_assistant()}
          </LinkButton>
        {/if}
        <ConsoleLink tone="quiet" />
      </div>
      {#if !service.consoleUrl && service.mcpUrl}
        <p class="mt-4 text-sm text-pretty text-muted">
          {m.product_agent_only_note({ name: service.name })}
          {billing[0]}<a
            href={ottoConsole.href}
            class="font-medium text-accent hover:underline"
            data-sveltekit-reload>{m.product_otto_console()}</a
          >{billing[1]}
        </p>
      {/if}
    </section>

    <div class="grid gap-12 lg:grid-cols-2">
      <section aria-labelledby="features-title">
        <h2 id="features-title" class="text-2xl font-semibold tracking-tight text-ink">
          {m.product_features_heading()}
        </h2>
        <ul role="list" class="mt-6 flex flex-col gap-4">
          {#each service.copy.features() as feature, i (i)}
            <li class="flex gap-3 text-muted">
              <span class="mt-2 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true"></span>
              <span>{feature}</span>
            </li>
          {/each}
        </ul>
      </section>

      {#if service.mcpUrl}
        <!--
          How to add the service to the assistants people actually use, one
          short paragraph each. The client names are products, so they are not
          translated; the steps are. Shown for every service with an endpoint,
          a web console or not: Factory's agents connect the same way.
        -->
        <section
          id="connect"
          tabindex="-1"
          bind:this={connect}
          aria-labelledby="connect-title"
          class="connect otto-card scroll-mt-6 self-start p-6"
        >
          <h2 id="connect-title" class="text-2xl font-semibold tracking-tight text-ink">
            {m.product_connect_heading()}
          </h2>
          <p class="mt-2 text-sm text-muted">{m.product_connect_body()}</p>
          <div class="mt-5">
            <CopyField value={service.mcpUrl} label={m.product_connector_address_label()} />
          </div>

          <div class="mt-6 flex flex-col gap-5 text-sm">
            <div>
              <h3 class="font-semibold text-ink">{m.product_setup_claude_heading()}</h3>
              <p class="mt-1 text-muted">{m.product_setup_claude()}</p>
            </div>
            <div>
              <h3 class="font-semibold text-ink">ChatGPT</h3>
              <p class="mt-1 text-muted">{m.product_setup_chatgpt()}</p>
            </div>
            {#if command}
              <div>
                <h3 class="font-semibold text-ink">Claude Code</h3>
                <div class="mt-2">
                  <CopyField value={command} label={m.product_setup_claude_code_label()} />
                </div>
                <p class="mt-2 text-muted">{m.product_setup_claude_code()}</p>
              </div>
            {/if}
          </div>
        </section>
      {/if}
    </div>

    <p>
      <a
        href={localizedPath(data.lang, '/pricing')}
        class="font-medium text-accent hover:underline"
      >
        {m.product_pricing_link()} <span aria-hidden="true">→</span>
      </a>
    </p>

    {#if others.length > 0}
      <section aria-labelledby="others-title">
        <h2 id="others-title" class="text-2xl font-semibold tracking-tight text-ink">
          {m.product_others_heading()}
        </h2>
        <ul role="list" class="mt-6 grid gap-4 sm:grid-cols-2">
          {#each others as other (other.slug)}
            <li class="grid"><ProductCard service={other} lang={data.lang} level={3} /></li>
          {/each}
        </ul>
      </section>
    {/if}
  </div>
{/if}

<style>
  /*
    The landing mark on the connect card: an accent outline that fades over a
    couple of seconds, so arriving says "here" without leaving a ring around
    the card for as long as it holds focus. `:focus` rather than
    `:focus-visible`, because the focus is always set by script and a browser
    may decide a scripted focus after a mouse click is not "visible".

    With reduced motion the outline does not fade: it stays while the card is
    focused and goes when focus moves on, which is a change of state, not an
    animation.
  */
  .connect:focus {
    outline: 2px solid var(--color-accent);
    outline-offset: 4px;
    animation: connect-arrival 2.4s ease-out forwards;
  }

  @keyframes connect-arrival {
    0%,
    50% {
      outline-color: var(--color-accent);
    }
    100% {
      outline-color: transparent;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .connect:focus {
      animation: none;
    }
  }
</style>
