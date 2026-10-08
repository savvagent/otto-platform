<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import type { Snippet } from 'svelte';

  import '../app.css';
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { reconcile, resolveAtBoot } from '$lib/locale';
  import { isServerRoute, safeNext } from '$lib/next';
  import { session } from '$lib/session.svelte';
  import { SERVICES } from '$lib/services';
  import { APP_VERSION } from '$lib/version';
  import Alert from '$lib/components/Alert.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import Logo from '$lib/components/Logo.svelte';

  /**
   * Decide the language before anything renders.
   *
   * Top-level in this script rather than in `+layout.ts`, because `ssr = false`
   * makes this file browser-only while a universal load module is also
   * evaluated by the static build — where `document` and `localStorage` do not
   * exist. It runs once, synchronously, ahead of the first paint, so no page
   * ever renders English and then snaps to Spanish.
   */
  resolveAtBoot();

  let { children }: { children: Snippet } = $props();

  /** A failure resolving the session that is *not* "signed out". */
  let fatal = $state<string | undefined>(undefined);
  let signingOut = $state(false);

  /**
   * Pages reachable without a session.
   *
   * Just the doors. `/signup` carries the whole account-creation flow now —
   * address, recovery codes, and authenticator enrollment in one visit — because
   * there is no email and so no second visit to come back from.
   *
   * `/invite/…` is deliberately *not* here: redeeming an invitation requires a
   * session whose address matches the one invited, so it sends the visitor to
   * sign in first. That check is what keeps a code that goes astray from being
   * a free seat.
   */
  const PUBLIC = ['/login', '/signup', '/claim'];

  const isPublic = $derived(PUBLIC.some((p) => page.url.pathname === p));

  $effect(() => {
    void resolve();
  });

  async function resolve() {
    if (session.ready) return;
    try {
      await session.refresh();
    } catch (error) {
      fatal = messageFor(error, m.error_session_resolve_failed());
    }
  }

  /**
   * Apply the account's stored language whenever the session resolves.
   *
   * **An effect over `session.me`, not a line inside `resolve()`.** `resolve()`
   * runs exactly once, on mount, and returns early forever after; every other
   * path that establishes a session — signing in, signing up, redeeming a
   * claim code or an invitation, and the settings page — calls
   * `session.refresh()` directly and would never reach it. Reading
   * `session.me` here makes this re-run for all of them.
   *
   * That is not a tidiness point: the case this whole mechanism exists for is
   * **the first sign-in on a new device**, where the cache is empty and the
   * browser's language differs from the account's. That is precisely the path
   * `resolve()` cannot see, because the session became ready while the visitor
   * was still signed out.
   *
   * `reconcile` no-ops unless the stored choice differs from what is rendering,
   * so running it on every change is free — and it reloads at most once when
   * they do differ, for the reason its own comment gives.
   */
  $effect(() => {
    reconcile(session.me?.user.locale);
  });

  /**
   * The routing guard, in one place.
   *
   * Written as an effect over `session.ready` and the current path rather than
   * as a check in each page: a page that forgets is a page that renders a
   * skeleton to a signed-out visitor and then flashes it away, and the
   * enrollment gate in particular has to hold everywhere at once — an account
   * with no confirmed authenticator can reach the API, so leaving one route
   * ungated would leave a usable console behind a half-finished login.
   */
  $effect(() => {
    // `signingOut` suppresses the guard for the moment between clearing the
    // session and arriving at `/login`. Without it the guard fires first, from
    // whatever org page the button was pressed on, and rewrites the destination
    // to `/login?next=/o/acme` — so someone who deliberately signed out is told
    // to "sign in to continue" and sent back where they left.
    if (!session.ready || fatal || signingOut) return;

    if (!session.signedIn) {
      if (!isPublic) {
        // `/` has no content of its own, so there is nothing to come back to.
        const next = page.url.pathname + page.url.search;
        const target = next === '/' ? '/login' : `/login?next=${encodeURIComponent(next)}`;
        void goto(target, { replaceState: true });
      }
      return;
    }

    // No enrollment gate any more: a session only exists for an account that
    // already registered a passkey, because the passkey is what creates the
    // account.
    //
    // One exception, and it is not a half-signed-in state so much as a
    // half-*introduced* one. Signup creates the account from the passkey and
    // asks for an address on the step after, so between those two the account
    // is signed in and sitting on `/signup` on purpose. Bouncing it to `/` the
    // moment the session appears makes that second step unreachable — which is
    // exactly what it did until a browser test caught it.
    const needsProfile = session.me != null && session.me.user.email == null;
    if (isPublic && !needsProfile) {
      // Honour `next` rather than always landing on `/`. A language change
      // detected at sign-in reloads this page, and the reload lands back here
      // signed in — so without this, arriving with a stored locale that differs
      // from the browser's silently costs the visitor their destination.
      // `safeNext` is what makes an attacker-supplied `next` safe to follow;
      // a server route needs a real navigation because the client router has
      // no `/oauth/authorize` to render.
      const next = safeNext(page.url.searchParams.get('next'));
      if (next && isServerRoute(next)) location.assign(next);
      else void goto(next ?? '/', { replaceState: true });
    }
  });

  async function signOut() {
    signingOut = true;
    try {
      await api.logout();
    } finally {
      // Cleared even if the request failed. The server clears the cookie on
      // success and treats an unknown one as already gone, so the only way to
      // reach here with a live session is a network error — and leaving the
      // console looking signed in after someone pressed "sign out" is the worse
      // of the two wrong answers.
      session.clear();
      await goto('/login', { replaceState: true });
      signingOut = false;
    }
  }
</script>

<div class="flex min-h-full flex-col">
  <header class="border-b border-edge/60 bg-surface/40">
    <div class="mx-auto flex w-full max-w-6xl items-center gap-4 px-4 py-3">
      <a href="/" class="flex items-center gap-2" aria-label="Otto">
        <Logo class="size-6 text-accent" />
        <span class="text-sm font-semibold tracking-tight text-ink">Otto</span>
      </a>

      {#if session.signedIn}
        <nav class="ml-2 hidden gap-1 text-sm sm:flex" aria-label={m.nav_organizations()}>
          {#each session.orgs as membership (membership.orgId)}
            <a
              href="/o/{membership.orgSlug}"
              class="rounded-md px-2.5 py-1 text-muted transition hover:bg-raised hover:text-ink"
              class:bg-raised={page.url.pathname.startsWith(`/o/${membership.orgSlug}`)}
              class:text-ink={page.url.pathname.startsWith(`/o/${membership.orgSlug}`)}
            >
              {membership.orgName}
            </a>
          {/each}
          <a
            href="/orgs/new"
            class="rounded-md px-2.5 py-1 text-faint transition hover:bg-raised hover:text-ink"
            title={m.nav_create_org()}
          >
            +
          </a>
        </nav>
      {/if}

      <div class="ml-auto flex items-center gap-3 text-sm">
        <!--
          Other Otto consoles. A plain external link, not a client-side route:
          each service is its own origin with its own session, so following one
          is a full navigation.
        -->
        {#if SERVICES.length > 0}
          <nav class="hidden items-center gap-1 sm:flex" aria-label={m.nav_services()}>
            <span class="otto-label">{m.nav_services()}</span>
            {#each SERVICES as service (service.url)}
              <a
                href={service.url}
                class="rounded-md px-2.5 py-1 text-muted transition hover:bg-raised hover:text-ink"
              >
                {service.name}
              </a>
            {/each}
          </nav>
        {/if}
        {#if session.me}
          <span class="hidden text-faint sm:inline"
            >{session.me.user.email ?? session.me.user.label}</span
          >
          <button
            class="rounded-md border border-edge px-2.5 py-1 text-muted transition hover:bg-raised hover:text-ink disabled:opacity-50"
            onclick={signOut}
            disabled={signingOut}
          >
            {m.nav_sign_out()}
          </button>
        {:else if session.ready}
          <a
            href="/login"
            class="rounded-md border border-edge px-2.5 py-1 text-muted transition hover:bg-raised hover:text-ink"
          >
            {m.nav_sign_in()}
          </a>
        {/if}
      </div>
    </div>
  </header>

  <main class="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
    {#if fatal}
      <Alert>
        {fatal}
        <button class="ml-2 underline" onclick={() => location.reload()}>{m.nav_try_again()}</button
        >
      </Alert>
    {:else if !session.ready}
      <Loading what={m.nav_checking_session()} />
    {:else}
      {@render children()}
    {/if}
  </main>

  <footer class="border-t border-edge/40 px-4 py-4 text-center text-xs text-faint">
    <a class="hover:text-muted" href="/api/openapi.json">{m.nav_api_reference()}</a>
    <span aria-hidden="true"> · </span>
    <span>v{APP_VERSION}</span>
  </footer>
</div>
