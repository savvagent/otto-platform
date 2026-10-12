<script lang="ts">
  import { page } from '$app/state';
  import type { Snippet } from 'svelte';

  import { api, ApiError } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { OrgContext, provideOrg } from '$lib/org.svelte';
  import { session } from '$lib/session.svelte';
  import Alert from '$lib/components/Alert.svelte';
  import Loading from '$lib/components/Loading.svelte';

  let { children }: { children: Snippet } = $props();

  const slug = $derived(page.params.org ?? '');

  const context = new OrgContext(() => page.params.org ?? '');
  provideOrg(context);

  let loading = $state(true);
  let missing = $state(false);
  let error = $state<string | undefined>(undefined);

  /**
   * Resolve the org named in the URL.
   *
   * **A `404` is rendered as "no such organization", full stop.** The server
   * answers `404` both for an org that does not exist and for one the caller is
   * not in, precisely so the two cannot be told apart — a `403` on a real slug
   * and a `404` on a fake one turns any signed-in account into a directory of
   * who uses the product. A console that helpfully said "you don't have access
   * to acme" would undo that from the client side.
   */
  $effect(() => {
    const wanted = slug;
    if (!wanted || !session.signedIn) return;

    loading = true;
    missing = false;
    error = undefined;

    void (async () => {
      try {
        const joined = await api.org(wanted);
        // Guard against an out-otto-order response: a fast navigation between two
        // orgs can land the first fetch after the second, and applying it would
        // show the wrong org's name over the right org's data.
        if (context.slug !== wanted) return;
        context.org = joined.org;
        context.role = joined.role;
        session.lastOrg = joined.org.slug;
      } catch (e) {
        if (e instanceof ApiError && e.isNotFound) {
          missing = true;
        } else {
          error = messageFor(e, m.orgnav_load_failed());
        }
      } finally {
        loading = false;
      }
    })();
  });

  const nav = $derived([
    { href: `/o/${slug}`, label: m.orgnav_overview(), exact: true },
    { href: `/o/${slug}/members`, label: m.orgnav_members() },
    { href: `/o/${slug}/teams`, label: m.orgnav_teams() },
    ...(context.isAdmin ? [{ href: `/o/${slug}/sso`, label: m.orgnav_sso() }] : []),
    { href: `/o/${slug}/usage`, label: m.orgnav_usage() },
    ...(context.isAdmin ? [{ href: `/o/${slug}/audit`, label: m.orgnav_audit() }] : [])
  ]);

  function active(href: string, exact = false): boolean {
    return exact ? page.url.pathname === href : page.url.pathname.startsWith(href);
  }
</script>

<svelte:head><title>{m.orgnav_document_title({ title: context.title })}</title></svelte:head>

{#if missing}
  <div class="mx-auto max-w-md py-10 text-center">
    <h1 class="text-lg font-semibold">{m.orgnav_missing_title()}</h1>
    <!--
      One message with the slug inside it, rather than prose either side of a
      `<code>`. The slug sits mid-sentence in English and does not in every
      language, and a sentence assembled from two fragments cannot be moved.
    -->
    <p class="mt-2 text-sm text-faint">{m.orgnav_missing_body({ slug })}</p>
  </div>
{:else if error}
  <Alert>{error}</Alert>
{:else}
  <div class="flex flex-col gap-6 sm:flex-row">
    <nav
      class="shrink-0 sm:w-auto sm:min-w-44"
      aria-label={m.orgnav_sections_aria({ org: context.title })}
    >
      <ul class="flex gap-1 overflow-x-auto sm:flex-col sm:overflow-visible">
        {#each nav as item (item.href)}
          <li>
            <a
              href={item.href}
              class="block rounded-md px-2.5 py-1.5 text-sm whitespace-nowrap text-muted transition hover:bg-raised hover:text-ink"
              class:bg-raised={active(item.href, item.exact)}
              class:text-ink={active(item.href, item.exact)}
              aria-current={active(item.href, item.exact) ? 'page' : undefined}
            >
              {item.label}
            </a>
          </li>
        {/each}
      </ul>
    </nav>

    <div class="min-w-0 flex-1">
      {#if loading && !context.org}
        <Loading what={m.orgnav_loading({ org: slug })} />
      {:else}
        {@render children()}
      {/if}
    </div>
  </div>
{/if}
