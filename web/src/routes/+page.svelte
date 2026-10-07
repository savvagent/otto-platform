<script lang="ts">
  import { goto } from '$app/navigation';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * `/` has no content of its own: it forwards.
   *
   * Everything this console shows is scoped to an organization, so a signed-in
   * visitor goes to the last org they looked at (else their first), and a brand
   * new account with no memberships goes to create one rather than sitting on an
   * empty shell. A signed-out visitor never sees this page — the routing guard in
   * `+layout.svelte` sends them to `/login` first.
   */
  $effect(() => {
    if (!session.ready || !session.signedIn) return;
    const home = session.homeOrg;
    void goto(home ? `/o/${home}` : '/orgs/new', { replaceState: true });
  });
</script>

<svelte:head><title>{m.home_page_title()}</title></svelte:head>

<Loading what={m.home_finding_org()} />
