<script lang="ts">
  /**
   * Mounts an org page inside an org context with a given role, for render
   * tests of what each role sees.
   *
   * The role is set directly rather than fetched: the layout resolves it, and
   * these tests are about the page, not the layout. It is a rendering hint
   * only; the server authorizes every request (see `OrgContext`).
   */
  import type { Component } from 'svelte';

  import { OrgContext, provideOrg } from '$lib/org.svelte';
  import type { Role } from '$lib/types';

  let { slug, role, page: Page }: { slug: string; role: Role; page: Component } = $props();

  const context = new OrgContext(() => slug);
  // svelte-ignore state_referenced_locally
  context.role = role;
  provideOrg(context);
</script>

<Page />
