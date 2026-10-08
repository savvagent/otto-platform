<script lang="ts">
  /**
   * Mounts the overview inside an org context, for `page.render.test.ts`.
   *
   * The page reads its org through `useOrg()`, which throws outside the org
   * layout on purpose, so a test that mounts the page directly is testing a
   * routing mistake. This is the smallest thing that is not one.
   */
  import { OrgContext, provideOrg } from '$lib/org.svelte';
  import Page from './+page.svelte';

  let { slug }: { slug: string } = $props();

  provideOrg(new OrgContext(() => slug));
</script>

<Page />
