<script lang="ts">
  import type { Snippet } from 'svelte';

  import '../app.css';

  /**
   * The root layout is shared by the console and the marketing pages, and the
   * marketing pages are rendered at build time in Node. So nothing here may
   * touch `window`, `document` or `localStorage`: the console's boot logic
   * (language, session, guard) lives in `(console)/+layout.svelte`, which only
   * ever runs in the browser.
   */
  let { children }: { children: Snippet } = $props();
</script>

{@render children()}
