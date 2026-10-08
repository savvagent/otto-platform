<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * The empty state.
   *
   * It always says what to do next. An empty table with no instruction is the
   * moment a new customer decides the product is broken rather than new.
   */
  interface Props {
    title: string;
    children?: Snippet;
  }

  let { title, children }: Props = $props();
</script>

<div class="rounded-md border border-dashed border-edge/70 px-4 py-8 text-center">
  <p class="text-sm text-muted">{title}</p>
  {#if children}
    <div class="mt-2 text-xs text-faint">{@render children()}</div>
  {/if}
</div>
