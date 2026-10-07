<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * A labelled input. The `<label>` wraps the control rather than pointing at
   * an id, so the association cannot break when a page renders two of these in
   * a loop.
   */
  interface Props {
    label: string;
    hint?: string;
    children: Snippet;
  }

  let { label, hint, children }: Props = $props();
</script>

<label class="block">
  <span class="otto-label">{label}</span>
  {@render children()}
  {#if hint}<span class="mt-1 block text-xs text-faint">{hint}</span>{/if}
</label>
