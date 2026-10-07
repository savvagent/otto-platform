<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title?: string;
    description?: string;
    actions?: Snippet;
    children: Snippet;
  }

  let { title, description, actions, children }: Props = $props();
</script>

<section class="otto-card">
  {#if title || actions}
    <header class="flex items-start justify-between gap-4 border-b border-edge/60 px-4 py-3">
      <div>
        {#if title}<h2 class="text-sm font-semibold text-ink">{title}</h2>{/if}
        {#if description}<p class="mt-0.5 text-xs text-faint">{description}</p>{/if}
      </div>
      {#if actions}<div class="flex shrink-0 gap-2">{@render actions()}</div>{/if}
    </header>
  {/if}
  <div class="px-4 py-3">
    {@render children()}
  </div>
</section>
