<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * Every button that calls the API is `type="button"` unless it submits a
   * form, and every one of them can be `pending`. A destructive action that
   * looks identical while a request is in flight is how a member gets removed
   * twice.
   */
  interface Props {
    children: Snippet;
    tone?: 'primary' | 'quiet' | 'danger';
    type?: 'button' | 'submit';
    disabled?: boolean;
    pending?: boolean;
    title?: string;
    onclick?: (event: MouseEvent) => void;
  }

  let {
    children,
    tone = 'primary',
    type = 'button',
    disabled = false,
    pending = false,
    title,
    onclick
  }: Props = $props();

  const tones = {
    primary: 'bg-accent text-accent-ink hover:brightness-110',
    quiet: 'border border-edge bg-raised/60 text-ink hover:bg-raised',
    danger: 'border border-bad/50 bg-transparent text-bad hover:bg-bad/10'
  } as const;
</script>

<button
  {type}
  {title}
  disabled={disabled || pending}
  {onclick}
  class="inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm
         font-medium transition disabled:cursor-not-allowed disabled:opacity-50 {tones[tone]}"
>
  {#if pending}
    <span
      class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
      aria-hidden="true"
    ></span>
  {/if}
  {@render children()}
</button>
