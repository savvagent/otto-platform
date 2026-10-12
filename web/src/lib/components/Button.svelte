<script lang="ts">
  import type { Snippet } from 'svelte';

  import { buttonClass, type ButtonTone } from './button';

  /**
   * Every button that calls the API is `type="button"` unless it submits a
   * form, and every one of them can be `pending`. A destructive action that
   * looks identical while a request is in flight is how a member gets removed
   * twice.
   */
  interface Props {
    children: Snippet;
    tone?: ButtonTone;
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
</script>

<button
  {type}
  {title}
  disabled={disabled || pending}
  {onclick}
  class="{buttonClass(tone)} disabled:cursor-not-allowed disabled:opacity-50"
>
  {#if pending}
    <span
      class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
      aria-hidden="true"
    ></span>
  {/if}
  {@render children()}
</button>
