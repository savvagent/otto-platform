<script lang="ts">
  import { copy } from '$lib/format';
  import { m } from '$lib/paraglide/messages';
  import Button from './Button.svelte';

  /**
   * A value that exists to be copied — a PAT, a provisioning key, an MCP URL.
   *
   * The value is always shown as text as well as offered to the clipboard.
   * Clipboard access can be refused by the browser, and for a credential shown
   * exactly once a copy button that silently did nothing is a lost account.
   */
  interface Props {
    value: string;
    label?: string;
  }

  let { value, label }: Props = $props();

  // Derived from the value rather than passed in. A caller that has to remember
  // to set `multiline` is a caller that will forget, and the failure is silent:
  // a shell command with a line continuation in it renders as one wrapped line
  // that looks correct and pastes wrong.
  const multiline = $derived(value.includes('\n'));
  let state = $state<'idle' | 'copied' | 'failed'>('idle');

  async function onCopy() {
    state = (await copy(value)) ? 'copied' : 'failed';
    setTimeout(() => (state = 'idle'), 2500);
  }
</script>

<div>
  {#if label}<span class="otto-label">{label}</span>{/if}
  <div class="flex items-start gap-2">
    <code
      class="otto-mono flex-1 rounded-md border border-edge bg-canvas px-3 py-2 text-ink"
      class:whitespace-pre-wrap={multiline}>{value}</code
    >
    <Button tone="quiet" onclick={onCopy}>
      {state === 'copied'
        ? m.copy_copied()
        : state === 'failed'
          ? m.copy_select_it()
          : m.copy_action()}
    </Button>
  </div>
  {#if state === 'failed'}
    <p class="mt-1 text-xs text-warn">{m.copy_clipboard_refused()}</p>
  {/if}
</div>
