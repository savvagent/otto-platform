<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * How every failure reaches the user.
   *
   * `role="alert"` so a screen reader announces it without the user hunting for
   * what changed — an error that only exists visually is an error a blind user
   * has to guess at.
   */
  interface Props {
    tone?: 'error' | 'warn' | 'ok' | 'info';
    children: Snippet;
  }

  let { tone = 'error', children }: Props = $props();

  const tones = {
    error: 'border-bad/50 bg-bad/10 text-bad',
    warn: 'border-warn/50 bg-warn/10 text-warn',
    ok: 'border-ok/50 bg-ok/10 text-ok',
    info: 'border-edge bg-raised/50 text-muted'
  } as const;
</script>

<div
  role={tone === 'error' ? 'alert' : 'status'}
  class="rounded-md border px-3 py-2 text-sm {tones[tone]}"
>
  {@render children()}
</div>
