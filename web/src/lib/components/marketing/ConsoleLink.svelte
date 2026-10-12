<script lang="ts">
  import { m } from '$lib/paraglide/messages';
  import { consoleEntry, session } from '$lib/session.svelte';
  import LinkButton from '$lib/components/LinkButton.svelte';
  import type { ButtonSize, ButtonTone } from '$lib/components/button';

  /**
   * The way into the console from a marketing page: "Create account" for a
   * visitor, "Open console" for someone signed in.
   *
   * **Signed out in the file, signed in after hydration.** The prerendered
   * HTML is built once for everyone, so it can only ever say "Create
   * account"; the marketing layout resolves `session` after mount, and this
   * swaps the moment it does. A visitor whose session check fails keeps the
   * sign-up link, which still works. Where it goes is `consoleEntry`, the
   * one rule every such link shares.
   *
   * **Always `data-sveltekit-reload`.** The console is browser-only and must
   * boot from a full load — its `resolveAtBoot` runs, and nothing of the
   * marketing layout's locale override survives — and the console has one URL
   * per page whatever the language, so the link is never localized.
   */
  interface Props {
    tone?: ButtonTone;
    size?: ButtonSize;
  }

  let { tone = 'primary', size = 'lg' }: Props = $props();

  const entry = $derived(consoleEntry(session));
</script>

<LinkButton href={entry.href} {tone} {size} data-sveltekit-reload>
  {entry.kind === 'console' ? m.marketing_open_console() : m.marketing_create_account()}
</LinkButton>
