<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';

  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import * as webauthn from '$lib/webauthn';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Field from '$lib/components/Field.svelte';

  /**
   * Register a new passkey after an admin cleared this account's.
   *
   * The assisted half of recovery, and the reason it exists: an account with no
   * passkeys and no outstanding claim would be claimable by whoever reached
   * registration first. The code is what makes it re-registrable only by
   * whoever the admin handed it to.
   *
   * The code arrives in the URL when someone follows the link an admin sent
   * them, but **nothing is spent on load** — the server consumes it only at
   * `claim/finish`, so a link preview that fetches this page burns nothing, and
   * an abandoned ceremony leaves the code still usable.
   */

  let code = $state(page.url.searchParams.get('code') ?? '');
  let pending = $state(false);
  let error = $state<string | undefined>(undefined);

  async function claim(event: SubmitEvent) {
    event.preventDefault();
    pending = true;
    error = undefined;
    try {
      const started = await api.claimStart(code.trim());
      const credential = await webauthn.register(started.challenge as never);
      await api.claimFinish(started.ceremonyId, code.trim(), credential, m.claim_device_name());
      await session.refresh();
      // The account's name reaches the vault by the same route on every
      // ceremony. Nothing here is a special case, and that is the point: a
      // signal attached to two of the three registration paths is the one that
      // gets forgotten when a fourth is added.
      if (session.me) await webauthn.signalAccount(session.me);
      await goto('/', { replaceState: true });
    } catch (e) {
      error = messageFor(e, m.claim_error_fallback());
    } finally {
      pending = false;
    }
  }
</script>

<svelte:head><title>{m.claim_page_title()}</title></svelte:head>

<div class="mx-auto max-w-sm py-8">
  <h1 class="text-lg font-semibold">{m.claim_heading()}</h1>
  <p class="mt-1 text-sm text-faint">{m.claim_intro()}</p>

  <form class="mt-6 space-y-4" onsubmit={claim}>
    <Field label={m.claim_code_label()}>
      <input
        class="otto-input otto-mono"
        type="text"
        autocapitalize="off"
        spellcheck="false"
        required
        bind:value={code}
      />
    </Field>

    {#if error}<Alert>{error}</Alert>{/if}

    <Button type="submit" {pending}>{m.claim_submit()}</Button>
  </form>

  <p class="mt-6 text-xs text-faint">
    <a class="text-muted underline hover:text-ink" href="/login">{m.claim_back_to_sign_in()}</a>
  </p>
</div>
