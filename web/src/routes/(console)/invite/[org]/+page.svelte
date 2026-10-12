<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';

  import { api, ApiError } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';

  /**
   * What an invitation link opens.
   *
   * Behind the sign-in guard in the root layout, deliberately. The server
   * requires a session whose address matches the one invited — otherwise a code
   * forwarded to the wrong person is a way into someone else's org — and a page
   * that redeemed on load would burn the token for whoever the browser happened
   * to be signed in as. Codes now travel through chat, which unfurls links just
   * as eagerly as a mail scanner did.
   *
   * The mismatch case (`invite_wrong_account`, `403`) gets its own message,
   * because the fix is "sign in as the invited address", which is not something
   * the generic error text can know.
   */

  const org = $derived(page.params.org ?? '');
  const token = $derived(page.url.searchParams.get('token') ?? '');

  let pending = $state(false);
  let error = $state<string | undefined>(undefined);
  let wrongAccount = $state(false);

  async function accept() {
    pending = true;
    error = undefined;
    wrongAccount = false;
    try {
      const joined = await api.acceptInvite(org, token);
      await session.refresh();
      await goto(`/o/${joined.org.slug}`, { replaceState: true });
    } catch (e) {
      wrongAccount = e instanceof ApiError && e.status === 403;
      error = messageFor(e, m.invite_error_fallback());
    } finally {
      pending = false;
    }
  }
</script>

<svelte:head><title>{m.invite_page_title({ org })}</title></svelte:head>

<div class="mx-auto max-w-sm py-8">
  <h1 class="text-lg font-semibold">{m.invite_heading({ org })}</h1>

  {#if !token}
    <Alert>{m.invite_missing_token()}</Alert>
  {:else}
    <p class="mt-1 text-sm text-faint">
      {m.invite_signed_in_as({
        email: session.me?.user.email ?? session.me?.user.label ?? m.invite_no_email()
      })}
      {m.invite_only_invited_address()}
    </p>

    {#if error}
      <div class="mt-4">
        <Alert>
          {error}
          {#if wrongAccount}
            <span class="mt-1 block">{m.invite_wrong_account_hint()}</span>
          {/if}
        </Alert>
      </div>
    {/if}

    <div class="mt-6">
      <Button {pending} onclick={accept}>{m.invite_accept_button()}</Button>
    </div>
  {/if}
</div>
