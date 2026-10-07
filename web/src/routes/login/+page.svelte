<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';

  import { api, ApiError } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import * as webauthn from '$lib/webauthn';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Field from '$lib/components/Field.svelte';

  /**
   * Sign in.
   *
   * **The passkey button itself takes no field**, and that's still the whole
   * design for that path: the passkey is discoverable, so the browser
   * resolves which account is signing in and nothing is submitted
   * beforehand. A login form that looked up an *account* by address would be
   * an oracle for which of an enterprise's employees hold accounts — a
   * target list for the phishing campaign that comes next.
   *
   * The collapsed "sign in with SSO" section below does take an email field,
   * and is a narrower, deliberately-accepted version of the same class of
   * leak: `POST /api/auth/sso/start` resolves an identity *provider* from
   * the email's domain, with no account lookup at all — it can only ever
   * reveal whether some org has claimed and verified that domain for SSO,
   * never whether any specific address has an account. See that endpoint's
   * own design-spec section for why this narrower disclosure is accepted.
   */

  const next = $derived(page.url.searchParams.get('next'));

  let pending = $state(false);
  let error = $state<string | undefined>(undefined);
  let supported = $state(true);

  /**
   * Sign in with SSO — collapsed by default, below the passkey button.
   *
   * `POST /api/auth/sso/start` resolves the identity provider purely from
   * the email's domain; there is no account lookup, so it needs no session
   * either. `sso_not_configured` is the one error this form expects and has
   * a translated sentence for (see `$lib/errors`), and that sentence itself
   * points back at the passkey button above rather than naming a second
   * place to go.
   */
  let ssoOpen = $state(false);
  let ssoEmail = $state('');
  let ssoPending = $state(false);
  let ssoError = $state<string | undefined>(undefined);

  async function signInWithSso(event: SubmitEvent) {
    event.preventDefault();
    ssoPending = true;
    ssoError = undefined;
    try {
      const started = await api.ssoStart(ssoEmail.trim());
      window.location.assign(started.redirectUrl);
    } catch (e) {
      ssoError = messageFor(e, m.error_could_not_sign_in());
    } finally {
      ssoPending = false;
    }
  }

  $effect(() => {
    supported = webauthn.isSupported();
  });

  async function signIn() {
    pending = true;
    error = undefined;
    // Declared above the `try` rather than inside it so the `catch` can still
    // name the key that was offered. An `unknown_credential` is a credential
    // this deployment has no record of — the shape an admin's passkey reset
    // leaves behind — and the id has to survive the throw that reports it.
    let credential: { rawId: string } | undefined;
    try {
      const started = await api.loginStart();
      credential = await webauthn.authenticate(started.challenge as never);
      await api.loginFinish(started.ceremonyId, credential);
      await session.refresh();
      // Signing in once is what makes the label retroactive: a key registered
      // before this account had an address is filed in the vault under words
      // nobody chose, and no re-registration would replace them.
      if (session.me) await webauthn.signalAccount(session.me);
      await goto(next ?? '/', { replaceState: true });
    } catch (e) {
      // The message is set first. `signalUnknownCredential` cannot throw today,
      // but if it ever could, awaiting it before this line would leave someone
      // watching a spinner stop with nothing said at all.
      error = messageFor(e, m.error_could_not_sign_in());
      // The one signal that names no account, because this browser is not
      // signed into one. Somebody already locked out is offered the dead key
      // first — it is the oldest in the vault — and telling the vault to drop
      // it is the difference between a second attempt working and looping.
      //
      // Only from a *sign-in* failure. `unknown_credential` also comes back
      // from removing or renaming a key that is not yours, and this signal is
      // destructive: reaching it from a management error would evict a
      // perfectly good credential from the vault.
      //
      // Deliberately not awaited. This is the one call site with no enclosing
      // handler left to report anything to, and awaiting it holds `pending`
      // true — so a slow or hanging rp_id fetch would keep the sign-in button
      // disabled and stop somebody retrying, for a hint they never see. Safe to
      // fire and forget specifically here: unlike the other two helpers this one
      // never calls `userHandle`, so it has no synchronous throw to lose.
      if (credential && e instanceof ApiError && e.code === 'unknown_credential') {
        void webauthn.signalUnknownCredential(credential.rawId);
      }
    } finally {
      pending = false;
    }
  }
</script>

<svelte:head><title>{m.login_page_title()}</title></svelte:head>

<div class="mx-auto max-w-sm py-8">
  <h1 class="text-lg font-semibold">{m.login_heading()}</h1>
  <p class="mt-1 text-sm text-faint">
    {#if next}
      {m.login_continue_hint()}
    {:else}
      {m.login_passkey_hint()}
    {/if}
  </p>

  {#if !supported}
    <div class="mt-4">
      <Alert>{m.login_unsupported()}</Alert>
    </div>
  {:else}
    {#if error}<div class="mt-4"><Alert>{error}</Alert></div>{/if}

    <div class="mt-5">
      <Button {pending} onclick={signIn}>{m.login_submit()}</Button>
    </div>
  {/if}

  <!--
    Deliberately outside the `supported` check above: signing in with SSO
    needs no WebAuthn at all (it's a plain POST + redirect), so it must stay
    reachable exactly on the browsers where the passkey button is hidden —
    otherwise a browser with no WebAuthn support has no way to sign in at
    all, including into an enforce_sso org where SSO is the *only* path in.
  -->
  <div class="mt-4">
    <button
      type="button"
      class="text-xs text-muted underline hover:text-ink"
      onclick={() => (ssoOpen = !ssoOpen)}
      aria-expanded={ssoOpen}
    >
      {m.login_sso_toggle()}
    </button>

    {#if ssoOpen}
      <form class="mt-3 space-y-3" onsubmit={signInWithSso}>
        <Field label={m.login_sso_email_label()}>
          <input
            class="otto-input"
            type="email"
            required
            autocomplete="email"
            bind:value={ssoEmail}
          />
        </Field>

        {#if ssoError}<Alert>{ssoError}</Alert>{/if}

        <Button type="submit" pending={ssoPending}>{m.login_sso_submit()}</Button>
      </form>
    {/if}
  </div>

  <div class="mt-6 space-y-2 border-t border-edge/50 pt-4 text-xs text-faint">
    <!--
      Two complete sentences, and the link is one of them. A sentence split
      around an anchor is a sentence no translator can reorder — and word order
      is exactly what differs between these six languages.
    -->
    <p>
      {m.login_recovery_hint()}
      <a class="text-muted underline hover:text-ink" href="/claim">{m.login_recovery_link()}</a>
    </p>
    <p class="pt-2">
      {m.login_no_account()}
      <a class="text-muted underline hover:text-ink" href="/signup">{m.login_create_account()}</a>
    </p>
  </div>
</div>
