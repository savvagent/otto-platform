<script lang="ts">
  import { goto } from '$app/navigation';

  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { session } from '$lib/session.svelte';
  import * as webauthn from '$lib/webauthn';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Field from '$lib/components/Field.svelte';

  /**
   * Create an account.
   *
   * **The passkey comes first and the address comes second**, and that ordering
   * is a security property rather than a style choice. Nothing is submitted
   * before the ceremony — no email, no username — so this page cannot be used
   * to ask whether an account exists. Every earlier version of signup could: a
   * password leaks through "already registered", and TOTP leaked because the
   * secret had to come back in the response and so had to be refused for an
   * address that already had one.
   *
   * The address is collected afterwards, by someone already holding the key,
   * where "that one is taken" costs nothing an attacker can use.
   */

  type Step = 'intro' | 'profile';

  let step = $state<Step>('intro');
  let email = $state('');
  let name = $state('');
  let pending = $state(false);
  let error = $state<string | undefined>(undefined);
  let supported = $state(true);
  let platform = $state(true);

  $effect(() => {
    supported = webauthn.isSupported();
    if (supported) void webauthn.hasPlatformAuthenticator().then((p) => (platform = p));
  });

  async function createAccount() {
    pending = true;
    error = undefined;
    try {
      const started = await api.signupStart();
      const credential = await webauthn.register(started.challenge as never);
      await api.signupFinish(started.ceremonyId, credential, deviceName());
      await session.refresh();
      // Agrees with what the ceremony just wrote — there is no address yet, so
      // both name this account by its label. Sent anyway because "signal after
      // every ceremony" is a rule with no exceptions to remember, and the one
      // exception would be the account that never reaches the next step.
      if (session.me) await webauthn.signalAccount(session.me);
      step = 'profile';
    } catch (e) {
      error = messageFor(e, m.error_could_not_create_account());
    } finally {
      pending = false;
    }
  }

  async function saveProfile(event: SubmitEvent) {
    event.preventDefault();
    pending = true;
    error = undefined;
    try {
      await api.setProfile({ email: email.trim(), name: name.trim() });
      await session.refresh();
      // Where the address first exists. The vault is still showing the label
      // the key was created under, and only a signal can replace it —
      // registering again would not, since the name is baked in at creation.
      if (session.me) await webauthn.signalAccount(session.me);
      await goto('/', { replaceState: true });
    } catch (e) {
      error = messageFor(e, m.error_could_not_save());
    } finally {
      pending = false;
    }
  }

  /** A first guess at a label, so the key list is not a row of blanks. */
  function deviceName(): string {
    const ua = navigator.userAgent;
    if (/iPhone|iPad/.test(ua)) return 'iPhone';
    if (/Android/.test(ua)) return m.signup_device_android();
    if (/Mac OS X/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return m.signup_device_windows();
    return m.signup_device_generic();
  }
</script>

<svelte:head><title>{m.signup_page_title()}</title></svelte:head>

<div class="mx-auto max-w-sm py-8">
  {#if step === 'intro'}
    <h1 class="text-lg font-semibold">{m.signup_heading()}</h1>
    <p class="mt-1 text-sm text-faint">{m.signup_intro()}</p>

    {#if !supported}
      <div class="mt-4">
        <Alert>{m.signup_unsupported()}</Alert>
      </div>
    {:else}
      <p class="mt-4 text-xs text-faint">
        {#if platform}
          {m.signup_platform_hint()}
        {:else}
          {m.signup_no_platform_hint()}
        {/if}
      </p>

      {#if error}<div class="mt-4"><Alert>{error}</Alert></div>{/if}

      <div class="mt-5">
        <Button {pending} onclick={createAccount}>{m.signup_create_passkey()}</Button>
      </div>
    {/if}

    <p class="mt-6 text-xs text-faint">
      {m.signup_have_account()}
      <a class="text-muted underline hover:text-ink" href="/login">{m.signup_sign_in_link()}</a>
    </p>
  {:else}
    <h1 class="text-lg font-semibold">{m.signup_ready_heading()}</h1>
    <p class="mt-1 text-sm text-faint">{m.signup_ready_intro()}</p>

    <form class="mt-6 space-y-4" onsubmit={saveProfile}>
      <Field label={m.signup_email_label()} hint={m.signup_email_hint()}>
        <input
          class="otto-input"
          type="email"
          autocomplete="username"
          required
          bind:value={email}
        />
      </Field>

      <Field label={m.signup_name_label()} hint={m.signup_name_hint()}>
        <input class="otto-input" type="text" autocomplete="name" bind:value={name} />
      </Field>

      {#if error}<Alert>{error}</Alert>{/if}

      <Button type="submit" {pending}>{m.signup_save()}</Button>
    </form>

    <!--
      The link is a whole sentence of its own rather than two words lifted out
      of the middle of one: a sentence cut around an anchor cannot be reordered
      into a language that puts the verb somewhere else.
    -->
    <p class="mt-6 text-xs text-faint">
      <a class="text-muted underline hover:text-ink" href="/settings"
        >{m.signup_second_passkey_link()}</a
      >
      {m.signup_second_passkey_hint()}
    </p>
  {/if}
</div>
