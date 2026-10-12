<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { relative } from '$lib/format';
  import { useOrg } from '$lib/org.svelte';
  import type { ClaimedDomain, IdpConnection } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Card from '$lib/components/Card.svelte';
  import CopyField from '$lib/components/CopyField.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Field from '$lib/components/Field.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * Enterprise single sign-on: the org's identity provider connection, the
   * claimed/verified email domains that route sign-ins to it, and the
   * `enforceSso` switch that makes it mandatory.
   *
   * The connection form loads whatever `GET .../sso/connection` reports —
   * issuer and client id, never the secret (the server has no read path for
   * it at all, so the secret field is always blank and write-only, on first
   * load and after every save alike).
   *
   * Every lockout refusal (`sso_lockout`, from the connection delete, the
   * last-verified-domain delete, or turning `enforceSso` on) is shown with
   * the server's own reason inline, never folded into a generic message —
   * `$lib/errors` already does the right thing for that code by falling back
   * to the server's own sentence (see the comment there).
   */

  const org = useOrg();

  let domains = $state<ClaimedDomain[]>([]);
  let loadingDomains = $state(true);
  let domainsError = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug || !org.isAdmin) return;

    loadingDomains = true;
    domainsError = undefined;

    void (async () => {
      try {
        domains = await api.ssoDomains(slug);
      } catch (e) {
        domainsError = messageFor(e, m.sso_error_load());
      } finally {
        loadingDomains = false;
      }
    })();
  });

  // ------------------------------------------------------------ connection

  let issuer = $state('');
  let clientId = $state('');
  let clientSecret = $state('');
  let savingConnection = $state(false);
  let connectionError = $state<string | undefined>(undefined);
  let removingConnection = $state(false);
  let connectionRemoveError = $state<string | undefined>(undefined);
  /**
   * Set on load from `GET .../sso/connection` (undefined = nothing bound
   * yet), and again from whatever `PUT`/`DELETE` themselves return — never
   * guessed at locally.
   */
  let savedConnection = $state<IdpConnection | undefined>(undefined);
  let loadingConnection = $state(true);

  $effect(() => {
    const slug = org.slug;
    if (!slug || !org.isAdmin) return;

    loadingConnection = true;

    void (async () => {
      try {
        const connection = await api.getSsoConnection(slug);
        savedConnection = connection;
        // A bound connection's issuer/client id are shown pre-filled so an
        // admin can see what's configured without retyping it — the secret
        // field is the one thing that never round-trips.
        if (connection) {
          issuer = connection.issuer;
          clientId = connection.clientId;
        }
      } catch (e) {
        connectionError = messageFor(e, m.sso_error_load());
      } finally {
        loadingConnection = false;
      }
    })();
  });

  async function saveConnection(event: SubmitEvent) {
    event.preventDefault();
    savingConnection = true;
    connectionError = undefined;
    try {
      savedConnection = await api.upsertSsoConnection(org.slug, {
        issuer: issuer.trim(),
        clientId: clientId.trim(),
        clientSecret
      });
      // Write-only: the secret is never shown again, here or anywhere else,
      // so there is nothing left in this field once the request succeeds.
      clientSecret = '';
    } catch (e) {
      connectionError = messageFor(e, m.sso_error_save_connection());
    } finally {
      savingConnection = false;
    }
  }

  async function removeConnection() {
    if (!confirm(m.sso_delete_connection_confirm())) return;
    removingConnection = true;
    connectionRemoveError = undefined;
    try {
      await api.deleteSsoConnection(org.slug);
      savedConnection = undefined;
    } catch (e) {
      // The one place this page expects `sso_lockout` — the server refuses
      // while enforceSso is on, and its own reason is what renders here.
      connectionRemoveError = messageFor(e, m.sso_error_delete_connection());
    } finally {
      removingConnection = false;
    }
  }

  // ---------------------------------------------------------------- domains

  let newDomain = $state('');
  let addingDomain = $state(false);
  let addDomainError = $state<string | undefined>(undefined);
  let domainBusy = $state<string | undefined>(undefined);
  let domainActionError = $state<string | undefined>(undefined);
  /** Which domain a verify attempt most recently answered "not yet" for. */
  let notYetVerified = $state<string | undefined>(undefined);

  async function addDomain(event: SubmitEvent) {
    event.preventDefault();
    addingDomain = true;
    addDomainError = undefined;
    try {
      const claimed = await api.claimSsoDomain(org.slug, newDomain.trim());
      domains = [...domains.filter((d) => d.domain !== claimed.domain), claimed];
      newDomain = '';
    } catch (e) {
      addDomainError = messageFor(e, m.sso_error_add_domain());
    } finally {
      addingDomain = false;
    }
  }

  async function verifyDomain(domain: string) {
    domainBusy = `${domain}:verify`;
    domainActionError = undefined;
    notYetVerified = undefined;
    try {
      const { verified } = await api.verifySsoDomain(org.slug, domain);
      if (verified) {
        // Refetch rather than patch one field locally: `verifiedAt` is a
        // timestamp the server chose, not something worth guessing here.
        domains = await api.ssoDomains(org.slug);
      } else {
        notYetVerified = domain;
      }
    } catch (e) {
      domainActionError = messageFor(e, m.sso_error_verify_domain());
    } finally {
      domainBusy = undefined;
    }
  }

  async function removeDomain(domain: string) {
    domainBusy = `${domain}:remove`;
    domainActionError = undefined;
    try {
      await api.deleteSsoDomain(org.slug, domain);
      domains = domains.filter((d) => d.domain !== domain);
    } catch (e) {
      // The other place `sso_lockout` shows up: removing the org's last
      // verified domain while enforceSso is on.
      domainActionError = messageFor(e, m.sso_error_remove_domain());
    } finally {
      domainBusy = undefined;
    }
  }

  // --------------------------------------------------------------- enforce

  let enforceBusy = $state(false);
  let enforceError = $state<string | undefined>(undefined);

  async function toggleEnforce(next: boolean) {
    enforceBusy = true;
    enforceError = undefined;
    try {
      // The server itself is the source of truth for the org's enforceSso
      // flag; writing its response back into the shared org context is what
      // keeps every other page (and a fresh navigation) in sync with it.
      org.org = await api.setEnforceSso(org.slug, next);
    } catch (e) {
      // The third `sso_lockout` site: turning this on with no bound
      // connection or no verified domain yet.
      enforceError = messageFor(e, m.sso_error_enforce());
    } finally {
      enforceBusy = false;
    }
  }
</script>

<svelte:head><title>{m.orgnav_document_title({ title: m.sso_title() })}</title></svelte:head>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.sso_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">{m.sso_subtitle()}</p>
  </div>

  {#if !org.isAdmin}
    <Alert>{m.sso_admin_only()}</Alert>
  {:else}
    <Card title={m.sso_connection_title()} description={m.sso_connection_description()}>
      {#if savedConnection}
        <div class="mb-3">
          <Alert tone="ok">{m.sso_connection_saved({ issuer: savedConnection.issuer })}</Alert>
        </div>
      {/if}

      <form class="max-w-lg space-y-4" onsubmit={saveConnection}>
        <Field label={m.sso_issuer_label()} hint={m.sso_issuer_hint()}>
          <input
            class="otto-input"
            type="url"
            required
            bind:value={issuer}
            placeholder="https://idp.example.com"
          />
        </Field>
        <Field label={m.sso_client_id_label()}>
          <input class="otto-input" type="text" required bind:value={clientId} />
        </Field>
        <Field label={m.sso_client_secret_label()} hint={m.sso_client_secret_hint()}>
          <input
            class="otto-input"
            type="password"
            required
            autocomplete="off"
            bind:value={clientSecret}
          />
        </Field>

        {#if connectionError}<Alert>{connectionError}</Alert>{/if}

        <Button type="submit" disabled={loadingConnection} pending={savingConnection}>
          {m.sso_save_connection()}
        </Button>
      </form>

      <div class="mt-4 border-t border-edge/50 pt-3">
        {#if connectionRemoveError}<div class="mb-2">
            <Alert>{connectionRemoveError}</Alert>
          </div>{/if}
        <Button tone="danger" pending={removingConnection} onclick={removeConnection}>
          {m.sso_delete_connection()}
        </Button>
      </div>
    </Card>

    <Card title={m.sso_domains_title()} description={m.sso_domains_description()}>
      <form class="flex flex-wrap items-end gap-3" onsubmit={addDomain}>
        <div class="min-w-56 flex-1">
          <Field label={m.sso_domain_input_label()}>
            <input
              class="otto-input"
              type="text"
              required
              bind:value={newDomain}
              placeholder={m.sso_domain_input_placeholder()}
            />
          </Field>
        </div>
        <div class="pb-0.5">
          <Button type="submit" pending={addingDomain}>{m.sso_domain_add_button()}</Button>
        </div>
      </form>
      {#if addDomainError}<div class="mt-3"><Alert>{addDomainError}</Alert></div>{/if}
      {#if domainActionError}<div class="mt-3"><Alert>{domainActionError}</Alert></div>{/if}

      <div class="mt-4">
        {#if loadingDomains}
          <Loading what={m.sso_domains_loading()} />
        {:else if domainsError}
          <Alert>{domainsError}</Alert>
        {:else if domains.length === 0}
          <Empty title={m.sso_domains_none()} />
        {:else}
          <ul class="divide-y divide-edge/40">
            {#each domains as claimed (claimed.domain)}
              <li class="py-3">
                <div class="flex flex-wrap items-center gap-3">
                  <div class="min-w-0 flex-1">
                    <div class="flex items-center gap-2 text-sm">
                      <span class="text-ink">{claimed.domain}</span>
                      {#if claimed.verifiedAt}
                        <span
                          class="rounded-full border border-ok/50 bg-ok/10 px-2 py-0.5 text-xs text-ok"
                        >
                          {m.sso_domain_verified()}
                        </span>
                      {:else}
                        <span
                          class="rounded-full border border-warn/50 bg-warn/10 px-2 py-0.5 text-xs text-warn"
                        >
                          {m.sso_domain_pending()}
                        </span>
                      {/if}
                    </div>
                    {#if claimed.verifiedAt}
                      <p class="text-xs text-faint">
                        {m.sso_domain_verified_meta({ when: relative(claimed.verifiedAt) })}
                      </p>
                    {/if}
                  </div>

                  {#if !claimed.verifiedAt}
                    <Button
                      tone="quiet"
                      pending={domainBusy === `${claimed.domain}:verify`}
                      onclick={() => verifyDomain(claimed.domain)}
                    >
                      {m.sso_domain_verify_button()}
                    </Button>
                  {/if}
                  <Button
                    tone="danger"
                    pending={domainBusy === `${claimed.domain}:remove`}
                    onclick={() => removeDomain(claimed.domain)}
                  >
                    {m.sso_domain_remove_button()}
                  </Button>
                </div>

                {#if !claimed.verifiedAt}
                  <div class="mt-3 space-y-2 rounded-md border border-edge/60 bg-canvas/60 p-3">
                    <p class="text-xs text-faint">{m.sso_domain_txt_instructions()}</p>
                    <CopyField
                      label={m.sso_domain_txt_name_label()}
                      value={claimed.txtRecordName}
                    />
                    <CopyField
                      label={m.sso_domain_txt_value_label()}
                      value={claimed.txtRecordValue}
                    />
                    {#if notYetVerified === claimed.domain}
                      <p class="text-xs text-warn">{m.sso_domain_not_verified_yet()}</p>
                    {/if}
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </Card>

    <Card title={m.sso_enforce_title()} description={m.sso_enforce_description()}>
      {#if enforceError}<div class="mb-3"><Alert>{enforceError}</Alert></div>{/if}
      <label class="flex items-center gap-2 text-sm text-ink">
        <input
          type="checkbox"
          checked={org.org?.enforceSso ?? false}
          disabled={enforceBusy}
          onchange={(e) => toggleEnforce(e.currentTarget.checked)}
        />
        {m.sso_enforce_toggle_label()}
      </label>
    </Card>
  {/if}
</div>
