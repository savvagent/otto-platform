<script lang="ts">
  import { replaceState } from '$app/navigation';
  import { page } from '$app/state';
  import { tick, untrack } from 'svelte';

  import { api, ApiError } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { useOrg } from '$lib/org.svelte';
  import type { BillingStatus, CardStatus } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Card from '$lib/components/Card.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import { leaveForCheckout } from './checkout';

  /**
   * Billing: whether a card is on file, and putting one there.
   *
   * **Owner only, reads included**, as on the server: a card's status is what
   * an owner answers for. Anyone else is told so and nothing is fetched.
   *
   * The card is typed into Stripe Checkout, never into this console. "Add
   * card" asks the server for a Checkout URL and leaves for it; Stripe sends
   * the owner back here with `?setup=success` or `?setup=cancelled`. Success
   * there means the details were sent, not that the card is on file: that is
   * what Stripe's webhook later tells the server. So after a success this
   * page re-reads the status a few times, briefly, and offers a refresh.
   */

  /** How often, and how many times, to re-read after returning from Checkout. */
  const POLL_MS = 2_000;
  const POLL_TRIES = 5;

  const org = useOrg();

  let status = $state<BillingStatus | undefined>(undefined);
  let loadError = $state<string | undefined>(undefined);
  let setupError = $state<string | undefined>(undefined);
  let starting = $state(false);
  let refreshing = $state(false);
  /** Bumped by "Try again" to re-run the load. */
  let reloads = $state(0);

  /** How the owner came back from Checkout, if they just did. */
  let returned = $state<'success' | 'cancelled' | undefined>(undefined);
  /** Re-read a few times after the next successful load: set on return from a successful Checkout. */
  let pollOnLoad = false;

  /**
   * Take `?setup=` off the URL once it has been read, so a reload neither
   * repeats the notice nor starts polling again. Declared before the load
   * below so the flag is set before that load's first answer can arrive.
   */
  $effect(() => {
    const setup = page.url.searchParams.get('setup');
    if (setup !== 'success' && setup !== 'cancelled') return;
    untrack(() => {
      returned = setup;
      pollOnLoad = setup === 'success';
    });
    const url = new URL(page.url);
    url.searchParams.delete('setup');
    replaceState(url, {});
  });

  /**
   * Read the status, and after a successful Checkout keep re-reading briefly
   * until Stripe's webhook has put the card on file.
   *
   * Every step checks `cancelled` after its `await`: an owner who navigates
   * away mid-poll must not leave a timer fetching for a page that is gone.
   */
  $effect(() => {
    const slug = org.slug;
    const owner = org.isOwner;
    void reloads;
    if (!slug || !owner) return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    untrack(() => {
      status = undefined;
      loadError = undefined;
    });

    const read = async (): Promise<BillingStatus | undefined> => {
      const next = await api.billing(slug);
      if (cancelled) return undefined;
      status = next;
      return next;
    };

    const poll = (left: number) => {
      timer = setTimeout(async () => {
        if (cancelled) return;
        try {
          const next = await read();
          if (!cancelled && next && next.cardStatus !== 'active' && left > 1) poll(left - 1);
        } catch {
          // The page already shows a status, and a refresh button; one
          // failed background re-read is not worth replacing it with an error.
        }
      }, POLL_MS);
    };

    void (async () => {
      try {
        const first = await read();
        if (cancelled || !first) return;
        const wanted = pollOnLoad;
        pollOnLoad = false;
        if (wanted && first.billingEnabled && first.cardStatus !== 'active') poll(POLL_TRIES);
      } catch (e) {
        if (!cancelled) loadError = messageFor(e, m.billing_load_failed());
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  });

  async function refresh() {
    const slug = org.slug;
    refreshing = true;
    try {
      const next = await api.billing(slug);
      if (org.slug !== slug) return;
      status = next;
    } catch (e) {
      if (org.slug === slug) loadError = messageFor(e, m.billing_load_failed());
    } finally {
      refreshing = false;
    }
  }

  let errorBox = $state<HTMLElement | undefined>(undefined);
  let disabledBox = $state<HTMLElement | undefined>(undefined);

  /**
   * Leave for Checkout. The button stays pending once the browser is on its
   * way, so a second press cannot start a second setup session.
   */
  async function addCard() {
    setupError = undefined;
    starting = true;
    try {
      const { url } = await api.startBillingSetup(org.slug);
      if (leaveForCheckout(url)) return;
      setupError = m.billing_setup_failed();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'billing_disabled') {
        // Said once, by the page's own "billing is not enabled" notice, which
        // replaces the card and its button.
        if (status) status = { ...status, billingEnabled: false };
      } else {
        setupError = setupMessage(e);
      }
    }
    starting = false;
    await tick();
    (setupError ? errorBox : disabledBox)?.focus();
  }

  function setupMessage(e: unknown): string {
    if (e instanceof ApiError) {
      if (e.code === 'billing_busy') return m.billing_error_busy();
      if (e.code === 'stripe_unavailable') return m.billing_error_stripe();
    }
    return messageFor(e, m.billing_setup_failed());
  }

  function cardLine(card: CardStatus): string {
    switch (card) {
      case 'active':
        return m.billing_card_active();
      case 'failed':
        return m.billing_card_failed();
      case 'detached':
        return m.billing_card_detached();
      case 'none':
        return m.billing_card_none();
    }
  }

  /** Stripe's vocabulary, in words where there are words for it; the code itself otherwise. */
  const SUBSCRIPTION: Record<string, () => string> = {
    active: () => m.billing_subscription_active(),
    trialing: () => m.billing_subscription_trialing(),
    past_due: () => m.billing_subscription_past_due(),
    unpaid: () => m.billing_subscription_unpaid(),
    canceled: () => m.billing_subscription_canceled()
  };
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.billing_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">{m.billing_subtitle()}</p>
  </div>

  {#if org.role && !org.isOwner}
    <Alert tone="info">{m.billing_owner_only()}</Alert>
  {:else}
    {#if returned === 'success'}
      <Alert tone="ok">
        {status?.cardStatus === 'active' ? m.billing_setup_confirmed() : m.billing_setup_success()}
      </Alert>
    {:else if returned === 'cancelled'}
      <Alert tone="info">{m.billing_setup_cancelled()}</Alert>
    {/if}

    {#if loadError}
      <Alert>{loadError}</Alert>
      <Button tone="quiet" onclick={() => reloads++}>{m.billing_retry()}</Button>
    {:else if !status}
      <Loading what={m.billing_loading()} />
    {:else if !status.billingEnabled}
      <div bind:this={disabledBox} tabindex="-1" class="outline-none">
        <Alert tone="info">{m.billing_disabled()}</Alert>
      </div>
    {:else}
      {#if status.billingStopped}
        <Alert>{m.billing_stopped_alert()}</Alert>
      {:else if status.cardStatus === 'failed'}
        <Alert>{m.billing_payment_failed_alert()}</Alert>
      {/if}

      <Card title={m.billing_card_title()}>
        {#snippet actions()}
          <Button tone="quiet" pending={refreshing} onclick={refresh}>{m.billing_refresh()}</Button>
        {/snippet}
        <p class="text-sm text-ink">{cardLine(status.cardStatus)}</p>

        <dl class="mt-4 grid grid-cols-2 gap-y-2 text-sm">
          <div>
            <dt class="sav-label">{m.billing_subscription_label()}</dt>
            <dd class="text-muted">
              {#if status.subscriptionStatus === null}
                {m.billing_subscription_none()}
              {:else if SUBSCRIPTION[status.subscriptionStatus]}
                {SUBSCRIPTION[status.subscriptionStatus]!()}
              {:else}
                <code class="sav-mono">{status.subscriptionStatus}</code>
              {/if}
            </dd>
          </div>
          <div>
            <dt class="sav-label">{m.billing_invoicing_label()}</dt>
            <dd class="text-muted">
              {status.subscriptionLive ? m.billing_invoicing_live() : m.billing_invoicing_off()}
            </dd>
          </div>
        </dl>

        <div class="mt-4 space-y-2">
          <Button pending={starting} onclick={addCard}>
            {status.cardStatus === 'active' ? m.billing_replace_card() : m.billing_add_card()}
          </Button>
          <p class="text-xs text-faint">{m.billing_add_card_hint()}</p>
        </div>
      </Card>
    {/if}

    {#if setupError}
      <!--
        Not a live region: focus moves here, and focus is what announces it.
        A role="alert" as well would read the same sentence twice.
      -->
      <div
        bind:this={errorBox}
        tabindex="-1"
        data-setup-error
        class="rounded-md border border-bad/50 bg-bad/10 px-3 py-2 text-sm text-bad outline-none"
      >
        {setupError}
      </div>
    {/if}
  {/if}
</div>
