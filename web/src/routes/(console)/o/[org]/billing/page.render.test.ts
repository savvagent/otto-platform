// @vitest-environment jsdom
/**
 * The billing page: owner only. Card status, putting a card on file through
 * Stripe Checkout, and every state the server can be in: billing off on this
 * deployment, a failed payment, billing stopped, and each refusal of setup.
 *
 * `leaveForCheckout` is replaced, since jsdom cannot navigate.
 */

import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/state', async () => await import('$lib/components/marketing/fake-app-state.svelte'));
vi.mock('./checkout', () => ({ leaveForCheckout: vi.fn(() => true) }));

import { page } from '$lib/components/marketing/fake-app-state.svelte';
import type { BillingStatus, Role } from '$lib/types';
import Harness from '../RoleHarness.svelte';
import { failure, json, requests, serve } from '../test-fixtures';
import { leaveForCheckout } from './checkout';
import Page from './+page.svelte';

const NO_CARD: BillingStatus = {
  billingEnabled: true,
  cardStatus: 'none',
  subscriptionStatus: null,
  subscriptionLive: false,
  billingStopped: false
};

const CARD_ON_FILE: BillingStatus = {
  billingEnabled: true,
  cardStatus: 'active',
  subscriptionStatus: 'active',
  subscriptionLive: true,
  billingStopped: false
};

const CHECKOUT = 'https://checkout.stripe.com/c/pay/cs_test_123';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  page.url = new URL('http://localhost/o/acme/billing');
  vi.mocked(leaveForCheckout).mockClear();
});

afterEach(() => {
  container.remove();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function render(role: Role) {
  return mount(Harness, { target: container, props: { slug: 'acme', role, page: Page } });
}

const button = (label: string) =>
  Array.from(container.querySelectorAll('button')).find((b) => b.textContent?.trim() === label);

describe('the billing page', () => {
  it.each<Role>(['admin', 'member'])('tells an %s it is for owners, and reads nothing', (role) => {
    const fetchMock = serve({});
    vi.stubGlobal('fetch', fetchMock);
    const instance = render(role);

    expect(container.textContent).toContain(
      'Only the organization’s owners can see and change billing.'
    );
    expect(button('Add card')).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();

    unmount(instance);
  });

  it('shows an owner with no card an "Add card" that goes to Stripe Checkout', async () => {
    const fetchMock = serve({
      'GET /api/orgs/acme/billing': () => json(NO_CARD),
      'POST /api/orgs/acme/billing/setup': () => json({ url: CHECKOUT })
    });
    vi.stubGlobal('fetch', fetchMock);
    const instance = render('owner');

    await vi.waitFor(() => expect(button('Add card')).toBeDefined());
    expect(container.textContent).toContain('No card on file.');
    expect(container.textContent).toContain('None yet');
    expect(container.textContent).toContain('Not invoiced');

    button('Add card')!.click();
    await vi.waitFor(() => expect(leaveForCheckout).toHaveBeenCalledWith(CHECKOUT));
    expect(requests(fetchMock)).toEqual([
      'GET /api/orgs/acme/billing',
      'POST /api/orgs/acme/billing/setup'
    ]);

    unmount(instance);
  });

  it('shows a card on file and offers to replace it', async () => {
    vi.stubGlobal('fetch', serve({ 'GET /api/orgs/acme/billing': () => json(CARD_ON_FILE) }));
    const instance = render('owner');

    await vi.waitFor(() => expect(button('Replace card')).toBeDefined());
    expect(container.textContent).toContain('A card is on file.');
    expect(container.textContent).toContain('Invoiced monthly');
    expect(container.querySelector('[role="alert"]')).toBeNull();

    unmount(instance);
  });

  it('says so when billing is not enabled on the deployment', async () => {
    vi.stubGlobal(
      'fetch',
      serve({ 'GET /api/orgs/acme/billing': () => json({ ...NO_CARD, billingEnabled: false }) })
    );
    const instance = render('owner');

    await vi.waitFor(() =>
      expect(container.textContent).toContain('Billing is not enabled on this deployment.')
    );
    expect(button('Add card')).toBeUndefined();

    unmount(instance);
  });

  it('shows a failed payment as an alert', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/billing': () =>
          json({ ...CARD_ON_FILE, cardStatus: 'failed', subscriptionStatus: 'past_due' })
      })
    );
    const instance = render('owner');

    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('A payment failed.');
    expect(container.textContent).toContain('Past due');
    expect(button('Add card')).toBeDefined();

    unmount(instance);
  });

  it('shows stopped billing as an alert, and an unknown Stripe status as given', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/billing': () =>
          json({
            ...NO_CARD,
            cardStatus: 'detached',
            subscriptionStatus: 'incomplete_expired',
            billingStopped: true
          })
      })
    );
    const instance = render('owner');

    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Billing has stopped');
    expect(container.textContent).toContain('The card on file was removed.');
    expect(container.querySelector('code')?.textContent).toBe('incomplete_expired');

    unmount(instance);
  });

  it.each([
    [409, 'billing_busy', 'Another billing change for this organization is in progress.'],
    [503, 'billing_disabled', 'Billing is not enabled on this deployment.'],
    [502, 'stripe_unavailable', 'The payment provider could not complete this right now.']
  ])('explains a %i %s from setup, and stays put', async (status, code, message) => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/billing': () => json(NO_CARD),
        'POST /api/orgs/acme/billing/setup': () => failure(status, code)
      })
    );
    const instance = render('owner');
    await vi.waitFor(() => expect(button('Add card')).toBeDefined());

    button('Add card')!.click();
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(message);
    expect(leaveForCheckout).not.toHaveBeenCalled();
    await vi.waitFor(() =>
      expect(document.activeElement?.querySelector('[role="alert"]')).not.toBeNull()
    );

    unmount(instance);
  });

  it('says a cancelled setup changed nothing', async () => {
    page.url = new URL('http://localhost/o/acme/billing?setup=cancelled');
    vi.stubGlobal('fetch', serve({ 'GET /api/orgs/acme/billing': () => json(NO_CARD) }));
    const instance = render('owner');

    await vi.waitFor(() => expect(button('Add card')).toBeDefined());
    expect(container.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'Card setup was cancelled. Nothing changed.'
    );

    unmount(instance);
  });

  it('after a successful setup, re-reads until Stripe has confirmed the card', async () => {
    vi.useFakeTimers();
    page.url = new URL('http://localhost/o/acme/billing?setup=success');
    let reads = 0;
    const fetchMock = serve({
      'GET /api/orgs/acme/billing': () => json(++reads < 3 ? NO_CARD : CARD_ON_FILE)
    });
    vi.stubGlobal('fetch', fetchMock);
    const instance = render('owner');

    await vi.advanceTimersByTimeAsync(0);
    expect(container.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'Card details sent to Stripe. It can take a moment for the card to appear here.'
    );
    expect(container.textContent).toContain('No card on file.');

    await vi.advanceTimersByTimeAsync(2_000);
    expect(reads).toBe(2);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(reads).toBe(3);
    expect(container.textContent).toContain('A card is on file.');
    expect(container.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'The card is on file.'
    );

    // Confirmed: no more polling.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(reads).toBe(3);

    unmount(instance);
  });

  it('stops re-reading after a few tries, and leaves a refresh', async () => {
    vi.useFakeTimers();
    page.url = new URL('http://localhost/o/acme/billing?setup=success');
    let reads = 0;
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/billing': () => {
          reads++;
          return json(NO_CARD);
        }
      })
    );
    const instance = render('owner');

    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads).toBe(6);

    button('Refresh')!.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(reads).toBe(7);

    unmount(instance);
  });
});
