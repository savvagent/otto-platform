// @vitest-environment jsdom
/**
 * The budgets page: owners and admins set, change and remove a service's
 * monthly budget and hard stop; members read the same figures with no form.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Role, ServiceBudget } from '$lib/types';
import Harness from '../RoleHarness.svelte';
import { BUDGETS, FLAGS_ROW, CXP_ROW, failure, json, requests, serve } from '../test-fixtures';
import Page from './+page.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  vi.unstubAllGlobals();
});

function render(role: Role) {
  return mount(Harness, { target: container, props: { slug: 'acme', role, page: Page } });
}

/** The card for one service, found by its heading. */
function card(name: string): HTMLElement {
  const heading = Array.from(container.querySelectorAll('h2')).find((h) => h.textContent === name);
  if (!heading) throw new Error(`no card for ${name}`);
  return heading.closest('section')!;
}

function type(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
}

function submit(form: HTMLFormElement) {
  form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  flushSync();
}

const loaded = () => vi.waitFor(() => expect(container.querySelectorAll('h2').length).toBe(2));

describe('the budgets page', () => {
  it.each<Role>(['owner', 'admin'])('lets an %s edit each service’s budget', async (role) => {
    vi.stubGlobal('fetch', serve({ 'GET /api/orgs/acme/budgets': () => json(BUDGETS) }));
    const instance = render(role);
    await loaded();

    const flags = card('Otto Flags');
    const amount = flags.querySelector<HTMLInputElement>('input[name="amount"]')!;
    // Labelled, prefilled in dollars from cents, and described by its hint.
    expect(container.querySelector(`label[for="${amount.id}"]`)?.textContent).toBe(
      'Monthly budget (US dollars)'
    );
    expect(amount.value).toBe('100');
    expect(
      document.getElementById(amount.getAttribute('aria-describedby')!)?.textContent
    ).toContain('$10,000,000.00');
    const hardStop = flags.querySelector<HTMLInputElement>('input[role="switch"]')!;
    expect(hardStop.type).toBe('checkbox');
    expect(hardStop.checked).toBe(false);
    expect(container.querySelector(`label[for="${hardStop.id}"]`)?.textContent).toBe('Hard stop');
    expect(flags.textContent).toContain('Remove budget');

    // No budget yet: an empty field, and nothing to remove.
    const cxp = card('Otto CXP');
    expect(cxp.querySelector<HTMLInputElement>('input[name="amount"]')!.value).toBe('');
    expect(cxp.textContent).not.toContain('Remove budget');
    expect(cxp.textContent).toContain('Spend unavailable');

    expect(container.textContent).not.toContain('Only owners and admins');

    unmount(instance);
  });

  it('shows a member the budgets read-only', async () => {
    vi.stubGlobal('fetch', serve({ 'GET /api/orgs/acme/budgets': () => json(BUDGETS) }));
    const instance = render('member');
    await loaded();

    expect(container.querySelector('form')).toBeNull();
    expect(container.querySelector('input')).toBeNull();
    expect(container.textContent).toContain('Only owners and admins can change budgets.');

    const flags = card('Otto Flags');
    const values = Array.from(flags.querySelectorAll('dd')).map((dd) => dd.textContent?.trim());
    expect(values).toEqual(['$100.00', 'Off']);
    expect(
      Array.from(card('Otto CXP').querySelectorAll('dd')).map((d) => d.textContent?.trim())
    ).toEqual(['None', 'Off']);

    // Members see the alerts too.
    expect(container.querySelector('section[aria-label="Budget alerts"]')?.textContent).toContain(
      'Otto Flags has reached 80% of its monthly budget this month.'
    );

    unmount(instance);
  });

  it('sends exact cents and the hard stop, then confirms and moves focus there', async () => {
    let sent: unknown;
    const saved: ServiceBudget = {
      ...FLAGS_ROW,
      thresholdsReached: [50, 80],
      budget: { ...FLAGS_ROW.budget!, monthlyBudgetCents: 25_050, hardStop: true, percentUsed: 32 }
    };
    const fetchMock = serve({
      'GET /api/orgs/acme/budgets': () => json(BUDGETS),
      'PUT /api/orgs/acme/budgets/otto-flags': (body) => {
        sent = body;
        return json(saved);
      }
    });
    vi.stubGlobal('fetch', fetchMock);
    const instance = render('admin');
    await loaded();

    const flags = card('Otto Flags');
    type(flags.querySelector<HTMLInputElement>('input[name="amount"]')!, '250.50');
    const hardStop = flags.querySelector<HTMLInputElement>('input[role="switch"]')!;
    hardStop.click();
    flushSync();
    expect(hardStop.checked).toBe(true);
    submit(flags.querySelector('form')!);

    await vi.waitFor(() => expect(flags.textContent).toContain('Budget saved for Otto Flags.'));
    expect(sent).toEqual({ monthlyBudgetCents: 25_050, hardStop: true });
    const status = flags.querySelector('[role="status"][tabindex="-1"]');
    await vi.waitFor(() => expect(document.activeElement).toBe(status));
    expect(flags.querySelector('[role="meter"]')?.getAttribute('aria-valuetext')).toBe(
      '$82.50 of $250.50 spent (32%)'
    );
    expect(requests(fetchMock)).toContain('PUT /api/orgs/acme/budgets/otto-flags');

    unmount(instance);
  });

  it.each([
    ['', 'Enter a budget in dollars.'],
    ['1,234.5', 'Enter an amount like 250 or 250.50, without thousands separators.'],
    ['0', 'The budget must be at least $0.01.'],
    ['10000000.01', 'The budget can be at most $10,000,000.00.']
  ])('refuses %j next to the field without asking the server', async (value, message) => {
    const fetchMock = serve({ 'GET /api/orgs/acme/budgets': () => json(BUDGETS) });
    vi.stubGlobal('fetch', fetchMock);
    const instance = render('owner');
    await loaded();

    const flags = card('Otto Flags');
    const amount = flags.querySelector<HTMLInputElement>('input[name="amount"]')!;
    type(amount, value);
    submit(flags.querySelector('form')!);

    await vi.waitFor(() => expect(amount.getAttribute('aria-invalid')).toBe('true'));
    const described = amount
      .getAttribute('aria-describedby')!
      .split(' ')
      .map((id) => document.getElementById(id)?.textContent?.trim());
    expect(described).toContain(message);
    await vi.waitFor(() => expect(document.activeElement).toBe(amount));
    expect(requests(fetchMock)).toEqual(['GET /api/orgs/acme/budgets']);

    unmount(instance);
  });

  it('removes a budget', async () => {
    const fetchMock = serve({
      'GET /api/orgs/acme/budgets': () => json(BUDGETS),
      'DELETE /api/orgs/acme/budgets/otto-flags': () => new Response(null, { status: 204 })
    });
    vi.stubGlobal('fetch', fetchMock);
    const instance = render('owner');
    await loaded();

    const flags = card('Otto Flags');
    const remove = Array.from(flags.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Remove budget'
    )!;
    remove.click();

    await vi.waitFor(() => expect(flags.textContent).toContain('Budget removed for Otto Flags.'));
    expect(flags.querySelector<HTMLInputElement>('input[name="amount"]')!.value).toBe('');
    expect(flags.textContent).not.toContain('Remove budget');
    expect(flags.textContent).toContain('No budget set');
    expect(flags.querySelector('[role="meter"]')).toBeNull();
    // With no budget, the month's fired thresholds no longer read as alerts.
    expect(container.querySelector('section[aria-label="Budget alerts"]')).toBeNull();

    unmount(instance);
  });

  it('shows what the server refused', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/budgets': () => json({ ...BUDGETS, services: [CXP_ROW] }),
        'PUT /api/orgs/acme/budgets/otto-cxp': () => failure(403, 'forbidden')
      })
    );
    const instance = render('admin');
    await vi.waitFor(() => expect(container.querySelector('form')).not.toBeNull());

    type(container.querySelector<HTMLInputElement>('input[name="amount"]')!, '40');
    submit(container.querySelector('form')!);

    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
    expect(container.textContent).not.toContain('Budget saved');

    unmount(instance);
  });
});
