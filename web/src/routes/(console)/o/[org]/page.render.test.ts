// @vitest-environment jsdom
/**
 * The overview, asserted where a user would see it: the counts come from the
 * members and teams lists, spend per service from the usage report, budget
 * alerts from the budgets report, and the services from the console's own
 * config rather than from anything the server said.
 */

import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import Harness from './OrgPageHarness.svelte';
import { BUDGETS, USAGE } from './test-fixtures';

const members = [
  { id: 'u1', email: 'ada@example.test', name: null, label: 'a-b-1', role: 'owner' },
  { id: 'u2', email: 'bob@example.test', name: null, label: 'c-d-2', role: 'member' }
];
const teams = [{ id: 't1', orgId: 'o1', slug: 'core', name: 'Core', createdAt: '2026-01-01' }];
let container: HTMLElement;

function serve(healthy: boolean, budgetsHealthy = true) {
  return vi.fn((path: string) => {
    if (!healthy || (!budgetsHealthy && path.endsWith('/budgets'))) {
      return Promise.resolve(new Response('', { status: 502 }));
    }
    const body = path.endsWith('/members')
      ? members
      : path.endsWith('/teams')
        ? teams
        : path.endsWith('/budgets')
          ? BUDGETS
          : USAGE;
    return Promise.resolve(
      new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
    );
  });
}

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  vi.unstubAllGlobals();
});

describe('the organization overview', () => {
  it('shows counts, spend per service, alerts, and a link to every configured service', async () => {
    const fetchMock = serve(true);
    vi.stubGlobal('fetch', fetchMock);
    const instance = mount(Harness, { target: container, props: { slug: 'acme' } });

    await vi.waitFor(() => {
      expect(container.querySelector('[role="meter"]')).not.toBeNull();
    });

    const paths = fetchMock.mock.calls.map((call) => call[0]);
    expect(paths).toEqual(
      expect.arrayContaining([
        '/api/orgs/acme/members',
        '/api/orgs/acme/teams',
        '/api/orgs/acme/usage',
        '/api/orgs/acme/budgets'
      ])
    );

    // Spend per service this month: a bar against a budget where there is
    // one, "unavailable" (never $0) where the price could not be read.
    const spend = container.querySelector('[role="meter"]')!.closest('ul')!;
    const rows = Array.from(spend.querySelectorAll('li')).map((li) => li.textContent);
    expect(rows[0]).toContain('Otto Flags');
    expect(rows[0]).toContain('$82.50');
    expect(rows[0]).toContain('$82.50 of $100.00 (82%)');
    expect(rows[1]).toContain('Otto CXP');
    expect(rows[1]).toContain('Spend unavailable');
    expect(rows[1]).not.toContain('$0');
    expect(container.textContent).not.toMatch(/operation|bucket|billable/i);

    // This month's 80% alert, here as well as on the budgets page.
    expect(container.querySelector('section[aria-label="Budget alerts"]')?.textContent).toContain(
      'Otto Flags has reached 80% of its monthly budget this month.'
    );

    const tiles = Array.from(container.querySelectorAll('a[href^="/o/acme/"]')).map(
      (a) => a.textContent
    );
    expect(tiles.some((t) => t?.includes('2') && t.includes('Members'))).toBe(true);
    expect(tiles.some((t) => t?.includes('1') && t.includes('Teams'))).toBe(true);

    // Otto Factory has a web console to leave for; Flags and CXP do not, so
    // they go to their connect cards, badged as connectors.
    const factory = container.querySelector('a[href="https://otto-factory.savvagent.com"]');
    expect(factory?.textContent?.trim()).toBe('Otto Factory');
    for (const [slug, name] of [
      ['flags', 'Otto Flags'],
      ['cxp', 'Otto CXP']
    ]) {
      const link = container.querySelector(`a[href="/products/${slug}#connect"]`);
      expect(link?.getAttribute('aria-label')).toBe(`${name}, connector`);
      expect(link?.textContent).toContain('Connector');
      expect(container.querySelector(`a[href^="https://otto-${slug}."]`)).toBeNull();
    }

    unmount(instance);
  });

  it('shows an error rather than a half-drawn page when a read fails', async () => {
    vi.stubGlobal('fetch', serve(false));
    const instance = mount(Harness, { target: container, props: { slug: 'acme' } });

    await vi.waitFor(() => {
      expect(container.querySelector('[role="alert"]')).not.toBeNull();
    });
    expect(container.querySelector('[role="meter"]')).toBeNull();

    unmount(instance);
  });

  it('still shows the overview when only the budgets read fails', async () => {
    vi.stubGlobal('fetch', serve(true, false));
    const instance = mount(Harness, { target: container, props: { slug: 'acme' } });

    await vi.waitFor(() => {
      expect(container.querySelector('[role="meter"]')).not.toBeNull();
    });
    expect(container.textContent).toContain('Budget alerts could not be read just now.');
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(container.querySelector('section[aria-label="Budget alerts"]')).toBeNull();

    unmount(instance);
  });
});
