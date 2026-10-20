// @vitest-environment jsdom
/**
 * The usage page, as each role sees it: per-service meters and spend this
 * month, budget alerts, and nothing of the retired family-wide bucket.
 */

import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Role } from '$lib/types';
import Harness from '../RoleHarness.svelte';
import { BUDGETS, USAGE, failure, json, requests, serve } from '../test-fixtures';
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

const healthy = () =>
  serve({
    'GET /api/orgs/acme/usage': () => json(USAGE),
    'GET /api/orgs/acme/budgets': () => json(BUDGETS)
  });

describe('the usage page', () => {
  it.each<Role>(['owner', 'admin', 'member'])(
    'shows each service’s meters and spend to a %s',
    async (role) => {
      const fetchMock = healthy();
      vi.stubGlobal('fetch', fetchMock);
      const instance = render(role);

      await vi.waitFor(() => expect(container.querySelectorAll('table')).toHaveLength(2));
      expect(requests(fetchMock).sort()).toEqual([
        'GET /api/orgs/acme/budgets',
        'GET /api/orgs/acme/usage'
      ]);

      const headings = Array.from(container.querySelectorAll('h2')).map((h) => h.textContent);
      expect(headings).toEqual(['Otto Flags', 'Otto CXP']);

      // Table semantics: a caption, column headers and a row header per meter.
      const flags = container.querySelectorAll('table')[0]!;
      expect(flags.querySelector('caption')?.textContent?.trim()).toBe(
        'Otto Flags meters this month'
      );
      expect(
        Array.from(flags.querySelectorAll('th[scope="col"]')).map((th) => th.textContent?.trim())
      ).toEqual(['Meter', 'Unit', 'This month']);
      const row = flags.querySelector('tbody tr')!;
      expect(row.querySelector('th[scope="row"]')?.textContent).toBe('Flag evaluations');
      expect(row.textContent).toContain('evaluation');
      expect(row.textContent).toContain('1,234,567');

      // Spend in dollars against the budget, as a meter.
      const meter = container.querySelector('[role="meter"]')!;
      expect(meter.getAttribute('aria-label')).toBe('Otto Flags spend against its monthly budget');
      expect(meter.getAttribute('aria-valuenow')).toBe('82');
      expect(meter.getAttribute('aria-valuetext')).toBe('$82.50 of $100.00 spent (82%)');
      expect(container.textContent).toContain('$82.50 this month');

      // Unknown spend is unknown, not free.
      const cxp = container.querySelectorAll('section')[2]!;
      expect(cxp.textContent).toContain('Spend unavailable');
      expect(cxp.textContent).not.toContain('$0');
      expect(cxp.querySelector('[role="meter"]')).toBeNull();

      // The 80% alert this month fired, announced as a status.
      const alerts = container.querySelector('section[aria-label="Budget alerts"]');
      expect(alerts?.querySelector('[role="status"]')?.textContent?.trim()).toBe(
        'Otto Flags has reached 80% of its monthly budget this month.'
      );

      // The retired bucket: none of its numbers or words.
      const text = container.textContent ?? '';
      expect(text).not.toMatch(/operation|bucket|included|remaining/i);
      expect(text).not.toContain('988');

      unmount(instance);
    }
  );

  it('says when no service is metered yet', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/usage': () => json({ ...USAGE, services: [] }),
        'GET /api/orgs/acme/budgets': () => json({ ...BUDGETS, services: [] })
      })
    );
    const instance = render('member');

    await vi.waitFor(() => expect(container.textContent).toContain('No metered services yet'));
    expect(container.querySelector('table')).toBeNull();
    expect(container.querySelector('section[aria-label="Budget alerts"]')).toBeNull();

    unmount(instance);
  });

  it('shows an error rather than a half-drawn page when the usage read fails', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/usage': () => failure(502, 'unknown'),
        'GET /api/orgs/acme/budgets': () => json(BUDGETS)
      })
    );
    const instance = render('owner');

    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
    expect(container.querySelector('table')).toBeNull();

    unmount(instance);
  });

  it('still shows usage when only the budgets read fails, with a quiet note', async () => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme/usage': () => json(USAGE),
        'GET /api/orgs/acme/budgets': () => failure(502, 'unknown')
      })
    );
    const instance = render('member');

    await vi.waitFor(() => expect(container.querySelectorAll('table')).toHaveLength(2));
    expect(container.textContent).toContain('Budget alerts could not be read just now.');
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(container.querySelector('section[aria-label="Budget alerts"]')).toBeNull();

    unmount(instance);
  });
});
