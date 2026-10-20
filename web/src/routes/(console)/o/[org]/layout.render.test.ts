// @vitest-environment jsdom
/**
 * The org section nav, per role: every member reaches usage and budgets;
 * billing is listed for owners only, as the server allows it only for them.
 */

import { createRawSnippet, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/state', () => ({
  page: { params: { org: 'acme' }, url: new URL('http://localhost/o/acme/usage') }
}));

import { session } from '$lib/session.svelte';
import type { Me, Role } from '$lib/types';
import Layout from './+layout.svelte';
import { json, serve } from './test-fixtures';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  session.me = { user: { id: 'u1', label: 'a-b-1' }, orgs: [] } as unknown as Me;
});

afterEach(() => {
  container.remove();
  session.clear();
  vi.unstubAllGlobals();
});

describe('the org section nav', () => {
  it.each<[Role, string[]]>([
    [
      'owner',
      ['Overview', 'Members', 'Teams', 'Single sign-on', 'Usage', 'Budgets', 'Billing', 'Audit log']
    ],
    ['admin', ['Overview', 'Members', 'Teams', 'Single sign-on', 'Usage', 'Budgets', 'Audit log']],
    ['member', ['Overview', 'Members', 'Teams', 'Usage', 'Budgets']]
  ])('lists what a %s may open', async (role, expected) => {
    vi.stubGlobal(
      'fetch',
      serve({
        'GET /api/orgs/acme': () =>
          json({
            org: {
              id: 'o1',
              slug: 'acme',
              name: 'Acme',
              plan: 'free',
              enforceSso: false,
              createdAt: '2026-01-01'
            },
            role
          })
      })
    );
    const children = createRawSnippet(() => ({ render: () => '<p>page</p>' }));
    const instance = mount(Layout, { target: container, props: { children } });

    const nav = () => container.querySelector('nav[aria-label="Acme sections"]');
    const links = () => Array.from(nav()?.querySelectorAll('a') ?? []);
    await vi.waitFor(() => expect(links().map((a) => a.textContent?.trim())).toEqual(expected));
    expect(
      links()
        .find((a) => a.textContent?.trim() === 'Budgets')
        ?.getAttribute('href')
    ).toBe('/o/acme/budgets');
    if (role === 'owner') {
      expect(
        links()
          .find((a) => a.textContent?.trim() === 'Billing')
          ?.getAttribute('href')
      ).toBe('/o/acme/billing');
    }

    unmount(instance);
  });
});
