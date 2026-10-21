// @vitest-environment jsdom
/**
 * The console header's Services nav: a service with a web console is a link
 * out to it, and one without goes to its product page's connect card with a
 * "Connector" badge, never to the bare origin, which answers a browser with
 * a JSON 404.
 */

import { createRawSnippet, flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/navigation', () => ({ goto: vi.fn(() => Promise.resolve()) }));
vi.mock('$app/state', async () => await import('$lib/components/marketing/fake-app-state.svelte'));

import { page } from '$lib/components/marketing/fake-app-state.svelte';
import { session } from '$lib/session.svelte';
import type { Me } from '$lib/types';
import Layout from './+layout.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  page.url = new URL('http://localhost/o/acme');
  session.me = {
    user: { id: 'u1', email: 'ada@example.test', label: 'a-b-1' },
    orgs: [
      { orgId: 'o1', userId: 'u1', role: 'owner', orgSlug: 'acme', orgName: 'Acme', plan: 'free' }
    ]
  } as unknown as Me;
  session.ready = true;
});

afterEach(() => {
  container.remove();
  session.clear();
});

describe('the console header', () => {
  it('links out to Tower, and to the connect cards of Flags and CXP', () => {
    const children = createRawSnippet(() => ({ render: () => '<p>page</p>' }));
    const instance = mount(Layout, { target: container, props: { children } });
    flushSync();

    const nav = container.querySelector('nav[aria-label="Services"]');
    expect(nav).not.toBeNull();
    const links = Array.from(nav!.querySelectorAll('a')).map((a) => [
      a.getAttribute('href'),
      a.getAttribute('aria-label') ?? a.textContent?.trim()
    ]);
    expect(links).toEqual([
      ['https://otto-factory.savvagent.com', 'Otto Tower'],
      ['/products/flags#connect', 'Otto Flags, connector'],
      ['/products/cxp#connect', 'Otto CXP, connector']
    ]);
    for (const slug of ['flags', 'cxp']) {
      expect(nav!.querySelector(`a[href="/products/${slug}#connect"]`)?.textContent).toContain(
        'Connector'
      );
    }

    unmount(instance);
  });
});
