// @vitest-environment jsdom
/**
 * The footer's language links, and the header's sign-in link.
 *
 * Each language link must be *this page* in that language, and each must
 * reload the document: Paraglide's messages are plain calls, so a client-side
 * navigation would leave the layout speaking the old language. The header's
 * `/login` crosses into the console, which boots its own locale getter, so it
 * needs the reload too.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/state', async () => await import('./fake-app-state.svelte'));

import { session } from '$lib/session.svelte';
import type { Me } from '$lib/types';
import { page } from './fake-app-state.svelte';
import MarketingFooter from './MarketingFooter.svelte';
import MarketingHeader from './MarketingHeader.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  page.url = new URL('http://localhost/');
  session.clear();
});

describe('the marketing footer', () => {
  it('links each language to the same page in that language, reloading the document', () => {
    page.url = new URL('http://localhost/es/pricing');
    const instance = mount(MarketingFooter, { target: container, props: { lang: 'es' } });

    const links = Array.from(container.querySelectorAll<HTMLAnchorElement>('a[hreflang]'));
    // Written out rather than rebuilt with `localizedPath`, so a bug there
    // cannot make this agree with itself. English has no prefix.
    expect(links.map((a) => [a.hreflang, a.getAttribute('href')])).toEqual([
      ['en', '/pricing'],
      ['es', '/es/pricing'],
      ['de', '/de/pricing'],
      ['fr', '/fr/pricing'],
      ['it', '/it/pricing'],
      ['hi', '/hi/pricing']
    ]);
    for (const a of links) {
      expect(a.hasAttribute('data-sveltekit-reload'), a.hreflang).toBe(true);
    }
    expect(links.filter((a) => a.hasAttribute('aria-current')).map((a) => a.hreflang)).toEqual([
      'es'
    ]);
    expect(links.find((a) => a.hreflang === 'es')?.getAttribute('aria-current')).toBe('true');

    unmount(instance);
  });
});

describe('the marketing header', () => {
  const loginLinks = () =>
    Array.from(container.querySelectorAll<HTMLAnchorElement>('a[href="/login"]'));

  it('reloads the document on its sign-in link, and drops it once signed in', () => {
    page.url = new URL('http://localhost/es/pricing');
    const instance = mount(MarketingHeader, { target: container, props: { lang: 'es' } });
    flushSync();

    expect(loginLinks().length).toBeGreaterThan(0);
    for (const a of loginLinks()) {
      expect(a.hasAttribute('data-sveltekit-reload')).toBe(true);
    }

    session.me = {
      orgs: [
        { orgId: 'o1', userId: 'u1', role: 'owner', orgSlug: 'acme', orgName: 'Acme', plan: 'free' }
      ]
    } as unknown as Me;
    flushSync();
    expect(loginLinks()).toHaveLength(0);

    unmount(instance);
  });
});
