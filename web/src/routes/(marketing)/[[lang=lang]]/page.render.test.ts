// @vitest-environment jsdom
/**
 * The landing page's calls to action, asserted where a visitor would see them.
 *
 * The prerendered file is the signed-out page — it is built once and handed to
 * everyone — and the layout resolves the session after mount, so the same
 * component must render the signed-out CTAs with no session and swap to the
 * console link once one appears. Both halves are checked here against the
 * shared `session` object, which is all the layout ever changes.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { getLocale, overwriteGetLocale } from '$lib/paraglide/runtime';
import { session } from '$lib/session.svelte';
import type { Me } from '$lib/types';
import Page from './+page.svelte';

/** Heading levels in document order, so a skip (h1 → h3) is visible as a jump of two. */
function headingLevels(root: HTMLElement): number[] {
  return Array.from(root.querySelectorAll('h1, h2, h3, h4, h5, h6')).map((h) =>
    Number(h.tagName.slice(1))
  );
}

function expectNoSkips(levels: number[]): void {
  expect(levels[0]).toBe(1);
  levels.reduce((previous, level) => {
    expect(level - previous, `h${previous} → h${level}`).toBeLessThanOrEqual(1);
    return level;
  });
}

/** The runtime's own getter, put back after a test speaks another language. */
const defaultGetLocale = getLocale;

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  session.clear();
  overwriteGetLocale(defaultGetLocale);
});

/** Every link with exactly this text: the hero and the closing CTA each have one. */
function links(text: string): HTMLAnchorElement[] {
  return Array.from(container.querySelectorAll('a')).filter((a) => a.textContent?.trim() === text);
}

function signInAs(orgSlugs: string[]): void {
  session.me = {
    orgs: orgSlugs.map((orgSlug) => ({
      orgId: orgSlug,
      userId: 'u1',
      role: 'owner',
      orgSlug,
      orgName: orgSlug,
      plan: 'free'
    }))
  } as unknown as Me;
  flushSync();
}

describe('the landing page', () => {
  it('offers "Create account" to a signed-out visitor, in every call to action', () => {
    const instance = mount(Page, { target: container, props: { data: { lang: 'en' } } });

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expectNoSkips(headingLevels(container));

    const create = links('Create account');
    expect(create).toHaveLength(2);
    for (const a of create) {
      expect(a.getAttribute('href')).toBe('/signup');
      expect(a.hasAttribute('data-sveltekit-reload')).toBe(true);
    }
    const pricing = links('See pricing');
    expect(pricing).toHaveLength(2);
    for (const a of pricing) expect(a.getAttribute('href')).toBe('/pricing');
    expect(links('Open console')).toHaveLength(0);

    unmount(instance);
  });

  it('offers "Open console" everywhere once the session resolves to a member of an org', () => {
    const instance = mount(Page, { target: container, props: { data: { lang: 'en' } } });

    signInAs(['acme']);

    const open = links('Open console');
    expect(open).toHaveLength(2);
    for (const a of open) {
      expect(a.getAttribute('href')).toBe('/o/acme');
      // A full load into the browser-only console, never a client-side route.
      expect(a.hasAttribute('data-sveltekit-reload')).toBe(true);
    }
    expect(links('Create account')).toHaveLength(0);

    unmount(instance);
  });

  it('sends a signed-in account with no org to create one', () => {
    const instance = mount(Page, { target: container, props: { data: { lang: 'en' } } });

    signInAs([]);

    const open = links('Open console');
    expect(open).toHaveLength(2);
    for (const a of open) expect(a.getAttribute('href')).toBe('/orgs/new');

    unmount(instance);
  });

  /**
   * The layout installs the URL's locale as Paraglide's getter before any
   * child renders; this does the same, then checks the two things a
   * language changes: the words, and every marketing link's prefix. The
   * console link is the one link that must *not* be prefixed.
   */
  it('speaks Spanish and links to Spanish pages under /es', () => {
    overwriteGetLocale(() => 'es');
    const instance = mount(Page, { target: container, props: { data: { lang: 'es' } } });

    expect(container.querySelector('#how-title')?.textContent?.trim()).toBe('Cómo funciona');
    const pricing = links('Ver precios');
    expect(pricing).toHaveLength(2);
    for (const a of pricing) expect(a.getAttribute('href')).toBe('/es/pricing');
    for (const slug of ['factory', 'flags']) {
      expect(container.querySelector(`a[href="/es/products/${slug}"]`)).not.toBeNull();
    }
    expect(container.querySelector('a[href^="/products/"]')).toBeNull();
    for (const a of links('Crear cuenta')) expect(a.getAttribute('href')).toBe('/signup');

    unmount(instance);
  });
});
