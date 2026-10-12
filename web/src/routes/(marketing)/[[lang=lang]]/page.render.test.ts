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

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  session.clear();
});

function link(text: string): HTMLAnchorElement | undefined {
  return Array.from(container.querySelectorAll('a')).find((a) => a.textContent?.trim() === text);
}

describe('the landing page', () => {
  it('offers "Create account" to a signed-out visitor', () => {
    const instance = mount(Page, { target: container, props: { data: { lang: 'en' } } });

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expectNoSkips(headingLevels(container));
    expect(link('Create account')?.getAttribute('href')).toBe('/signup');
    expect(link('See pricing')?.getAttribute('href')).toBe('/pricing');
    expect(link('Open console')).toBeUndefined();

    unmount(instance);
  });

  it('offers "Open console" once the session resolves to a member of an org', () => {
    const instance = mount(Page, { target: container, props: { data: { lang: 'en' } } });

    session.me = {
      orgs: [
        {
          orgId: 'o1',
          userId: 'u1',
          role: 'owner',
          orgSlug: 'acme',
          orgName: 'Acme',
          plan: 'free'
        }
      ]
    } as unknown as Me;
    flushSync();

    const open = link('Open console');
    expect(open?.getAttribute('href')).toBe('/o/acme');
    // A full load into the browser-only console, never a client-side route.
    expect(open?.hasAttribute('data-sveltekit-reload')).toBe(true);
    expect(link('Create account')).toBeUndefined();

    unmount(instance);
  });
});
