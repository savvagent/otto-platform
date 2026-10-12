// @vitest-environment jsdom
/**
 * A product page renders its own product: the name as the page's only `<h1>`,
 * and the MCP endpoint an agent is pointed at, as text that can be copied.
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

function mountProduct(slug: string) {
  const instance = mount(Page, { target: container, props: { data: { lang: 'en', slug } } });
  flushSync();
  return instance;
}

function linkText(href: string): string | undefined {
  return container.querySelector(`a[href="${href}"]`)?.textContent?.trim();
}

describe('the product page', () => {
  it('names the product in the h1 and shows its MCP endpoint', () => {
    const instance = mount(Page, {
      target: container,
      props: { data: { lang: 'en', slug: 'factory' } }
    });

    flushSync();

    const headings = container.querySelectorAll('h1');
    expect(headings).toHaveLength(1);
    expectNoSkips(headingLevels(container));
    // The cross-linked card's name is a real heading, one level under its section.
    const card = Array.from(container.querySelectorAll('h3')).find((h) =>
      h.textContent?.includes('Otto Flags')
    );
    expect(card).toBeDefined();
    expect(headings[0]?.textContent).toContain('Otto Factory');
    expect(container.textContent).toContain('https://otto-factory.savvagent.com/mcp');

    // The page title is the name and the product's own title phrase, with no
    // closing full stop; the description is the short SEO one, not the summary.
    expect(document.title).toBe('Otto Factory: Coordination for teams of coding agents');
    const description = document.head.querySelector('meta[name="description"]');
    expect(description?.getAttribute('content')?.length).toBeLessThanOrEqual(160);

    // A link preview gets the image's alt text, and every other language.
    expect(
      document.head.querySelector('meta[property="og:image:alt"]')?.getAttribute('content')
    ).toBe('The Otto logo');
    const others = Array.from(
      document.head.querySelectorAll('meta[property="og:locale:alternate"]')
    ).map((meta) => meta.getAttribute('content'));
    expect(others).toEqual(['es_ES', 'de_DE', 'fr_FR', 'it_IT', 'hi_IN']);

    // The service's own console names its destination; the arrow marking it
    // as off-site is decoration, so it is not part of the accessible name.
    const open = container.querySelector('a[href="https://otto-factory.savvagent.com"]');
    expect(open?.textContent).toContain('Open the Otto Factory console');
    expect(open?.querySelector('[aria-hidden="true"]')?.textContent).toBe('↗');

    // The other products are cross-linked; this one is not linked to itself.
    expect(container.querySelector('a[href="/products/flags"]')).not.toBeNull();
    expect(container.querySelector('a[href="/products/factory"]')).toBeNull();

    unmount(instance);
  });

  it('renders Otto Flags as its own page, cross-linking Factory', () => {
    const instance = mountProduct('flags');

    const headings = container.querySelectorAll('h1');
    expect(headings).toHaveLength(1);
    expect(headings[0]?.textContent).toContain('Otto Flags');
    expectNoSkips(headingLevels(container));
    expect(container.textContent).toContain('https://otto-flags.savvagent.com/mcp');
    expect(container.textContent).toContain('Automatic rollback on Team plans and above.');
    expect(linkText('https://otto-flags.savvagent.com')).toContain('Open the Otto Flags console');
    expect(container.querySelector('a[href="/products/factory"]')).not.toBeNull();
    expect(container.querySelector('a[href="/products/flags"]')).toBeNull();

    unmount(instance);
  });

  it('turns "Create account" into "Open console" for a signed-in visitor', () => {
    const instance = mountProduct('factory');
    expect(linkText('/signup')).toBe('Create account');

    session.me = {
      orgs: [
        { orgId: 'o1', userId: 'u1', role: 'owner', orgSlug: 'acme', orgName: 'Acme', plan: 'free' }
      ]
    } as unknown as Me;
    flushSync();

    expect(container.querySelector('a[href="/signup"]')).toBeNull();
    expect(linkText('/o/acme')).toBe('Open console');
    expect(
      container.querySelector('a[href="/o/acme"]')?.hasAttribute('data-sveltekit-reload')
    ).toBe(true);

    unmount(instance);
  });
});
