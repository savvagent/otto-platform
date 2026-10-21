// @vitest-environment jsdom
/**
 * A product page renders its own product: the name as the page's only `<h1>`,
 * and the MCP endpoint an agent is pointed at, as text that can be copied.
 *
 * Its primary button depends on whether the product has a web console of its
 * own. Otto Tower does, and the button leaves for it; Otto Flags and Otto
 * CXP live inside the visitor's AI assistant, so theirs stays on the page and
 * points at the connect card.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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
  history.replaceState(null, '', '/');
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
      props: { data: { lang: 'en', slug: 'tower' } }
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
    expect(headings[0]?.textContent).toContain('Otto Tower');
    expect(container.textContent).toContain('https://otto-factory.savvagent.com/mcp');

    // The page title is the name and the product's own title phrase, with no
    // closing full stop; the description is the short SEO one, not the summary.
    expect(document.title).toBe('Otto Tower: Coordination for teams of coding agents');
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
    expect(open?.textContent).toContain('Open the Otto Tower console');
    expect(open?.querySelector('[aria-hidden="true"]')?.textContent).toBe('↗');

    // The other products are cross-linked; this one is not linked to itself.
    expect(container.querySelector('a[href="/products/flags"]')).not.toBeNull();
    expect(container.querySelector('a[href="/products/tower"]')).toBeNull();

    unmount(instance);
  });

  it('renders Otto Flags as its own page, cross-linking Tower', () => {
    const instance = mountProduct('flags');

    const headings = container.querySelectorAll('h1');
    expect(headings).toHaveLength(1);
    expect(headings[0]?.textContent).toContain('Otto Flags');
    expectNoSkips(headingLevels(container));
    expect(container.textContent).toContain('https://otto-flags.savvagent.com/mcp');
    expect(container.textContent).toContain('Automatic rollback on Team plans and above.');
    expect(container.querySelector('a[href="/products/tower"]')).not.toBeNull();
    expect(container.querySelector('a[href="/products/flags"]')).toBeNull();

    unmount(instance);
  });

  it('turns "Create account" into "Open console" for a signed-in visitor', () => {
    const instance = mountProduct('tower');
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

  it("keeps the way into a product's own web console when it has one", () => {
    const instance = mountProduct('tower');

    expect(linkText('https://otto-factory.savvagent.com')).toContain('Open the Otto Tower console');
    expect(container.querySelector('a[href="#connect"]')).toBeNull();
    expect(container.textContent).not.toContain('has no web console of its own');

    unmount(instance);
  });

  for (const [slug, name] of [
    ['flags', 'Otto Flags'],
    ['cxp', 'Otto CXP']
  ] as const) {
    it(`sends a visitor to the connect card for ${name}, which has no web console`, () => {
      const instance = mountProduct(slug);

      // Nothing on the page leads to the bare origin, which answers a browser
      // with a JSON 404.
      expect(container.querySelector(`a[href^="https://otto-${slug}."]`)).toBeNull();
      expect(container.textContent).not.toContain(`Open the ${name} console`);

      const add = container.querySelector('a[href="#connect"]');
      expect(add?.textContent?.trim()).toBe('Add to your AI assistant');

      const note = Array.from(container.querySelectorAll('p')).find((p) =>
        p.textContent?.includes('has no web console of its own')
      );
      expect(note?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
        `${name} works inside your AI assistant; it has no web console of its own. Usage and billing are in your Otto console.`
      );
      // "Otto console" goes where every other way into the console goes.
      const otto = note?.querySelector('a');
      expect(otto?.textContent?.trim()).toBe('Otto console');
      expect(otto?.getAttribute('href')).toBe('/signup');
      expect(otto?.hasAttribute('data-sveltekit-reload')).toBe(true);

      // The account console stays as the secondary button.
      expect(linkText('/signup')).toBe('Create account');

      unmount(instance);
    });
  }

  it('sends the "Otto console" note to the signed-in visitor\'s org', () => {
    session.me = {
      orgs: [
        { orgId: 'o1', userId: 'u1', role: 'owner', orgSlug: 'acme', orgName: 'Acme', plan: 'free' }
      ]
    } as unknown as Me;
    const instance = mountProduct('cxp');

    const otto = Array.from(container.querySelectorAll('a')).find(
      (a) => a.textContent?.trim() === 'Otto console'
    );
    expect(otto?.getAttribute('href')).toBe('/o/acme');

    unmount(instance);
  });

  it('gives the connect card a focusable target, setup steps, and the Claude Code command', () => {
    for (const slug of ['tower', 'flags', 'cxp']) {
      const instance = mountProduct(slug);

      const connect = container.querySelector('#connect');
      expect(connect?.tagName).toBe('SECTION');
      expect(connect?.getAttribute('tabindex')).toBe('-1');
      expect(connect?.getAttribute('aria-labelledby')).toBe('connect-title');

      const text = connect?.textContent ?? '';
      expect(text).toContain('Connector address');
      // Otto Tower stays on its old host until the otto-tower cutover.
      const host = slug === 'tower' ? 'otto-factory' : `otto-${slug}`;
      expect(text).toContain(`https://${host}.savvagent.com/mcp`);
      expect(text).toContain('Add custom connector');
      expect(text).toContain('ChatGPT');
      expect(text).toContain('developer mode');
      expect(text).toContain(
        `claude mcp add --transport http otto-${slug} https://${host}.savvagent.com/mcp`
      );
      expect(text).toContain('/mcp');
      expectNoSkips(headingLevels(container));

      unmount(instance);
    }
  });

  it('moves focus to the connect card, marked as arrived, when the button is followed', async () => {
    const instance = mountProduct('cxp');
    const connect = container.querySelector<HTMLElement>('#connect')!;
    expect(connect.classList.contains('arrived')).toBe(false);

    container.querySelector<HTMLAnchorElement>('a[href="#connect"]')?.click();
    await vi.waitFor(() => expect(document.activeElement).toBe(connect));
    flushSync();
    expect(connect.classList.contains('arrived')).toBe(true);

    // Leaving the card clears the mark, so it never lingers.
    connect.blur();
    flushSync();
    expect(connect.classList.contains('arrived')).toBe(false);

    unmount(instance);
  });

  it('does not mark a click on the card itself as an arrival', () => {
    const instance = mountProduct('cxp');
    const connect = container.querySelector<HTMLElement>('#connect')!;

    connect.focus();
    connect.click();
    flushSync();
    expect(connect.classList.contains('arrived')).toBe(false);

    unmount(instance);
  });

  it('moves focus to the connect card when the hash changes to #connect, and only then', async () => {
    const instance = mountProduct('cxp');
    const connect = container.querySelector<HTMLElement>('#connect')!;

    history.replaceState(null, '', '/products/cxp#elsewhere');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await Promise.resolve();
    flushSync();
    expect(document.activeElement).not.toBe(connect);

    history.replaceState(null, '', '/products/cxp#connect');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await vi.waitFor(() => expect(document.activeElement).toBe(connect));

    unmount(instance);
  });

  it('moves focus to the connect card on arriving at #connect from another page', async () => {
    history.replaceState(null, '', '/products/cxp#connect');
    const instance = mountProduct('cxp');

    await vi.waitFor(() =>
      expect(document.activeElement).toBe(container.querySelector('#connect'))
    );

    unmount(instance);
  });

  it('leaves focus alone on arrival if the visitor has already moved it', async () => {
    const elsewhere = document.createElement('button');
    document.body.appendChild(elsewhere);
    elsewhere.focus();
    history.replaceState(null, '', '/products/cxp#connect');
    const instance = mountProduct('cxp');

    await Promise.resolve();
    flushSync();
    expect(document.activeElement).toBe(elsewhere);

    unmount(instance);
    elsewhere.remove();
  });
});
