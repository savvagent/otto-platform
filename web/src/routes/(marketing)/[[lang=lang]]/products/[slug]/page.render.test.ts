// @vitest-environment jsdom
/**
 * A product page renders its own product: the name as the page's only `<h1>`,
 * and the MCP endpoint an agent is pointed at, as text that can be copied.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

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
});

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

    const open = Array.from(container.querySelectorAll('a')).find(
      (a) => a.getAttribute('href') === 'https://otto-factory.savvagent.com'
    );
    expect(open?.getAttribute('rel')).toContain('noopener');

    // The other products are cross-linked; this one is not linked to itself.
    expect(container.querySelector('a[href="/products/flags"]')).not.toBeNull();
    expect(container.querySelector('a[href="/products/factory"]')).toBeNull();

    unmount(instance);
  });
});
