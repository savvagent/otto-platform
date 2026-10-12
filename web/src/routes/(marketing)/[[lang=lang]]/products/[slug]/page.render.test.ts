// @vitest-environment jsdom
/**
 * A product page renders its own product: the name as the page's only `<h1>`,
 * and the MCP endpoint an agent is pointed at, as text that can be copied.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import Page from './+page.svelte';

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
    expect(headings[0]?.textContent).toContain('Otto Factory');
    expect(container.textContent).toContain('https://otto-factory.savvagent.com/mcp');

    // The page title is the name and the product's own title phrase, with no
    // closing full stop; the description is the short SEO one, not the summary.
    expect(document.title).toBe('Otto Factory: Coordination for teams of coding agents');
    const description = document.head.querySelector('meta[name="description"]');
    expect(description?.getAttribute('content')?.length).toBeLessThanOrEqual(160);

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
