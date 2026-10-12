// @vitest-environment jsdom
/**
 * The small-screen menu is a `<details>`, which the browser opens and closes
 * on its own — but a `<details>` knows nothing about routing. A client-side
 * navigation from one of its links leaves the new page under an open menu,
 * and nothing about Escape closes one. Both are this component's job.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/state', async () => await import('./fake-app-state.svelte'));

import { page } from './fake-app-state.svelte';
import MarketingHeader from './MarketingHeader.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  page.url = new URL('http://localhost/');
});

afterEach(() => {
  container.remove();
});

function openMenu(): { details: HTMLDetailsElement; summary: HTMLElement } {
  // Let the mount's own effects settle first, so the open below is the last word.
  flushSync();
  const details = container.querySelector('details') as HTMLDetailsElement;
  const summary = details.querySelector('summary') as HTMLElement;
  details.open = true;
  details.dispatchEvent(new Event('toggle'));
  flushSync();
  expect(details.open).toBe(true);
  return { details, summary };
}

describe('the marketing header menu', () => {
  it('closes when the page changes', () => {
    const instance = mount(MarketingHeader, { target: container, props: { lang: 'en' } });
    const { details } = openMenu();

    page.url = new URL('http://localhost/products/flags');
    flushSync();

    expect(details.open).toBe(false);
    unmount(instance);
  });

  it('closes on Escape and hands focus back to its toggle', () => {
    const instance = mount(MarketingHeader, { target: container, props: { lang: 'en' } });
    const { details, summary } = openMenu();
    const link = details.querySelector('nav a') as HTMLAnchorElement;
    link.focus();

    link.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    flushSync();

    expect(details.open).toBe(false);
    expect(document.activeElement).toBe(summary);
    unmount(instance);
  });

  it('marks the current page with more than colour', () => {
    page.url = new URL('http://localhost/products/flags');
    const instance = mount(MarketingHeader, { target: container, props: { lang: 'en' } });

    const current = container.querySelector('a[aria-current="page"]');
    expect(current?.getAttribute('href')).toBe('/products/flags');
    expect(current?.className).toMatch(/aria-\[current=page\]:underline/);
    unmount(instance);
  });
});
