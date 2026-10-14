// @vitest-environment jsdom
/**
 * A link to a service from inside the console, as a person would meet it.
 *
 * A service with a web console is a plain external link, as before. One
 * without is a link to its product page's connect card, carries a visible
 * "Connector" badge so the difference shows before the click, and reads as
 * "Otto CXP, connector" to a screen reader.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { serviceBySlug } from '$lib/services';
import ServiceLink from './ServiceLink.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
});

function render(slug: string) {
  const instance = mount(ServiceLink, {
    target: container,
    props: { service: serviceBySlug(slug)!, variant: 'nav' }
  });
  flushSync();
  return { instance, link: container.querySelector('a')! };
}

describe('a link to a service', () => {
  it('leaves for the web console of a service that has one', () => {
    const { instance, link } = render('factory');

    expect(link.getAttribute('href')).toBe('https://otto-factory.savvagent.com');
    expect(link.textContent?.trim()).toBe('Otto Factory');
    expect(link.hasAttribute('aria-label')).toBe(false);
    expect(link.hasAttribute('data-sveltekit-reload')).toBe(false);

    unmount(instance);
  });

  it('goes to the connect card of a service that has none, badged as a connector', () => {
    const { instance, link } = render('cxp');

    expect(link.getAttribute('href')).toBe('/products/cxp#connect');
    // A marketing page, reached from the console: a full load, like every
    // link across that line.
    expect(link.hasAttribute('data-sveltekit-reload')).toBe(true);
    expect(link.getAttribute('aria-label')).toBe('Otto CXP, connector');
    expect(link.textContent?.replace(/\s+/g, ' ').trim()).toBe('Otto CXP Connector');

    unmount(instance);
  });
});
