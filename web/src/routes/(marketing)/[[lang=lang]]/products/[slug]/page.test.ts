/**
 * Which product pages exist: one per service per locale, and nothing else.
 *
 * `entries` is what the prerender crawler is told to build even if nothing
 * links to it, and `load` is what turns a slug no service owns into a 404
 * rather than a page about `undefined`.
 */

import { isHttpError } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';

import { baseLocale, locales } from '$lib/paraglide/runtime';
import { SERVICES } from '$lib/services';
import { entries, load } from './+page';

type LoadEvent = Parameters<typeof load>[0];

describe('product page entries', () => {
  it('lists every service in every locale, English unprefixed', async () => {
    const all = await entries();
    expect(all).toHaveLength(SERVICES.length * locales.length);
    expect(all).toContainEqual({ slug: 'tower' });
    expect(all).toContainEqual({ lang: 'es', slug: 'flags' });
    expect(all).not.toContainEqual({ lang: baseLocale, slug: 'tower' });
  });
});

describe('product page load', () => {
  it('returns the slug of a known service', async () => {
    const data = await load({ params: { slug: 'flags' } } as unknown as LoadEvent);
    expect(data).toEqual({ slug: 'flags' });
  });

  it('throws a 404 for a slug no service owns', async () => {
    let thrown: unknown;
    try {
      await load({ params: { slug: 'nope' } } as unknown as LoadEvent);
    } catch (error) {
      thrown = error;
    }
    expect(isHttpError(thrown, 404)).toBe(true);
  });
});
