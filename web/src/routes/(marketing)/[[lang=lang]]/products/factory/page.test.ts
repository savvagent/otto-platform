/**
 * The old product address redirects to the renamed one, in the same locale.
 */

import { isRedirect } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';

import { baseLocale, locales } from '$lib/paraglide/runtime';
import { entries, load } from './+page';

type LoadEvent = Parameters<typeof load>[0];

function redirectOf(lang?: string) {
  try {
    load({ params: { lang } } as unknown as LoadEvent);
  } catch (thrown) {
    if (isRedirect(thrown)) return thrown;
    throw thrown;
  }
  throw new Error('load did not redirect');
}

describe('legacy factory product page', () => {
  it('is prerendered once per locale, English unprefixed', async () => {
    const all = await entries();
    expect(all).toHaveLength(locales.length);
    expect(all).toContainEqual({});
    expect(all).toContainEqual({ lang: 'es' });
    expect(all).not.toContainEqual({ lang: baseLocale });
  });

  it('redirects English to /products/tower', () => {
    const r = redirectOf(undefined);
    expect(r.status).toBe(308);
    expect(r.location).toBe('/products/tower');
  });

  it('keeps the locale prefix', () => {
    expect(redirectOf('de').location).toBe('/de/products/tower');
  });
});
