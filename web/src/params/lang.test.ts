import { describe, expect, it } from 'vitest';

import { baseLocale, locales } from '$lib/paraglide/runtime';

import { match } from './lang';

describe('the lang param matcher', () => {
  it('accepts every non-base locale', () => {
    for (const lang of ['es', 'de', 'fr', 'it', 'hi']) expect(match(lang), lang).toBe(true);
  });

  it('covers every locale but the base one', () => {
    expect(locales.filter((l) => match(l))).toEqual(locales.filter((l) => l !== baseLocale));
  });

  // `/en/pricing` would be a second URL for `/pricing`: duplicate content to a
  // crawler, and a page the build never emits.
  it('rejects the base locale', () => {
    expect(match('en')).toBe(false);
  });

  // Anything else is a console path or a 404, never a language: `/login` must
  // not be read as a page in the "login" locale.
  it.each(['', 'login', 'o', 'home', 'ES', 'es-MX', 'xx', 'pricing'])('rejects %j', (value) => {
    expect(match(value)).toBe(false);
  });
});
