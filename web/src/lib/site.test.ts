import { describe, expect, it } from 'vitest';

import {
  CONTACT_EMAIL,
  MARKETING_LOCALES,
  OG_LOCALES,
  SITE_ORIGIN,
  alternates,
  localizedPath,
  stripLocale
} from './site';

describe('the site constants', () => {
  it('names the production origin, with no trailing slash', () => {
    expect(SITE_ORIGIN).toBe('https://otto.savvagent.com');
    expect(CONTACT_EMAIL).toBe('sales@savvagent.com');
  });

  it('offers every locale, English first', () => {
    expect(MARKETING_LOCALES).toEqual(['en', 'es', 'de', 'fr', 'it', 'hi']);
    for (const lang of MARKETING_LOCALES) expect(OG_LOCALES[lang]).toMatch(/^[a-z]{2}_[A-Z]{2}$/);
  });
});

describe('localizedPath', () => {
  it.each([
    ['en', '/', '/'],
    ['en', '/pricing', '/pricing'],
    ['es', '/', '/es'],
    ['es', '/pricing', '/es/pricing'],
    ['hi', '/products/factory', '/hi/products/factory']
  ] as const)('%s %s -> %s', (lang, path, expected) => {
    expect(localizedPath(lang, path)).toBe(expected);
  });
});

describe('alternates', () => {
  it('lists every locale plus x-default, as absolute URLs', () => {
    const links = alternates('/pricing');
    expect(links).toEqual([
      { hreflang: 'en', href: 'https://otto.savvagent.com/pricing' },
      { hreflang: 'es', href: 'https://otto.savvagent.com/es/pricing' },
      { hreflang: 'de', href: 'https://otto.savvagent.com/de/pricing' },
      { hreflang: 'fr', href: 'https://otto.savvagent.com/fr/pricing' },
      { hreflang: 'it', href: 'https://otto.savvagent.com/it/pricing' },
      { hreflang: 'hi', href: 'https://otto.savvagent.com/hi/pricing' },
      { hreflang: 'x-default', href: 'https://otto.savvagent.com/pricing' }
    ]);
  });

  it('writes the root without a trailing slash for prefixed locales', () => {
    const links = alternates('/');
    expect(links.find((l) => l.hreflang === 'de')?.href).toBe('https://otto.savvagent.com/de');
    expect(links.find((l) => l.hreflang === 'x-default')?.href).toBe('https://otto.savvagent.com/');
  });
});

describe('stripLocale', () => {
  it.each([
    ['/', { lang: 'en', path: '/' }],
    ['/pricing', { lang: 'en', path: '/pricing' }],
    ['/es', { lang: 'es', path: '/' }],
    ['/es/pricing', { lang: 'es', path: '/pricing' }],
    ['/fr/products/flags', { lang: 'fr', path: '/products/flags' }],
    // Not a prefix: the base locale owns unprefixed paths, and a segment that
    // merely starts with a locale code is not one.
    ['/en/pricing', { lang: 'en', path: '/en/pricing' }],
    ['/espresso', { lang: 'en', path: '/espresso' }]
  ])('%s', (pathname, expected) => {
    expect(stripLocale(pathname)).toEqual(expected);
  });

  it('round-trips with localizedPath', () => {
    for (const lang of MARKETING_LOCALES) {
      for (const path of ['/', '/pricing', '/products/factory']) {
        expect(stripLocale(localizedPath(lang, path))).toEqual({ lang, path });
      }
    }
  });
});
