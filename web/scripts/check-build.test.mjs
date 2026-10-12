import { describe, expect, it } from 'vitest';

import { MARKETING_LOCALES, SITE_ORIGIN as SITE_TS_ORIGIN, localizedPath } from '../src/lib/site';
import { MARKETING_PATHS } from '../src/lib/sitemap';
import {
  PAGE_PATHS,
  SITE_ORIGIN,
  checkPage,
  checkShell,
  expectedPages,
  fileFor
} from './check-build.mjs';

const settings = { baseLocale: 'en', locales: ['en', 'es', 'de', 'fr', 'it', 'hi'] };

describe('the copies this script keeps of the app’s rules', () => {
  it('lists the same pages as the sitemap', () => {
    expect(PAGE_PATHS).toEqual(MARKETING_PATHS);
  });

  it('uses the same origin and locale spelling as $lib/site', () => {
    expect(SITE_ORIGIN).toBe(SITE_TS_ORIGIN);
    const pages = expectedPages(settings);
    for (const lang of MARKETING_LOCALES) {
      for (const path of MARKETING_PATHS) {
        const canonical = SITE_ORIGIN + localizedPath(lang, path);
        expect(pages).toContainEqual(expect.objectContaining({ lang, canonical }));
      }
    }
  });
});

describe('fileFor', () => {
  it.each([
    ['/', 'index.html'],
    ['/pricing', 'pricing.html'],
    ['/es', 'es.html'],
    ['/es/pricing', 'es/pricing.html'],
    ['/products/flags', 'products/flags.html'],
    ['/hi/products/flags', 'hi/products/flags.html']
  ])('%s -> %s', (path, file) => {
    expect(fileFor(path)).toBe(file);
  });
});

describe('expectedPages', () => {
  it('is every page in every locale', () => {
    const pages = expectedPages(settings);
    expect(pages).toHaveLength(PAGE_PATHS.length * settings.locales.length);
    expect(pages).toContainEqual({
      file: 'es/pricing.html',
      lang: 'es',
      canonical: 'https://otto.savvagent.com/es/pricing'
    });
    expect(pages).toContainEqual({
      file: 'index.html',
      lang: 'en',
      canonical: 'https://otto.savvagent.com/'
    });
  });
});

describe('checkPage', () => {
  const expected = { file: 'de.html', lang: 'de', canonical: 'https://otto.savvagent.com/de' };
  const good =
    '<html lang="de" class="h-full"><head><meta name="robots" content="index, follow"/>' +
    '<link rel="canonical" href="https://otto.savvagent.com/de"/></head></html>';

  it('passes a correct page', () => {
    expect(checkPage(good, expected)).toEqual([]);
  });

  it('names each thing that is wrong', () => {
    const bad = '<html lang="en"><head><link rel="canonical" href="https://otto.savvagent.com/"/>';
    const errors = checkPage(bad, expected);
    expect(errors).toHaveLength(3);
    expect(errors.join('\n')).toMatch(/lang="de"/);
    expect(errors.join('\n')).toMatch(/canonical/);
    expect(errors.join('\n')).toMatch(/index, follow/);
  });
});

describe('checkShell', () => {
  it('wants English and no index directive', () => {
    expect(checkShell('<html lang="en" class="h-full"><head></head>')).toEqual([]);
    expect(
      checkShell('<html lang="es"><meta name="robots" content="index, follow"/>')
    ).toHaveLength(2);
  });
});
