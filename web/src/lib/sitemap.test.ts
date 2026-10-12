import { describe, expect, it } from 'vitest';

import { SERVICES } from './services';
import { MARKETING_PATHS, sitemapXml } from './sitemap';

describe('the marketing page list', () => {
  it('is the landing page, pricing, and one page per product', () => {
    expect(MARKETING_PATHS).toEqual([
      '/',
      '/pricing',
      ...SERVICES.map((s) => `/products/${s.slug}`)
    ]);
  });
});

describe('sitemapXml', () => {
  const xml = sitemapXml(['/', '/pricing']);

  it('declares the sitemap and xhtml namespaces', () => {
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n')).toBe(true);
    expect(xml).toContain('xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"');
    expect(xml).toContain('xmlns:xhtml="http://www.w3.org/1999/xhtml"');
  });

  it('has one <url> per page per locale', () => {
    expect(xml.match(/<url>/g)).toHaveLength(2 * 6);
    expect(xml).toContain('<loc>https://otto.savvagent.com/</loc>');
    expect(xml).toContain('<loc>https://otto.savvagent.com/es</loc>');
    expect(xml).toContain('<loc>https://otto.savvagent.com/hi/pricing</loc>');
  });

  it('lists every alternate, plus x-default, under each <url>', () => {
    const entry = xml.split('<url>')[1] ?? '';
    expect(entry.match(/<xhtml:link /g)).toHaveLength(7);
    expect(entry).toContain(
      '<xhtml:link rel="alternate" hreflang="x-default" href="https://otto.savvagent.com/"/>'
    );
    expect(entry).toContain(
      '<xhtml:link rel="alternate" hreflang="fr" href="https://otto.savvagent.com/fr"/>'
    );
  });

  it('escapes what XML cannot carry verbatim', () => {
    expect(sitemapXml(['/a&b'])).toContain('<loc>https://otto.savvagent.com/a&amp;b</loc>');
  });
});
