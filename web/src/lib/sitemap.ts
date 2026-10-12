/**
 * `sitemap.xml`, built from the same page list and URL rules the pages use.
 *
 * One `<url>` per page per locale, each listing every language version as an
 * `xhtml:link` alternate plus `x-default`. That is the sitemap form of the
 * `hreflang` tags `Seo.svelte` puts in each page's head; declaring them in
 * both places is redundant on purpose, since a crawler that has not fetched a
 * page yet can only learn its siblings from here.
 *
 * Only the public marketing pages are listed. Console routes are `noindex`
 * and disallowed in `robots.txt`.
 */

import { MARKETING_LOCALES, SITE_ORIGIN, alternates, localizedPath } from './site';
import { SERVICES } from './services';

/**
 * Every marketing page, by its English path.
 *
 * `scripts/check-build.mjs` keeps its own copy of this list (it runs in plain
 * Node, without SvelteKit's `$lib` alias), and its test asserts the two agree.
 */
export const MARKETING_PATHS: readonly string[] = [
  '/',
  '/pricing',
  ...SERVICES.map((service) => `/products/${service.slug}`)
];

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;'
};

function escapeXml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export function sitemapXml(paths: readonly string[] = MARKETING_PATHS): string {
  const urls = paths.flatMap((path) => {
    const links = alternates(path)
      .map(
        (alt) =>
          `    <xhtml:link rel="alternate" hreflang="${alt.hreflang}" href="${escapeXml(alt.href)}"/>`
      )
      .join('\n');
    return MARKETING_LOCALES.map(
      (lang) =>
        `  <url>\n    <loc>${escapeXml(SITE_ORIGIN + localizedPath(lang, path))}</loc>\n${links}\n  </url>`
    );
  });
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ...urls,
    '</urlset>',
    ''
  ].join('\n');
}
