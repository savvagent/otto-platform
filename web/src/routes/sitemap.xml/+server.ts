import { sitemapXml } from '$lib/sitemap';

import type { RequestHandler } from './$types';

/**
 * `/sitemap.xml`, written to a file at build time.
 *
 * Outside both route groups because it is neither a console page nor a
 * marketing one: it has no layout and no language. Prerendered, so there is
 * still no server-side rendering at runtime — the Rust server and the Worker
 * serve it like any other static file. Its contents are not crawled by the
 * prerenderer, which is why it can list pages before they exist.
 */
export const prerender = true;

export const GET: RequestHandler = () =>
  new Response(sitemapXml(), { headers: { 'content-type': 'application/xml' } });
