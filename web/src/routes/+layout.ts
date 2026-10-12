/**
 * Only what both route groups share.
 *
 * `ssr` and `prerender` are deliberately *not* set here: the two groups want
 * opposite answers. `(console)` renders only in the browser because its pages
 * are behind a session cookie that must never reach a rendering server, while
 * `(marketing)` is prerendered at build time because its pages are public,
 * identical for every visitor, and should be indexable. Each group's own
 * `+layout.ts` says which it is.
 *
 * `trailingSlash = 'never'` does belong to both: `/pricing` and `/pricing/`
 * must not be two URLs, and the prerendered files are written as
 * `pricing.html` rather than `pricing/index.html` so the server can find them.
 */
export const trailingSlash = 'never';
