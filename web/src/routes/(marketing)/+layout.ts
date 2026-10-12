/**
 * The public pages are rendered at build time.
 *
 * The opposite of `(console)/+layout.ts`, for the opposite reason: nothing here
 * depends on who is asking, so every visitor — and every crawler — can be
 * handed the finished HTML from a static file. No session is read and no API
 * is called, which is what makes it safe to render outside the browser.
 */
export const prerender = true;
export const ssr = true;
