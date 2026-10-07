/**
 * The console renders entirely in the browser.
 *
 * `ssr = false` is not a performance choice. The session is an `HttpOnly`,
 * `__Host-`-prefixed cookie; a SvelteKit server rendering these pages would
 * have to hold that credential to fetch on the user's behalf, which means a
 * second process with the keys to every console session, for pages that are
 * behind a login and cannot be cached. Keeping the fetch in the browser keeps
 * the cookie in exactly one place.
 *
 * `prerender = false` follows: there is no page here whose content is knowable
 * without a session. The static adapter still emits the shell, and its
 * `fallback` serves it for any deep link.
 */
export const ssr = false;
export const prerender = false;
export const trailingSlash = 'never';
