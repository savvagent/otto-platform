/**
 * A stand-in for `$app/state` in render tests, where there is no SvelteKit
 * router to provide one.
 *
 * Rune-backed, so a test that assigns `page.url` sees every `$derived` and
 * `$effect` that reads it re-run, exactly as a client-side navigation would
 * make them.
 */
export const page = $state({ url: new URL('http://localhost/') });
