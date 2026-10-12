import { baseLocale, locales } from '$lib/paraglide/runtime';

import type { EntryGenerator } from './$types';

/**
 * One prerendered pricing page per locale.
 *
 * The header links to `/pricing` in each language, so the crawler would find
 * them anyway; they are listed so the page set does not depend on a link
 * somewhere else staying put, the same as the landing and product pages.
 * English is the entry with no `lang`.
 *
 * No `load`: the plans are fetched in the browser (see `+page.svelte`), and
 * the layout already provides `lang`.
 */
export const entries: EntryGenerator = () =>
  locales.map((lang) => (lang === baseLocale ? {} : { lang }));
