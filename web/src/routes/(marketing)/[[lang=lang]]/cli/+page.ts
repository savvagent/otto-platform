import { baseLocale, locales } from '$lib/paraglide/runtime';

import type { EntryGenerator } from './$types';

/**
 * One prerendered CLI page per locale.
 *
 * The header links to `/cli` in each language, so the crawler would find them
 * anyway; they are listed so the page set does not depend on a link somewhere
 * else staying put, the same as the pricing and product pages. English is the
 * entry with no `lang`.
 *
 * No `load`: the page is static and the layout already provides `lang`.
 */
export const entries: EntryGenerator = () =>
  locales.map((lang) => (lang === baseLocale ? {} : { lang }));
