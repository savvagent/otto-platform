import { baseLocale, locales } from '$lib/paraglide/runtime';

import type { EntryGenerator } from './$types';

/**
 * One prerendered landing page per locale.
 *
 * The crawler only finds pages something links to, and nothing links to
 * `/es` yet, so the locales are listed here. English is the entry with no
 * `lang` at all, which SvelteKit writes as `index.html`; the others become
 * `es.html`, `de.html` and so on.
 */
export const entries: EntryGenerator = () =>
  locales.map((lang) => (lang === baseLocale ? {} : { lang }));
