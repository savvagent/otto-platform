import { isSupported, type Locale } from '$lib/locale';

import type { LayoutLoad } from './$types';

/**
 * Which language this marketing page is in, from its URL alone.
 *
 * English is unprefixed (`/pricing`) and every other locale carries its code
 * (`/es/pricing`); the `lang` matcher only accepts the non-base locales, so an
 * absent param means English. The URL is the only input on purpose: a
 * prerendered page cannot read `localStorage` or `navigator.languages`, and the
 * same file is served to every visitor.
 *
 * **No message is rendered here, and none may be.** `load` functions for
 * different pages can interleave during prerendering, so the locale override
 * the layout component installs is not guaranteed to be this page's while a
 * `load` runs. Messages are called only from components, which Svelte renders
 * synchronously, one page at a time.
 */
export const load: LayoutLoad = ({ params }) => ({
  lang: (isSupported(params.lang) ? params.lang : 'en') as Locale
});
