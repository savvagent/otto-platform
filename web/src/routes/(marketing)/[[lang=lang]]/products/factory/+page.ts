import { redirect } from '@sveltejs/kit';

import { baseLocale, locales, type Locale } from '$lib/paraglide/runtime';
import { localizedPath } from '$lib/site';

import type { EntryGenerator, PageLoad } from './$types';

/**
 * `/products/factory` is the product's old address, from before it was renamed
 * Otto Tower. Links to it are out in the world, so it answers with a redirect
 * to `/products/tower` (in the same locale) instead of a 404.
 *
 * The site is built to static files, so the redirect is prerendered: SvelteKit
 * writes an HTML page with a meta refresh and a script that navigate to the
 * target. A hosting-level 301 would be better for search engines; the entries
 * below make sure the file exists for every locale.
 */
export const entries: EntryGenerator = () =>
  locales.map((lang) => (lang === baseLocale ? {} : { lang }));

export const load: PageLoad = ({ params }) => {
  redirect(
    308,
    localizedPath((params.lang as Locale | undefined) ?? baseLocale, '/products/tower')
  );
};
