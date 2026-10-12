import { error } from '@sveltejs/kit';

import { baseLocale, locales } from '$lib/paraglide/runtime';
import { SERVICES, serviceBySlug } from '$lib/services';

import type { EntryGenerator, PageLoad } from './$types';

/**
 * One prerendered page per product per locale, derived from `SERVICES`.
 *
 * Listed rather than left to the crawler because a page nothing links to is a
 * page the crawler never writes, and `scripts/check-build.mjs` would then
 * report it missing. English is the entry with no `lang`, as on the landing
 * page.
 */
export const entries: EntryGenerator = () =>
  SERVICES.flatMap(({ slug }) =>
    locales.map((lang) => (lang === baseLocale ? { slug } : { lang, slug }))
  );

/**
 * The slug, once it is known to name a service.
 *
 * **Only the slug is returned, and no message is called.** The service's copy
 * is a set of `m.*()` calls, and a `load` may run while another page's locale
 * override is in place (see `../../+layout.ts`); the component looks the
 * service up again and calls its copy while it renders, which is the one
 * place the locale is guaranteed to be this page's.
 */
export const load: PageLoad = ({ params }) => {
  const service = serviceBySlug(params.slug);
  if (service === undefined) error(404, 'Not found');
  return { slug: service.slug };
};
