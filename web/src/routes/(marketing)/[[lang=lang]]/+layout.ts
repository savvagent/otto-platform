import type { LayoutLoad } from './$types';

/**
 * Which language this marketing page is in, from its URL alone.
 *
 * English is unprefixed (`/pricing`) and every other locale carries its code
 * (`/es/pricing`); the `lang` matcher only accepts the non-base locales, so an
 * absent param means English. The URL is the only input on purpose: a
 * prerendered page cannot read `localStorage` or `navigator.languages`, and the
 * same file is served to every visitor.
 */
export const load: LayoutLoad = ({ params }) => ({ lang: params.lang ?? 'en' });
