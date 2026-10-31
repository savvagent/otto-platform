/**
 * Where the public site lives, and how a page's path changes with its language.
 *
 * Everything here is pure and safe at module scope, because it is imported by
 * pages that are rendered at build time in Node as well as in the browser.
 *
 * **English is unprefixed and every other locale carries its code** (`/pricing`,
 * `/es/pricing`). That rule is written once, in [`localizedPath`], and
 * everything that emits a URL — links, the canonical tag, `hreflang`
 * alternates, the sitemap — goes through it, so a page cannot be linked under
 * one spelling and declared canonical under another.
 */

import { baseLocale, locales } from '$lib/paraglide/runtime';
import type { Locale } from '$lib/locale';

/**
 * The production origin, with no trailing slash.
 *
 * Absolute URLs are required in a canonical tag, an `hreflang` alternate, an
 * Open Graph URL and a sitemap — a relative one is either ignored or resolved
 * against whatever host a crawler happened to reach. Hard-coded rather than
 * read from the request because there is no request: these pages are written
 * at build time, and a preview deploy should still point crawlers at the real
 * site rather than at itself.
 */
export const SITE_ORIGIN = 'https://savvagent.com';

/** Where sales questions go. Shown on the marketing pages, never in the console. */
export const CONTACT_EMAIL = 'sales@savvagent.com';

/** Every locale the marketing pages are built in, base locale first. */
export const MARKETING_LOCALES: readonly Locale[] = locales;

/**
 * `og:locale` wants a language *and* a territory (`es_ES`), not a bare code.
 *
 * The territory is the language's largest market as Open Graph consumers
 * understand it; nothing else reads these values.
 */
export const OG_LOCALES: Record<Locale, string> = {
  en: 'en_US',
  es: 'es_ES',
  de: 'de_DE',
  fr: 'fr_FR',
  it: 'it_IT',
  hi: 'hi_IN'
};

/**
 * `path` as it is spelled in `lang`.
 *
 * `path` is the English (base) path and always starts with `/`. The root of a
 * prefixed locale is `/es`, not `/es/`: `trailingSlash = 'never'` makes the
 * slash a redirect, and the file on disk is `es.html`.
 */
export function localizedPath(lang: Locale, path: string): string {
  if (lang === baseLocale) return path;
  return `/${lang}${path === '/' ? '' : path}`;
}

export interface Alternate {
  /** A locale code, or `x-default` for "no better match". */
  hreflang: string;
  /** Absolute, on [`SITE_ORIGIN`]. */
  href: string;
}

/**
 * The `hreflang` set for one page: every locale's spelling of it, plus
 * `x-default` pointing at English.
 *
 * Each language version must list *all* of them, itself included — search
 * engines ignore an alternate that the other page does not link back to —
 * so the same list is emitted on every version and in the sitemap.
 */
export function alternates(path: string): Alternate[] {
  return [
    ...MARKETING_LOCALES.map((lang) => ({
      hreflang: lang,
      href: SITE_ORIGIN + localizedPath(lang, path)
    })),
    { hreflang: 'x-default', href: SITE_ORIGIN + localizedPath(baseLocale as Locale, path) }
  ];
}

/**
 * Split a pathname into its locale and its base (English) path — the inverse
 * of [`localizedPath`].
 *
 * The language switcher uses it to offer "this page, in German" rather than
 * "the German home page". Only a whole first segment that is a *prefixed*
 * locale counts: `/en/…` is not a URL this site has, and `/espresso` is not
 * Spanish.
 */
export function stripLocale(pathname: string): { lang: Locale; path: string } {
  const [, first, ...rest] = pathname.split('/');
  const lang = MARKETING_LOCALES.find((l) => l !== baseLocale && l === first);
  if (lang === undefined) return { lang: baseLocale as Locale, path: pathname };
  return { lang, path: `/${rest.join('/')}` };
}
