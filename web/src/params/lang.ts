import type { ParamMatcher } from '@sveltejs/kit';

import { baseLocale, locales } from '$lib/paraglide/runtime';

/**
 * The locales that appear as a URL prefix: every one but the base locale.
 *
 * English lives at unprefixed paths (`/pricing`), so `/en/pricing` would be a
 * second URL for the same page — duplicate content to a crawler, and a file
 * the build never writes. Derived from Paraglide's generated runtime rather
 * than typed out, so adding a locale to `project.inlang/settings.json` adds
 * its prefix too.
 *
 * The match is exact and case-sensitive, which is also what keeps
 * `[[lang=lang]]` from swallowing a console path like `/login`.
 */
const PREFIXED: ReadonlySet<string> = new Set(locales.filter((l) => l !== baseLocale));

export const match: ParamMatcher = (param) => PREFIXED.has(param);
