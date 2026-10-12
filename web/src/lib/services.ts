/**
 * The Otto products: linked from the console's header, and described on the
 * public marketing pages.
 *
 * Otto is split across hostnames: this console owns the account and the
 * organization (sign-in, passkeys, members, teams, SSO, usage, audit), and each
 * product service runs its own console for its own domain and signs in here
 * with OAuth. Each of those consoles links back to this one, so a person never
 * has to know a hostname.
 *
 * **It is deliberately a plain list.** A new service is one entry here, its
 * copy in the message catalogs, and nothing else: the marketing pages, the
 * sitemap and the build check all derive their product pages from it. The
 * console itself still knows nothing about what any of them *do* — it reads
 * only `name` and `url`.
 *
 * `url` is where the service's console lives, with no trailing slash. It is an
 * external origin: a link here is a full navigation, never a client-side route.
 * https only — `servicesIn` drops anything else, so a typo cannot put a
 * plaintext or `javascript:` link in the header.
 */

import { m } from '$lib/paraglide/messages';

/**
 * A product's marketing copy, as functions.
 *
 * **Called at render time, never at module load.** Paraglide's `m.*()` read
 * the locale when they are called; this module is evaluated once per build (or
 * once per page load), so a string captured at import would be frozen in
 * whichever language happened to be current then — every prerendered page
 * would say the same thing in the same language.
 */
export interface ServiceCopy {
  /** One short line, under the name. */
  tagline(): string;
  /** One or two sentences. */
  summary(): string;
  /** Four to six bullets. */
  features(): string[];
}

export interface Service {
  /** The product page's path segment: `/products/{slug}`. Lowercase, digits and `-`. */
  slug: string;
  /** Product name. A name, so it is never translated. */
  name: string;
  /** The service console's origin, e.g. `https://otto-factory.savvagent.com`. */
  url: string;
  /** The MCP endpoint an agent is pointed at, if the service has one. */
  mcpUrl?: string;
  copy: ServiceCopy;
}

const CONFIGURED: readonly Service[] = [
  {
    slug: 'factory',
    name: 'Otto Factory',
    url: 'https://otto-factory.savvagent.com',
    // `OF_RESOURCE_URI` in otto-factory's `fly.toml`: the MCP endpoint is
    // `/mcp` on the service's own origin.
    mcpUrl: 'https://otto-factory.savvagent.com/mcp',
    copy: {
      tagline: () => m.product_factory_tagline(),
      summary: () => m.product_factory_summary(),
      features: () => [
        m.product_factory_feature_jobs(),
        m.product_factory_feature_visibility(),
        m.product_factory_feature_leases(),
        m.product_factory_feature_trackers(),
        m.product_factory_feature_install()
      ]
    }
  },
  {
    slug: 'flags',
    name: 'Otto Flags',
    url: 'https://otto-flags.savvagent.com',
    mcpUrl: 'https://otto-flags.savvagent.com/mcp',
    copy: {
      tagline: () => m.product_flags_tagline(),
      summary: () => m.product_flags_summary(),
      features: () => [
        m.product_flags_feature_manage(),
        m.product_flags_feature_risk(),
        m.product_flags_feature_rollback(),
        m.product_flags_feature_evaluate(),
        m.product_flags_feature_auto_rollback()
      ]
    }
  }
];

/** A slug is one path segment and one file name: no case, no separators. */
const SLUG = /^[a-z0-9-]+$/;

function isHttps(raw: string): boolean {
  try {
    return new URL(raw).protocol === 'https:';
  } catch {
    return false;
  }
}

/** Keep only entries that are safe to render as an external link and a page path. */
export function servicesIn(candidates: readonly Service[]): Service[] {
  return candidates.filter(
    (service) =>
      isHttps(service.url) &&
      service.name.trim().length > 0 &&
      SLUG.test(service.slug) &&
      (service.mcpUrl === undefined || isHttps(service.mcpUrl))
  );
}

export const SERVICES: readonly Service[] = servicesIn(CONFIGURED);
