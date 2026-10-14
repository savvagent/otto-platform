/**
 * The Otto products: linked from the console's header, and described on the
 * public marketing pages.
 *
 * Otto is split across hostnames: this console owns the account and the
 * organization (sign-in, passkeys, members, teams, SSO, usage, audit), and each
 * product is a service on its own host that signs in here with OAuth.
 *
 * **Not every service has a web console.** Otto Factory serves one, which links
 * back to this console, so a person never has to know a hostname. Otto Flags
 * and Otto CXP are agent-only: their origin answers a browser with a JSON 404,
 * and the place a person uses them is their AI assistant, with the service
 * added as a custom connector. So the field is `consoleUrl`, and optional, and
 * a link to a service goes through `serviceLink`, which sends a service with no
 * console to its product page's connect card instead of to its origin.
 *
 * **It is deliberately a plain list.** A new service is one entry here plus its
 * copy in the message catalogs: the marketing pages and the sitemap derive
 * their product pages from it. The one exception is `scripts/check-build.mjs`,
 * which runs in plain Node without `$lib` and so keeps its own copy of the
 * slugs; `check-build.test.mjs` fails until that copy matches. The console
 * itself still knows nothing about what any of them *do* — it reads only
 * `name`, and where `serviceLink` says to go.
 *
 * `consoleUrl` and `mcpUrl` are https only — `servicesIn` drops anything else,
 * so a typo cannot put a plaintext or `javascript:` link in the header.
 */

import type { Locale } from '$lib/locale';
import { m } from '$lib/paraglide/messages';
import { localizedPath } from '$lib/site';

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
  /**
   * The product page's `<title>` after the name: a phrase, with no closing
   * punctuation, because it is joined to the name as `{name}: {title}` and a
   * title that ends in a full stop reads as a sentence in a search result.
   */
  title(): string;
  /**
   * The product page's meta description: at most 160 characters in every
   * locale (`services.test.ts` checks), which is roughly what a search result
   * shows before it truncates. `summary` is the longer, on-page version.
   */
  description(): string;
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
  /**
   * The origin of the service's own web console, with no trailing slash, e.g.
   * `https://otto-factory.savvagent.com` — or absent for a service that has
   * none. Absent is not "unknown": it is what makes every link to the service
   * point at its connect card, so set it only for an origin that answers a
   * browser with a page. An external origin, so a link to it is a full
   * navigation, never a client-side route.
   */
  consoleUrl?: string;
  /**
   * The MCP endpoint an agent is pointed at, if the service has one: the
   * "connector address" a person pastes into their assistant.
   */
  mcpUrl?: string;
  copy: ServiceCopy;
}

const CONFIGURED: readonly Service[] = [
  {
    slug: 'factory',
    name: 'Otto Factory',
    consoleUrl: 'https://otto-factory.savvagent.com',
    // `OF_RESOURCE_URI` in otto-factory's `fly.toml`: the MCP endpoint is
    // `/mcp` on the service's own origin.
    mcpUrl: 'https://otto-factory.savvagent.com/mcp',
    copy: {
      title: () => m.product_factory_title(),
      description: () => m.product_factory_description(),
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
    // No `consoleUrl`: the origin serves the API and `/mcp`, not a page.
    mcpUrl: 'https://otto-flags.savvagent.com/mcp',
    copy: {
      title: () => m.product_flags_title(),
      description: () => m.product_flags_description(),
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
  },
  {
    slug: 'cxp',
    name: 'Otto CXP',
    // No `consoleUrl`: the origin serves the API and `/mcp`, not a page.
    mcpUrl: 'https://otto-cxp.savvagent.com/mcp',
    copy: {
      title: () => m.product_cxp_title(),
      description: () => m.product_cxp_description(),
      tagline: () => m.product_cxp_tagline(),
      summary: () => m.product_cxp_summary(),
      features: () => [
        m.product_cxp_feature_profiles(),
        m.product_cxp_feature_support(),
        m.product_cxp_feature_feedback(),
        m.product_cxp_feature_scope()
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

/**
 * Keep only entries that are safe to render as an external link and a page path.
 *
 * An entry with neither a console nor an MCP endpoint is dropped too: there is
 * nowhere to send a person, and `serviceLink` would point at a connect card
 * the product page does not render.
 */
export function servicesIn(candidates: readonly Service[]): Service[] {
  return candidates.filter(
    (service) =>
      service.name.trim().length > 0 &&
      SLUG.test(service.slug) &&
      (service.consoleUrl === undefined || isHttps(service.consoleUrl)) &&
      (service.mcpUrl === undefined || isHttps(service.mcpUrl)) &&
      (service.consoleUrl !== undefined || service.mcpUrl !== undefined)
  );
}

export const SERVICES: readonly Service[] = servicesIn(CONFIGURED);

/** The service a product page's slug names, or `undefined` if none does. */
export function serviceBySlug(slug: string): Service | undefined {
  return SERVICES.find((service) => service.slug === slug);
}

/**
 * Where a link to a service goes, from anywhere in this site.
 *
 * `console` is the service's own web console, on its own origin. `connector`
 * is its product page's connect card (`#connect`), in `lang`: the page that
 * says how to add it to an AI assistant, which is where a service without a
 * console is used. The two are told apart in the type, not by sniffing the
 * href, because they want different markup — a `connector` link crosses from
 * the console into the marketing half and needs `data-sveltekit-reload`, and
 * says so with a badge.
 */
export type ServiceDestination =
  { kind: 'console'; href: string } | { kind: 'connector'; href: string };

export function serviceLink(service: Service, lang: Locale): ServiceDestination {
  if (service.consoleUrl) return { kind: 'console', href: service.consoleUrl };
  return { kind: 'connector', href: `${localizedPath(lang, `/products/${service.slug}`)}#connect` };
}

/**
 * The name an MCP client knows the service by: `otto-{slug}`, which is also
 * the first label of its host and the name each service's own docs use, so a
 * person who follows both ends up with one server rather than two.
 */
export function connectorName(service: Service): string {
  return `otto-${service.slug}`;
}

/** The Claude Code command that adds the service, or `undefined` without an MCP endpoint. */
export function claudeCodeCommand(service: Service): string | undefined {
  if (!service.mcpUrl) return undefined;
  return `claude mcp add --transport http ${connectorName(service)} ${service.mcpUrl}`;
}
