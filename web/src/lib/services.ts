/**
 * The other Otto consoles, linked from this one's header.
 *
 * Otto is split across hostnames: this console owns the account and the
 * organization (sign-in, passkeys, members, teams, SSO, usage, audit), and each
 * product service runs its own console for its own domain and signs in here
 * with OAuth. Each of those consoles links back to this one, so a person never
 * has to know a hostname.
 *
 * **This is the placeholder hook, and it is deliberately a plain list.** A new
 * service is one entry. Nothing else in the bundle knows what any of them do,
 * which keeps this console from learning about a product it does not serve.
 *
 * `url` is where the service's console lives, with no trailing slash. It is an
 * external origin: a link here is a full navigation, never a client-side route.
 * https only — `servicesIn` drops anything else, so a typo cannot put a
 * plaintext or `javascript:` link in the header.
 */
export interface Service {
  /** Product name. A name, so it is never translated. */
  name: string;
  /** The service console's origin, e.g. `https://otto-factory.savvagent.com`. */
  url: string;
}

const CONFIGURED: readonly Service[] = [
  { name: 'Otto Factory', url: 'https://otto-factory.savvagent.com' }
];

/** Keep only entries that are safe to render as an external link. */
export function servicesIn(candidates: readonly Service[]): Service[] {
  return candidates.filter((service) => {
    try {
      return new URL(service.url).protocol === 'https:' && service.name.trim().length > 0;
    } catch {
      return false;
    }
  });
}

export const SERVICES: readonly Service[] = servicesIn(CONFIGURED);
