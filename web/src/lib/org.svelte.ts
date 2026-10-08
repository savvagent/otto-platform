/**
 * The org the current page is about, resolved once by `o/[org]/+layout.svelte`
 * and read by everything under it.
 *
 * Context rather than a module-level singleton: the org is a property of a
 * position in the route tree, not of the application, and a singleton would
 * survive a navigation to a different org for exactly as long as it takes the
 * new layout to finish fetching — which is long enough to render one org's
 * heading over another's data.
 *
 * The role held here is for *rendering*, never for authorization. Hiding a
 * button a member may not press is a courtesy; the server decides, on every
 * request, through `OrgCtx`. Nothing in this console is prevented by a `$derived`.
 */

import { getContext, setContext } from 'svelte';
import type { Org, Role } from './types';

const KEY = Symbol('otto.org');

export class OrgContext {
  org = $state<Org | undefined>(undefined);
  role = $state<Role | undefined>(undefined);

  /**
   * The slug is read from the route on every access rather than copied into
   * state and kept in sync. Copying is the version of this that has a bug: the
   * copy and the URL disagree for one frame after a navigation between two
   * orgs, and that frame is where a page fetches org A's data under org B's
   * heading.
   */
  readonly #slug: () => string;

  constructor(slug: () => string) {
    this.#slug = slug;
  }

  get slug(): string {
    return this.#slug();
  }

  get isAdmin(): boolean {
    return this.role === 'owner' || this.role === 'admin';
  }

  get isOwner(): boolean {
    return this.role === 'owner';
  }

  /** The display name, falling back to the slug while the fetch is in flight. */
  get title(): string {
    return this.org?.name ?? this.slug;
  }
}

export function provideOrg(context: OrgContext): void {
  setContext(KEY, context);
}

export function useOrg(): OrgContext {
  const context = getContext<OrgContext | undefined>(KEY);
  if (!context) {
    // A page under `o/[org]` that cannot find this was mounted outside the org
    // layout — a routing mistake, and one that would otherwise show up as an
    // undefined slug in a URL and a confusing 404 from the API.
    throw new Error('useOrg() called outside the organization layout');
  }
  return context;
}
