/**
 * Who is signed in, held in one place.
 *
 * A rune-backed module, not a Svelte store: `$state` in a `.svelte.ts` file is
 * reactive anywhere it is imported, and the whole console reads the same object
 * rather than each page fetching `/api/me` on mount.
 *
 * **There is no cached credential here.** The session lives in an `HttpOnly`
 * cookie the browser holds; this object caches only the *answer* to "who is
 * that cookie", which is a rendering convenience. Anything that changes who the
 * caller is — signing in, signing out, accepting an invitation, enrolling —
 * calls `refresh()`, and the server re-resolves the cookie on every request
 * regardless. The worst a stale copy here can do is render the wrong name for
 * one paint; it can never grant access, because nothing downstream trusts it.
 */

import { api, ApiError } from './api';
import type { Me, Membership, Role } from './types';

class Session {
  /** `undefined` while the first `/api/me` is still in flight. */
  me = $state<Me | undefined>(undefined);
  /** False until the first resolution attempt finishes, success or not. */
  ready = $state(false);
  /** The org slug the user was last looking at, so `/home` can go somewhere useful. */
  lastOrg = $state<string | undefined>(undefined);

  get signedIn(): boolean {
    return this.me !== undefined;
  }

  get orgs(): Membership[] {
    return this.me?.orgs ?? [];
  }

  /**
   * Re-resolve the session cookie.
   *
   * A `401` is not an error to report — it is the ordinary answer for a visitor
   * who has not signed in yet, and the layout uses it to decide whether to show
   * the app or the login page. Anything else is left to throw: a `500` from
   * `/api/me` is not "you are signed out", and silently treating it as such
   * would log everyone out during an incident.
   */
  async refresh(): Promise<Me | undefined> {
    try {
      this.me = await api.me();
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthenticated) {
        this.me = undefined;
      } else {
        this.ready = true;
        throw error;
      }
    }
    this.ready = true;
    return this.me;
  }

  /** Drop the local copy. The cookie is cleared by `POST /api/auth/logout`. */
  clear(): void {
    this.me = undefined;
    this.lastOrg = undefined;
  }

  membership(slug: string): Membership | undefined {
    return this.orgs.find((m) => m.orgSlug === slug);
  }

  roleIn(slug: string): Role | undefined {
    return this.membership(slug)?.role;
  }

  /**
   * Where `/home`, the console's entry point, should land.
   *
   * The last org visited, else the first membership, else nowhere — a brand new
   * account with no orgs is sent to create one rather than to an empty shell.
   */
  get homeOrg(): string | undefined {
    if (this.lastOrg && this.membership(this.lastOrg)) return this.lastOrg;
    return this.orgs[0]?.orgSlug;
  }
}

export const session = new Session();

/**
 * Where a "way into the console" link goes, and so what it says.
 *
 * `signup` reads "Create account"; `console` reads "Open console" and goes to
 * the home org, or to creating one for an account that has none — the same
 * place `/home` would send them, so the marketing pages and the console agree.
 */
export type ConsoleEntry = { kind: 'signup'; href: '/signup' } | { kind: 'console'; href: string };

/**
 * The one rule for that link, beside `homeOrg` because it is a reading of it.
 *
 * Takes the two fields rather than reading `session` itself so it can be
 * tested with plain objects; callers pass `session`. Called inside a
 * `$derived` or the markup, it re-runs when the session resolves.
 */
export function consoleEntry(who: Pick<Session, 'signedIn' | 'homeOrg'>): ConsoleEntry {
  if (!who.signedIn) return { kind: 'signup', href: '/signup' };
  return { kind: 'console', href: who.homeOrg ? `/o/${who.homeOrg}` : '/orgs/new' };
}

/** `owner` and `admin` may change the org; `member` may only look. */
export function isAdmin(role: Role | undefined): boolean {
  return role === 'owner' || role === 'admin';
}

export function isOwner(role: Role | undefined): boolean {
  return role === 'owner';
}
