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
  /** The org slug the user was last looking at, so `/` can go somewhere useful. */
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
   * Where `/` should land.
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

/** `owner` and `admin` may change the org; `member` may only look. */
export function isAdmin(role: Role | undefined): boolean {
  return role === 'owner' || role === 'admin';
}

export function isOwner(role: Role | undefined): boolean {
  return role === 'owner';
}
