import { CONSOLE_HOME, consoleNext, isServerRoute } from './next';

/** What the console's routing guard sees. */
export interface GuardState {
  signedIn: boolean;
  /** Signed in, but signup's second step (the address) is still to come. */
  needsProfile: boolean;
  /** The current route is one of the doors: reachable without a session. */
  isPublic: boolean;
  /** `pathname + search` of the current URL. */
  path: string;
  /** The raw `next` query parameter, attacker-supplied. */
  next: string | null;
}

/**
 * Where the guard sends the browser, if anywhere.
 *
 * `goto` is a client-side navigation; `assign` is a full one, for a server
 * route such as `/oauth/authorize` that the client router cannot render.
 */
export type GuardMove = { kind: 'goto'; to: string } | { kind: 'assign'; to: string } | null;

/**
 * The console layout's routing guard, as a pure decision.
 *
 * Kept out of `(console)/+layout.svelte` so it can be tested without mounting
 * the layout, its session, and the API behind it. The layout supplies the
 * state and performs the move; every rule lives here.
 */
export function guard(state: GuardState): GuardMove {
  if (!state.signedIn) {
    if (state.isPublic) return null;
    // The console home has no content of its own, so there is nothing to come
    // back to: plain `/login`. `/` is the marketing page and never reaches this
    // guard; it is listed only so a bare `/` can never become `next=/`.
    const home = state.path === '/' || state.path === CONSOLE_HOME;
    return {
      kind: 'goto',
      to: home ? '/login' : `/login?next=${encodeURIComponent(state.path)}`
    };
  }

  // One signed-in visitor stays on a door: signup creates the account from the
  // passkey and asks for an address on the step after, so between the two the
  // account is signed in and on `/signup` on purpose. Bouncing it to the home
  // the moment the session appears makes that second step unreachable — which
  // is exactly what it did until a browser test caught it.
  if (!state.isPublic || state.needsProfile) return null;

  // Honour `next` rather than always landing on the home. A language change
  // detected at sign-in reloads this page, and the reload lands back here
  // signed in — so without this, arriving with a stored locale that differs
  // from the browser's silently costs the visitor their destination.
  // `consoleNext` is what makes an attacker-supplied `next` safe to follow.
  const next = consoleNext(state.next);
  if (next && isServerRoute(next)) return { kind: 'assign', to: next };
  return { kind: 'goto', to: next ?? CONSOLE_HOME };
}
