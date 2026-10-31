/**
 * Where to send the browser after a successful sign-in.
 *
 * `savvagent-web` redirects a signed-out visitor from `/oauth/authorize` to
 * `/login?next=/oauth/authorize?…`, so `next` routinely names a *server* route
 * rather than a page in this app. That is why the caller does a full
 * navigation instead of `goto`: the client router has no `/oauth/authorize`,
 * and routing to it internally would render a 404 in the middle of an OAuth
 * flow.
 *
 * **`next` is attacker-supplied.** Anyone can send a victim a link with any
 * `next` they like, so it is accepted only as a same-origin absolute path. The
 * `//` case is the one worth naming: `//evil.test/` is a protocol-relative URL
 * that a browser resolves to another origin, and it passes a naive
 * "starts with `/`" check. A back-slash is rejected for the same reason —
 * browsers normalize `/\evil.test` the same way. So are control characters,
 * matching the server's `safe_next`: browsers strip a tab or newline from a URL
 * before resolving it, which turns `/\t/evil.test` into `//evil.test`.
 */
export function safeNext(raw: string | null): string | undefined {
  if (!raw) return undefined;
  if (!raw.startsWith('/')) return undefined;
  if (raw.startsWith('//') || raw.startsWith('/\\')) return undefined;
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return undefined;
  return raw;
}

/** True when `next` names a server route this app cannot render itself. */
export function isServerRoute(next: string): boolean {
  return next.startsWith('/oauth/') || next.startsWith('/api/') || next.startsWith('/.well-known/');
}

/** Where the console's own home is. `/` is the public landing page. */
export const CONSOLE_HOME = '/home';

/**
 * `safeNext`, read the way the console means it.
 *
 * Inside the console an explicit `next=/` can only mean "the console home": it
 * comes from a link written before `/` became the public landing page, or from
 * someone who typed it. Following it literally would sign a visitor in and
 * then drop them on a marketing page that looks signed out. Anything else is
 * `safeNext`'s answer unchanged, so the same-origin rule still holds.
 */
export function consoleNext(raw: string | null): string | undefined {
  const next = safeNext(raw);
  return next === '/' ? CONSOLE_HOME : next;
}
