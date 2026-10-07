/**
 * Where to send the browser after a successful sign-in.
 *
 * `otto-web` redirects a signed-out visitor from `/oauth/authorize` to
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
 * browsers normalize `/\evil.test` the same way.
 */
export function safeNext(raw: string | null): string | undefined {
  if (!raw) return undefined;
  if (!raw.startsWith('/')) return undefined;
  if (raw.startsWith('//') || raw.startsWith('/\\')) return undefined;
  return raw;
}

/** True when `next` names a server route this app cannot render itself. */
export function isServerRoute(next: string): boolean {
  return next.startsWith('/oauth/') || next.startsWith('/api/') || next.startsWith('/.well-known/');
}
