/**
 * The console at the edge, and the one origin a browser is ever allowed to see.
 *
 * Cloudflare serves the built SPA from its own network and forwards everything
 * dynamic (`/api`, `/oauth`, `/sso`, `/.well-known`, and the health probes) to
 * `otto-platform-server`. The browser talks to exactly one hostname, which is
 * not a performance decision: the console's session is an `HttpOnly`,
 * `__Host-` prefixed cookie, and `__Host-` means the browser refuses to store it
 * unless it is `Secure`, has `Path=/`, and carries no `Domain`. Put the SPA on
 * one hostname and the API on another and that cookie cannot be sent at all; no
 * CORS header rescues it.
 *
 * The same single hostname is what makes passkeys work. The WebAuthn relying
 * party id is the host of the server's `OTTO_PUBLIC_URL` (`otto.savvagent.com`),
 * and a browser only completes a ceremony for an rp_id that is a suffix of the
 * page's own origin. The origin the browser sees is this Worker's hostname, so
 * the two match; the Fly hostname never appears in a ceremony.
 *
 * This Worker therefore proxies rather than redirects.
 */

/**
 * Path prefixes that belong to `otto-platform-server` rather than to the
 * console's own client-side routing. **This list mirrors `API_PREFIXES` in
 * `crates/otto-platform-server/src/lib.rs`, minus the server-to-server paths in
 * `NEVER_PROXIED`** and must not drift from it: the server keeps the same list
 * to decide what gets a JSON `404` instead of the SPA shell, and a prefix that
 * exists on one side only is a route that behaves differently depending on
 * whether Cloudflare is in front.
 *
 * `/healthz` and `/readyz` are here and not on the server's list because the
 * server mounts them as real routes ahead of its SPA fallback. At the edge there
 * is no such precedence: anything not proxied is answered from the asset
 * bundle, so leaving them out would make `/readyz` return the console's HTML
 * with a `200`, which is the shape that keeps a health check green while the
 * database is gone.
 */
export const ORIGIN_PREFIXES = ['/api', '/oauth', '/sso', '/.well-known', '/healthz', '/readyz'];

/**
 * Paths that exist on the origin for resource servers, and are refused here.
 *
 * `/oauth/introspect` and `/internal/*` authenticate with a resource server's
 * own credential and are called server to server, at the origin's own hostname
 * (`otto-platform.fly.dev`). A browser has no business there, so the public
 * hostname does not carry them. Proxying them would be harmless in the sense
 * that they are credential-checked either way, but a second public path to a
 * credential check is a second thing to rate-limit, log and reason about, and
 * the edge's `cf-connecting-ip` header means nothing to a caller that is not a
 * browser. Refused with the same JSON `404` the origin gives an unknown path, so
 * the answer does not advertise that the route exists.
 */
export const NEVER_PROXIED = ['/internal', '/oauth/introspect'];

/**
 * A path as the origin's router would see it after the proxy and the browser
 * have both had their way with it: percent-decoded, with repeated slashes
 * collapsed. `/oauth//introspect` and `/oauth/%69ntrospect` are the same
 * request as `/oauth/introspect` to anything that normalises, and a guard that
 * compares the raw string is a guard with two doors.
 */
function normalise(path: string): string {
  let decoded = path;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    // A malformed escape cannot be decoded; compare it as written.
  }
  return decoded.replace(/\/{2,}/g, '/');
}

function underPrefix(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

/**
 * Prefix matching on segment boundaries, exactly as the server does it.
 *
 * `startsWith` alone is wrong and quietly so: `/apiary` is a legal org slug and
 * belongs to the console. Sending it to the origin would answer a JSON `404` for
 * a route the SPA was going to render.
 */
export function belongsToOrigin(path: string): boolean {
  const p = normalise(path);
  return underPrefix(p, ORIGIN_PREFIXES) && !isNeverProxied(p);
}

/** True for the server-to-server paths this Worker refuses to carry. */
export function isNeverProxied(path: string): boolean {
  return underPrefix(normalise(path), NEVER_PROXIED);
}

export interface Env {
  /** The built `web/build` bundle, uploaded with the Worker. */
  ASSETS: Fetcher;
  /** Where `otto-platform-server` actually listens, e.g. `https://otto-platform.fly.dev`. */
  OTTO_ORIGIN: string;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });

/**
 * The SPA shell, as the asset binding names it.
 *
 * adapter-static writes it to `200.html`, but the binding's default
 * `html_handling: "auto-trailing-slash"` answers `/200.html` with a `307` to
 * `/200`, so `/200` is the name that returns the file.
 */
const SHELL = '/200';

/**
 * The shell, answering with a `200` and `X-Robots-Tag: noindex, nofollow`.
 *
 * It is the same HTML for every route it stands in for, so an indexed copy is
 * a search result for `/o/acme/members` that renders a login prompt. The
 * prerendered pages are the ones meant to be found, and they pass through
 * without the header.
 *
 * The header goes on a copy: responses from the asset binding have immutable
 * headers, and setting one in place throws.
 */
async function shell(request: Request, env: Env): Promise<Response | undefined> {
  const found = await env.ASSETS.fetch(
    new Request(new URL(SHELL, request.url), { method: request.method })
  );
  if (!found.ok) return undefined;
  const headers = new Headers(found.headers);
  headers.set('x-robots-tag', 'noindex, nofollow');
  return new Response(found.body, { status: 200, headers });
}

/**
 * True when the last path segment has no `.`: a page route rather than a file.
 * A missing `/_app/x.js` must stay a `404`; answered with HTML it is a syntax
 * error in the browser and a cache entry nobody can explain.
 */
function extensionless(path: string): boolean {
  return !(path.split('/').pop() ?? '').includes('.');
}

/**
 * The bundle side of the Worker: prerendered pages and assets as themselves,
 * and the shell for any page route that has no file.
 *
 * `not_found_handling` is `"none"` (see wrangler.jsonc), so the binding's
 * `404` reaches this function and the shell is chosen here, where the rule can
 * tell a page route from a missing asset.
 */
async function fromBundle(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;
  // Trailing slashes trimmed so `/200/` is the shell with its header and not
  // a page, and `/index` is not a second URL for the landing page.
  const bare = path.replace(/\/+$/, '');
  if (bare === '/index.html' || bare === '/index') {
    return new Response(null, { status: 308, headers: { location: `/${url.search}` } });
  }
  const page = request.method === 'GET' || request.method === 'HEAD';
  if (page && (bare === '/200' || bare === '/200.html')) {
    return (await shell(request, env)) ?? new Response(null, { status: 404 });
  }

  const response = await env.ASSETS.fetch(request);
  if (response.status !== 404 || !page || !extensionless(path)) {
    return response;
  }
  return (await shell(request, env)) ?? response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (isNeverProxied(url.pathname)) {
      return json(404, {
        error: 'not_found',
        error_description: `no route serves ${url.pathname}.`
      });
    }

    if (!belongsToOrigin(url.pathname)) {
      // A prerendered page or asset as itself, and anything else that looks
      // like a page as the shell, which is what makes a hard refresh of
      // `/o/acme/members` work.
      return fromBundle(request, env, url);
    }

    if (!env.OTTO_ORIGIN) {
      // Loud, and in the one place it can be seen. Without this the failure is
      // a URL constructor throwing inside a proxy hop, which reaches the caller
      // as a bare 500 with nothing naming the cause.
      return json(500, {
        error: 'misconfigured',
        error_description:
          'this Worker has no OTTO_ORIGIN, so it does not know where otto-platform-server is. ' +
          'Deploy with --env production, or pass --var OTTO_ORIGIN:https://…'
      });
    }

    const target = new URL(url.pathname + url.search, env.OTTO_ORIGIN);
    const headers = new Headers(request.headers);

    // The origin keys every per-IP throttle on this header
    // (`OTTO_CLIENT_IP_HEADER=cf-connecting-ip`), so what it contains has to be
    // the platform's value and never the caller's. Cloudflare overwrites
    // `CF-Connecting-IP` before the Worker is invoked, which is what makes the
    // inbound value safe to forward. The `delete` is for the case where there is
    // no value at all: an empty header would become one throttle bucket shared by
    // everyone.
    //
    // `fly-client-ip` cannot do this job here. Fly's proxy overwrites it with the
    // address it sees, which is a Cloudflare egress address, so keyed on it every
    // visitor to the console would share a handful of throttle buckets.
    //
    // None of this holds if the origin can be reached without going through
    // Cloudflare: a direct caller sets the header itself. See
    // docs/deploy/cloudflare.md.
    const clientIp = request.headers.get('cf-connecting-ip');
    if (clientIp) {
      headers.set('cf-connecting-ip', clientIp);
    } else {
      headers.delete('cf-connecting-ip');
    }

    // `Origin` and `Sec-Fetch-Site` are deliberately left exactly as the browser
    // sent them. The server's CSRF guard requires a cookie-bearing write to carry
    // an `Origin` equal to `OTTO_PUBLIC_URL`'s origin, and the browser's origin
    // is this Worker's hostname, which is that value.

    return fetch(
      new Request(target, {
        method: request.method,
        headers,
        body: request.body,
        // A proxy that follows redirects is not a proxy. `/oauth/authorize`
        // answers `303` to a loopback address the *client* is listening on, and
        // `/sso/callback` redirects into the console; following either here
        // would fetch the destination from Cloudflare, burn a single-use code,
        // and leave the caller waiting forever.
        redirect: 'manual',
        // Nothing on these paths is cacheable and some of it is per-session.
        // A heuristically cached `GET /api/me` is one user's identity served to
        // another. A negative TTL is the documented way to say "never", where
        // `cacheTtl: 0` only means "expired".
        cf: { cacheTtlByStatus: { '200-599': -1 } }
      })
    );
  }
} satisfies ExportedHandler<Env>;
