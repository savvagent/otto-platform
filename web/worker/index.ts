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
 * party id is the host of the server's `SAVVAGENT_PUBLIC_URL` (`savvagent.com`),
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
 * The one path every decision in this Worker is made on: percent-decoded, with
 * repeated slashes collapsed, as the origin's router and the asset binding both
 * see it. `/oauth//introspect` and `/oauth/%69ntrospect` are the same request
 * as `/oauth/introspect` to anything that normalises, and a guard that compares
 * the raw string is a guard with two doors.
 *
 * `undefined` when the path does not decode (a malformed escape such as `%zz`,
 * or bytes that are not UTF-8): no route and no file has that name, and the
 * server's `strict_decode` refuses exactly the same paths.
 */
export function decodePath(path: string): string | undefined {
  try {
    return decodeURIComponent(path).replace(/\/{2,}/g, '/');
  } catch {
    return undefined;
  }
}

/**
 * A `.` or `..` segment, which only an encoded slash can produce here: URL
 * parsing has already removed the literal and `%2e` ones. The server refuses
 * them, because tower-http resolves them where its routing decisions do not.
 */
function hasDotSegment(path: string): boolean {
  return path.split('/').some((segment) => segment === '.' || segment === '..');
}

function underPrefix(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

/**
 * Prefix matching on segment boundaries, exactly as the server does it.
 *
 * `startsWith` alone is wrong and quietly so: `/apiary` is a legal org slug and
 * belongs to the console. Sending it to the origin would answer a JSON `404` for
 * a route the SPA was going to render. Takes the raw path; `false` when it does
 * not decode, which the Worker answers with a `404` before asking.
 */
export function belongsToOrigin(path: string): boolean {
  const p = decodePath(path);
  return p !== undefined && underPrefix(p, ORIGIN_PREFIXES) && !underPrefix(p, NEVER_PROXIED);
}

/** True for the server-to-server paths this Worker refuses to carry. */
export function isNeverProxied(path: string): boolean {
  const p = decodePath(path);
  return p !== undefined && underPrefix(p, NEVER_PROXIED);
}

export interface Env {
  /** The built `web/build` bundle, uploaded with the Worker. */
  ASSETS: Fetcher;
  /** Where `otto-platform-server` actually listens, e.g. `https://otto-platform.fly.dev`. */
  SAVVAGENT_ORIGIN: string;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });

/** The origin's JSON `404`, word for word, so the answer does not depend on
 * whether Cloudflare is in front. */
const notFound = (path: string) =>
  json(404, {
    error: 'not_found',
    error_description: `no route serves ${path}. See /api/openapi.json for the API.`
  });

/**
 * The SPA shell, as the asset binding names it.
 *
 * adapter-static writes it to `200.html`, but the binding's
 * `html_handling: "auto-trailing-slash"` (set explicitly in wrangler.jsonc for
 * this reason) answers `/200.html` with a `307` to `/200`, so `/200` is the
 * name that returns the file.
 */
const SHELL = '/200';

const NOINDEX = 'noindex, nofollow';

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
 *
 * A shell the binding will not return is a broken deployment, not a missing
 * page: the bundle has no `200.html`, or `html_handling` no longer maps `/200`
 * to it. Every client route depends on it, so it is logged and answered with a
 * named JSON `500`, like a missing `SAVVAGENT_ORIGIN`, rather than a bare `404`
 * that looks like an ordinary miss.
 */
async function shell(request: Request, env: Env): Promise<Response> {
  const found = await env.ASSETS.fetch(
    new Request(new URL(SHELL, request.url), { method: request.method })
  );
  if (!found.ok) {
    console.error(
      `the asset binding answered ${found.status} for the SPA shell (${SHELL}); ` +
        'every client route is failing. Check that the bundle has 200.html and that ' +
        'html_handling is "auto-trailing-slash".'
    );
    return json(500, {
      error: 'misconfigured',
      error_description:
        'this Worker could not load the console shell (200.html) from its asset bundle.'
    });
  }
  const headers = new Headers(found.headers);
  headers.set('x-robots-tag', NOINDEX);
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
 * A `308` to a path on this site. Leading slashes and backslashes are stripped
 * and exactly one put back, so a request for `//evil.com/` can never become
 * `Location: //evil.com` (or `/\evil.com`, which browsers read the same way).
 */
function redirectOnSite(path: string, search: string): Response {
  const location = `/${path.replace(/^[/\\]+/, '')}${search}`;
  return new Response(null, { status: 308, headers: { location } });
}

/**
 * The bundle side of the Worker: prerendered pages and assets as themselves,
 * and the shell for any page route that has no file. The same steps, in the
 * same order, as `route` in `crates/otto-platform-server/src/lib.rs`.
 *
 * `not_found_handling` is `"none"` (see wrangler.jsonc), so the binding's
 * `404` reaches this function and the shell is chosen here, where the rule can
 * tell a page route from a missing asset. Only a `404` falls through: any
 * other answer is that file's own.
 */
async function fromBundle(request: Request, env: Env, url: URL, path: string): Promise<Response> {
  const page = request.method === 'GET' || request.method === 'HEAD';

  // Trailing slashes trimmed so `/200/` is the shell with its header and not
  // a page, and `/index/` is not a second URL for the landing page.
  const bare = path.replace(/\/+$/, '');
  if (bare === '/index.html' || bare === '/index') {
    return new Response(null, { status: 308, headers: { location: `/${url.search}` } });
  }
  // The shell's own names, for every method: a write must not reach the
  // binding and come back as the shell without its header.
  if (bare === '/200' || bare === '/200.html') {
    if (!page) {
      return new Response(null, {
        status: 405,
        headers: { allow: 'GET, HEAD', 'x-robots-tag': NOINDEX }
      });
    }
    return shell(request, env);
  }
  // `/pricing/` → `/pricing`, as the server does and SvelteKit's
  // `trailingSlash: 'never'` expects. The binding's own `auto-trailing-slash`
  // only does this for files that exist, and with a `307`.
  const raw = url.pathname;
  if (page && raw !== '/' && raw.endsWith('/')) {
    return redirectOnSite(raw.replace(/\/+$/, ''), url.search);
  }

  // `/pricing.html` → `/pricing`: one URL per page, with the same `308` the
  // server sends, rather than the binding's own `307`. `/200.html` and
  // `/index.html` were answered above. Only when the page exists, so
  // `/nope.html` stays a `404`; looked up by its decoded name, so
  // `/pricing%2Ehtml` is the same request.
  if (page && path.endsWith('.html')) {
    const target = encodePath(path.slice(0, -'.html'.length));
    const found = await env.ASSETS.fetch(
      new Request(new URL(target, url.origin), { method: request.method })
    );
    if (found.status !== 404) {
      return redirectOnSite(target, url.search);
    }
  }

  const response = await env.ASSETS.fetch(request);
  if (response.status !== 404 || !page || !extensionless(path)) {
    return response;
  }
  return shell(request, env);
}

/**
 * A decoded path made safe to put back into a `Location`, escaping what the
 * server's `LOCATION_PATH` escapes: `encodeURI` covers `%`, `\`, spaces and
 * non-ASCII, and leaves `?` and `#`, which would end the path.
 */
function encodePath(path: string): string {
  return encodeURI(path).replace(/\?/g, '%3F').replace(/#/g, '%23');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Decided once, on the decoded path; see `decodePath`.
    const path = decodePath(url.pathname);
    if (path === undefined || hasDotSegment(path)) {
      return notFound(url.pathname);
    }

    // Refused with the origin's JSON 404, so the answer does not advertise
    // that the route exists.
    if (underPrefix(path, NEVER_PROXIED)) {
      return notFound(path);
    }

    if (!underPrefix(path, ORIGIN_PREFIXES)) {
      // A prerendered page or asset as itself, and anything else that looks
      // like a page as the shell, which is what makes a hard refresh of
      // `/o/acme/members` work.
      return fromBundle(request, env, url, path);
    }

    if (!env.SAVVAGENT_ORIGIN) {
      // Loud, and in the one place it can be seen. Without this the failure is
      // a URL constructor throwing inside a proxy hop, which reaches the caller
      // as a bare 500 with nothing naming the cause.
      return json(500, {
        error: 'misconfigured',
        error_description:
          'this Worker has no SAVVAGENT_ORIGIN, so it does not know where otto-platform-server is. ' +
          'Deploy with --env production, or pass --var SAVVAGENT_ORIGIN:https://…'
      });
    }

    // The target is the origin with the request's path *assigned*, never the
    // request's path *resolved against* the origin. `new URL(path, base)` reads a
    // path beginning with `//` as protocol-relative and discards the base, so
    // `//api%2F@evil.test/x` — whose decoded, collapsed form `/api/@evil.test/x`
    // passes every prefix check above — would resolve to host `evil.test`, and
    // this Worker would forward the visitor's session cookie there and serve the
    // reply on our origin. A pathname setter cannot change the host. The origin
    // comparison below is the backstop: nothing leaves for any other host.
    const origin = new URL(env.SAVVAGENT_ORIGIN);
    const target = new URL(origin.origin);
    target.pathname = url.pathname;
    target.search = url.search;
    if (target.origin !== origin.origin) {
      return notFound(path);
    }
    const headers = new Headers(request.headers);

    // The origin keys every per-IP throttle on this header
    // (`SAVVAGENT_CLIENT_IP_HEADER=cf-connecting-ip`), so what it contains has to be
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
    // an `Origin` equal to `SAVVAGENT_PUBLIC_URL`'s origin, and the browser's origin
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
