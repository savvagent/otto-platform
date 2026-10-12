import { describe, expect, it, vi } from 'vitest';

import worker, { belongsToOrigin, isNeverProxied, type Env } from './index';

/**
 * `belongsToOrigin` is a second copy of the server's `API_PREFIXES`, in a
 * different language, that nothing forces to agree with the first.
 *
 * Drift here is silent in the worst direction. If the edge stops recognising a
 * path as the origin's, the Worker answers it with the SPA shell (`200.html`)
 * and a `200`, and a client calling `/api/orgs/nope` gets HTML forever instead
 * of the `404` it can parse.
 */
describe('belongsToOrigin', () => {
  it('claims the browser-facing API surfaces, bare and nested', () => {
    for (const path of [
      '/api',
      '/api/',
      '/api/orgs/acme',
      '/api/orgs/acme/members/u1/logout',
      '/api/openapi.json',
      '/oauth',
      '/oauth/authorize',
      '/oauth/token',
      '/oauth/register',
      '/oauth/revoke',
      '/sso/callback',
      '/.well-known',
      '/.well-known/oauth-authorization-server',
      '/healthz',
      '/readyz'
    ]) {
      expect(belongsToOrigin(path), path).toBe(true);
    }
  });

  it('leaves the console its own routes, including the look-alikes', () => {
    for (const path of [
      '/',
      '/login',
      '/signup',
      '/claim',
      '/invite/acme',
      '/orgs/new',
      '/settings',
      '/o/acme/members',
      // `/apiary` is a legal org slug. A prefix test that is not
      // segment-aware sends it to the origin, which answers a JSON 404 for a
      // page the SPA was going to render.
      '/apiary',
      '/apiary/members',
      '/oauthentication',
      '/ssor',
      '/internals',
      '/readyzzz',
      '/healthzcheck',
      '/.well-knownish'
    ]) {
      expect(belongsToOrigin(path), path).toBe(false);
    }
  });

  it('matches every prefix on a segment boundary', () => {
    for (const prefix of ['/api', '/oauth', '/sso', '/.well-known', '/healthz', '/readyz']) {
      expect(belongsToOrigin(prefix), prefix).toBe(true);
      expect(belongsToOrigin(`${prefix}/x`), `${prefix}/x`).toBe(true);
      expect(belongsToOrigin(`${prefix}x`), `${prefix}x`).toBe(false);
    }
  });
});

describe('the server-to-server paths', () => {
  it('are never proxied, however they are spelled', () => {
    for (const path of [
      '/oauth/introspect',
      '/oauth/introspect/',
      '/oauth//introspect',
      '/oauth/%69ntrospect',
      '/internal',
      '/internal/usage',
      '/internal/orgs/acme/usage-status',
      '//internal/usage',
      '/internal//usage',
      '/%69nternal/usage'
    ]) {
      expect(isNeverProxied(path), path).toBe(true);
      expect(belongsToOrigin(path), path).toBe(false);
    }
  });

  it('do not swallow their neighbours', () => {
    for (const path of ['/oauth/token', '/oauth/introspection', '/internals', '/oauth']) {
      expect(isNeverProxied(path), path).toBe(false);
    }
  });
});

describe('the Worker', () => {
  const assets = vi.fn(async () => new Response('<html>spa</html>'));
  const env = (origin = 'https://origin.test'): Env =>
    ({ ASSETS: { fetch: assets } as unknown as Fetcher, OTTO_ORIGIN: origin }) as Env;
  const call = (request: Request, e: Env = env()) => worker.fetch(request, e);

  it('answers a server-to-server path with a JSON 404, from neither the origin nor the SPA', async () => {
    const upstream = vi.spyOn(globalThis, 'fetch');
    assets.mockClear();

    for (const path of ['/oauth/introspect', '/internal/usage']) {
      const response = await call(new Request(`https://otto.test${path}`, { method: 'POST' }));
      expect(response.status, path).toBe(404);
      expect(response.headers.get('content-type')).toContain('application/json');
    }

    expect(upstream).not.toHaveBeenCalled();
    expect(assets).not.toHaveBeenCalled();
    upstream.mockRestore();
  });

  it('serves a console route from the asset bundle', async () => {
    assets.mockClear();
    const response = await call(new Request('https://otto.test/o/acme/members'));
    expect(await response.text()).toContain('spa');
    expect(assets).toHaveBeenCalledOnce();
  });

  it('forwards the browser Origin and the real client address, and never a forged one', async () => {
    const upstream = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 200 }));

    await call(
      new Request('https://otto.test/api/auth/logout?x=1', {
        method: 'POST',
        headers: {
          origin: 'https://otto.test',
          'sec-fetch-site': 'same-origin',
          cookie: '__Host-otto_session=otto_ss_abc',
          'cf-connecting-ip': '203.0.113.9'
        }
      })
    );

    const forwarded = upstream.mock.calls[0]![0] as Request;
    expect(new URL(forwarded.url).origin).toBe('https://origin.test');
    expect(new URL(forwarded.url).pathname + new URL(forwarded.url).search).toBe(
      '/api/auth/logout?x=1'
    );
    expect(forwarded.headers.get('origin')).toBe('https://otto.test');
    expect(forwarded.headers.get('sec-fetch-site')).toBe('same-origin');
    expect(forwarded.headers.get('cookie')).toContain('__Host-otto_session');
    expect(forwarded.headers.get('cf-connecting-ip')).toBe('203.0.113.9');
    expect(forwarded.redirect).toBe('manual');
    upstream.mockRestore();
  });

  it('forwards no client-address header at all when Cloudflare supplied none', async () => {
    const upstream = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 200 }));
    await call(new Request('https://otto.test/api/me'));
    const forwarded = upstream.mock.calls[0]![0] as Request;
    expect(forwarded.headers.has('cf-connecting-ip')).toBe(false);
    upstream.mockRestore();
  });

  it('fails loudly when it does not know where the origin is', async () => {
    const response = await call(new Request('https://otto.test/api/me'), env(''));
    expect(response.status).toBe(500);
    expect(await response.text()).toContain('OTTO_ORIGIN');
  });
});

/**
 * The asset bundle, as Cloudflare's asset binding would answer it with
 * `not_found_handling: "none"` and the default `auto-trailing-slash` HTML
 * handling: `/pricing` finds `pricing.html`, `/200` finds the shell, and
 * anything else is a bare `404`. Headers are immutable, as on the real
 * binding, so a Worker that mutates them in place fails here too.
 */
describe('the Worker in front of the asset bundle', () => {
  const pages: Record<string, string> = {
    '/': '<html>landing</html>',
    '/pricing': '<html>pricing</html>',
    '/200': '<html>shell</html>',
    '/_app/app.js': 'console.log(1)'
  };
  const immutable = (body: string | null, status: number) => {
    const response = new Response(body, {
      status,
      headers: { 'content-type': 'text/html', etag: '"v1"' }
    });
    Object.defineProperty(response, 'headers', {
      value: new Proxy(response.headers, {
        get(target, prop) {
          if (prop === 'set' || prop === 'append' || prop === 'delete') {
            return () => {
              throw new TypeError("Can't modify immutable headers.");
            };
          }
          const value = Reflect.get(target, prop, target);
          return typeof value === 'function' ? value.bind(target) : value;
        }
      })
    });
    return response;
  };
  const assets = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : input.toString()).pathname;
    const page = pages[path];
    if (path === '/broken') return immutable('upstream trouble', 500);
    return page === undefined ? immutable(null, 404) : immutable(page, 200);
  });
  const env = {
    ASSETS: { fetch: assets } as unknown as Fetcher,
    OTTO_ORIGIN: 'https://origin.test'
  } as Env;
  const call = (path: string, init?: RequestInit) =>
    worker.fetch(new Request(`https://otto.test${path}`, init), env);
  const askedFor = () =>
    assets.mock.calls.map(
      ([input]) => new URL(input instanceof Request ? input.url : input.toString()).pathname
    );

  it('answers a deep link with the shell, marked noindex', async () => {
    assets.mockClear();
    const response = await call('/o/acme/members');
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('<html>shell</html>');
    expect(response.headers.get('x-robots-tag')).toBe('noindex, nofollow');
    // The shell's own headers survive the copy.
    expect(response.headers.get('etag')).toBe('"v1"');
    // `/200`, not `/200.html`: the latter is a 307 under auto-trailing-slash.
    expect(askedFor()).toEqual(['/o/acme/members', '/200']);
  });

  it('answers a HEAD deep link with the shell too', async () => {
    const response = await call('/o/acme/members', { method: 'HEAD' });
    expect(response.status).toBe(200);
    expect(response.headers.get('x-robots-tag')).toBe('noindex, nofollow');
  });

  it('leaves a missing asset a 404, never HTML', async () => {
    assets.mockClear();
    const response = await call('/_app/missing.js');
    expect(response.status).toBe(404);
    expect(response.headers.has('x-robots-tag')).toBe(false);
    expect(askedFor()).toEqual(['/_app/missing.js']);
  });

  it('does not answer a write to an unknown page with the shell', async () => {
    const response = await call('/o/acme/members', { method: 'POST' });
    expect(response.status).toBe(404);
  });

  it('passes a page that exists through untouched', async () => {
    for (const path of ['/', '/pricing', '/_app/app.js']) {
      assets.mockClear();
      const response = await call(path);
      expect(response.status, path).toBe(200);
      expect(await response.text(), path).toBe(pages[path]);
      expect(response.headers.has('x-robots-tag'), path).toBe(false);
      expect(askedFor(), path).toEqual([path]);
    }
  });

  it('redirects /index.html to the one URL the landing page has', async () => {
    for (const [path, to] of [
      ['/index.html', '/'],
      ['/index', '/'],
      ['/index.html?a=1', '/?a=1']
    ]) {
      assets.mockClear();
      const response = await call(path!);
      expect(response.status, path).toBe(308);
      // Exactly, not resolved: a resolved check passes on `//evil.com/`.
      expect(response.headers.get('location'), path).toBe(to);
      expect(assets, path).not.toHaveBeenCalled();
    }
  });

  it('decides on the decoded path, so encoding changes nothing', async () => {
    for (const path of ['/%32%30%30', '/200%2Ehtml', '/200%2ehtml']) {
      const response = await call(path);
      expect(response.status, path).toBe(200);
      expect(response.headers.get('x-robots-tag'), path).toBe('noindex, nofollow');
      expect(await response.text(), path).toBe('<html>shell</html>');
    }
    for (const path of ['/%69ndex.html', '/index%2Ehtml', '/%69ndex']) {
      const response = await call(path);
      expect(response.status, path).toBe(308);
      expect(response.headers.get('location'), path).toBe('/');
    }
    for (const path of ['/x%2Ejs', '/_app/missing%2Ejs']) {
      assets.mockClear();
      const response = await call(path);
      expect(response.status, path).toBe(404);
      expect(response.headers.has('x-robots-tag'), path).toBe(false);
      expect(askedFor(), path).not.toContain('/200');
    }
  });

  it("answers a path that does not decode with the origin's JSON 404", async () => {
    for (const path of ['/%E0%A4%A', '/%zz', '/%FF', '/trailing%', '/api/%zz']) {
      assets.mockClear();
      const response = await call(path);
      expect(response.status, path).toBe(404);
      expect(response.headers.get('content-type'), path).toContain('application/json');
      expect(((await response.json()) as { error: string }).error, path).toBe('not_found');
      expect(assets, path).not.toHaveBeenCalled();
    }
  });

  it('lets URL parsing resolve dot segments, and refuses the ones it cannot see', async () => {
    // Literal and `%2e` dot segments are gone before the Worker runs, so these
    // are `/200` and `/200.html`: the shell, with its header.
    for (const path of ['/./200', '/./200.html', '/%2e/200', '/a/../200']) {
      const response = await call(path);
      expect(response.status, path).toBe(200);
      expect(response.headers.get('x-robots-tag'), path).toBe('noindex, nofollow');
    }
    const landing = await call('/./index.html');
    expect(landing.status).toBe(308);
    expect(landing.headers.get('location')).toBe('/');

    // Behind an encoded slash, a `..` survives parsing; the server refuses
    // it, and so does the edge.
    assets.mockClear();
    const response = await call('/a%2F..%2F200');
    expect(response.status).toBe(404);
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(assets).not.toHaveBeenCalled();
  });

  it('redirects a trailing slash away, and never off-site', async () => {
    for (const [path, to] of [
      ['/pricing/', '/pricing'],
      ['/pricing/?a=1', '/pricing?a=1'],
      ['/o/acme/', '/o/acme'],
      ['//evil.com/', '/evil.com'],
      ['///evil.com//', '/evil.com'],
      ['//', '/'],
      ['///', '/']
    ]) {
      const response = await call(path!);
      expect(response.status, path).toBe(308);
      expect(response.headers.get('location'), path).toBe(to);
    }
  });

  it('returns any answer but a 404 as is, never the shell', async () => {
    assets.mockClear();
    const response = await call('/broken');
    expect(response.status).toBe(500);
    expect(response.headers.has('x-robots-tag')).toBe(false);
    expect(askedFor()).toEqual(['/broken']);
  });

  it('does not let a write to the shell reach the binding without the header', async () => {
    for (const path of ['/200', '/200.html']) {
      assets.mockClear();
      const response = await call(path, { method: 'POST' });
      expect(response.status, path).toBe(405);
      expect(response.headers.get('x-robots-tag'), path).toBe('noindex, nofollow');
      expect(assets, path).not.toHaveBeenCalled();
    }
  });

  it('serves the shell under its own names with the header', async () => {
    for (const path of ['/200', '/200.html']) {
      assets.mockClear();
      const response = await call(path);
      expect(response.status, path).toBe(200);
      expect(await response.text(), path).toBe('<html>shell</html>');
      expect(response.headers.get('x-robots-tag'), path).toBe('noindex, nofollow');
      expect(askedFor(), path).toEqual(['/200']);
    }
  });

  it('still proxies origin paths without touching the bundle', async () => {
    assets.mockClear();
    const upstream = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 404 }));
    const response = await call('/api/no/such');
    expect(response.status).toBe(404);
    expect(response.headers.has('x-robots-tag')).toBe(false);
    expect(upstream).toHaveBeenCalledOnce();
    expect(assets).not.toHaveBeenCalled();
    upstream.mockRestore();
  });
});
