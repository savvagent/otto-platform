import { describe, expect, it, vi } from 'vitest';

import worker, { belongsToOrigin, isNeverProxied, type Env } from './index';

/**
 * `belongsToOrigin` is a second copy of the server's `API_PREFIXES`, in a
 * different language, that nothing forces to agree with the first.
 *
 * Drift here is silent in the worst direction. If the edge stops recognising a
 * path as the origin's, the asset router answers it from `index.html` with a
 * `200`, and a client calling `/api/orgs/nope` gets HTML forever instead of the
 * `404` it can parse.
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
