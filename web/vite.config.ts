import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

/**
 * In production the console and the API are one origin: `otto-platform-server` serves
 * the built bundle beside `/api`, `/oauth`, `/sso` and `/.well-known`, and in the
 * Cloudflare deployment a Worker does the same job (`worker/index.ts`).
 *
 * Development has to reproduce that, not merely approximate it. The session
 * cookie carries the `__Host-` prefix, which browsers refuse to store unless
 * the cookie has `Path=/` and **no `Domain`** — so it is bound to whatever
 * origin set it and cannot be sent to a different port. A dev server that
 * pointed `fetch` at `http://localhost:8080` would never send the session, and
 * CORS could not rescue it. Proxying instead keeps every request on the Vite
 * origin, where the cookie lives.
 *
 * `secure: false` only tells the proxy not to verify an upstream TLS
 * certificate; it has nothing to do with the cookie's `Secure` attribute, which
 * browsers honour on `localhost` regardless.
 */
const api = process.env.OTTO_API_ORIGIN ?? 'http://127.0.0.1:8080';

const proxied = {
  target: api,
  changeOrigin: false,
  secure: false
};

/**
 * Messages are compiled, not looked up at runtime.
 *
 * `emitTsDeclarations` is not optional. Without it Paraglide emits no `.d.ts`
 * at all and a misspelled key type-checks clean, then renders the base locale's
 * string in every language — which is exactly the failure `npm run check` is
 * supposed to catch before a customer does. With it, `m.no_such_key()` is a
 * `TS2339`.
 *
 * The output is generated and git-ignored, so it is also in `.prettierignore`;
 * a fresh compile would otherwise fail `npm run lint` on code no human wrote.
 */
const paraglide = paraglideVitePlugin({
  project: './project.inlang',
  outdir: './src/lib/paraglide',
  emitTsDeclarations: true
});

export default defineConfig({
  plugins: [paraglide, tailwindcss(), sveltekit()],
  // Vitest resolves package `exports` with a "node" condition by default,
  // which is what mounting a Svelte component needs to avoid — Svelte's
  // package exports a server-only build under "default", and only the
  // "browser" condition resolves to the client build that has `mount`.
  // Scoped to `process.env.VITEST` so dev/build keep their normal resolution.
  resolve: process.env.VITEST ? { conditions: ['browser'] } : undefined,
  server: {
    port: 5173,
    proxy: {
      '/api': proxied,
      '/oauth': proxied,
      '/sso': proxied,
      '/.well-known': proxied
    }
  }
});
