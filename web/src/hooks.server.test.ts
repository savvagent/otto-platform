import type { RequestEvent, ResolveOptions } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';

import { handle } from './hooks.server';

/** A stand-in for the shell `app.html` produces, placeholder and all. */
const TEMPLATE =
  '<!doctype html>\n<html lang="%savvagent.lang%" class="h-full"><head></head></html>';

/** Run `handle` and return the page as the hook leaves it. */
async function render(params: Record<string, string>): Promise<string> {
  let html = TEMPLATE;
  const resolve = async (_event: RequestEvent, opts?: ResolveOptions) => {
    html = (await opts?.transformPageChunk?.({ html, done: true })) ?? html;
    return new Response(html);
  };
  await handle({ event: { params } as unknown as RequestEvent, resolve });
  return html;
}

describe('the <html lang> hook', () => {
  it.each([
    [{ lang: 'es' }, 'es'],
    [{}, 'en'],
    // Not a locale: never written into the document.
    [{ lang: 'xx' }, 'en'],
    [{ lang: '"><script>' }, 'en']
  ])('writes %j as lang="%s"', async (params, expected) => {
    const html = await render(params);
    expect(html).toContain(`<html lang="${expected}" class="h-full">`);
    expect(html).not.toContain('%savvagent.lang%');
  });
});
