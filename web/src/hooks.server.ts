import type { Handle } from '@sveltejs/kit';

import { isSupported } from '$lib/locale';

/**
 * The whole opening of the root element, not the bare placeholder, so the
 * replacement can only ever land on `<html lang>`.
 */
const PLACEHOLDER = '<html lang="%savvagent.lang%"';

/**
 * Write the page's language into `<html lang>`.
 *
 * `<html lang>` cannot be set from `<svelte:head>`, which only reaches inside
 * `<head>`, so `app.html` carries a placeholder there and this replaces
 * it. There is no server at runtime: this hook runs during `vite build`, once
 * for each prerendered marketing page — so `/es` is written as Spanish to the
 * file itself, which is what a crawler and a screen reader see before any
 * script runs — and once more for the adapter-static fallback shell
 * (`200.html`), which has no `lang` param and gets the base locale.
 *
 * The param is validated even though the `lang` matcher already ran, because
 * the value lands in markup: a route that someday has a `lang` param without
 * the matcher must not be able to write arbitrary text into the document.
 *
 * The console still sets `<html lang>` itself at boot (`resolveAtBoot` in
 * `$lib/locale`), since its language comes from the account and the browser,
 * which no build step can know.
 */
export const handle: Handle = ({ event, resolve }) => {
  const param = event.params.lang;
  const lang = isSupported(param) ? param : 'en';
  return resolve(event, {
    transformPageChunk: ({ html }) => html.replace(PLACEHOLDER, `<html lang="${lang}"`)
  });
};
