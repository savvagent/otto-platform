#!/usr/bin/env node
/**
 * The built bundle has every marketing page, each one in the right language
 * and indexable, and the console shell is neither.
 *
 * **What this catches that the build does not.** The prerender crawler only
 * writes pages something links to, and it is perfectly happy to write none:
 * a broken `entries`, a matcher that stops matching, or a hook that stops
 * running all produce a green build missing half the site, or a site whose
 * Spanish page says `lang="en"` (or `lang="es"` over English text). Every failure here is one a visitor or a
 * crawler would see and the build would not.
 *
 * Run after `npm run build`: `npm run check:build` (or
 * `node scripts/check-build.mjs [dir]`, default `build/`).
 *
 * **It runs in plain Node**, without SvelteKit's `$lib` alias or TypeScript,
 * so it cannot import `$lib/site` or `$lib/sitemap`. It keeps copies of the
 * page list, the origin and the locale-prefix rule instead, and
 * `check-build.test.mjs` asserts each copy against the original — so a new
 * product added to `services.ts` fails that test until it is added here too.
 * The locales are read from the inlang project, like `check-messages.mjs`.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readCatalog, readSettings } from './check-messages.mjs';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Mirrors `SITE_ORIGIN` in `src/lib/site.ts`. */
export const SITE_ORIGIN = 'https://otto.savvagent.com';

/** Mirrors the slugs in `src/lib/services.ts`. */
const PRODUCT_SLUGS = ['factory', 'flags'];

/** Mirrors `MARKETING_PATHS` in `src/lib/sitemap.ts`. */
export const PAGE_PATHS = ['/', '/pricing', ...PRODUCT_SLUGS.map((slug) => `/products/${slug}`)];

/** Mirrors `localizedPath` in `src/lib/site.ts`. */
function localizedPath(baseLocale, lang, path) {
  if (lang === baseLocale) return path;
  return `/${lang}${path === '/' ? '' : path}`;
}

/**
 * The file adapter-static writes for a URL path. With
 * `trailingSlash = 'never'`, `/es/pricing` is `es/pricing.html` and the root
 * is `index.html`.
 */
export function fileFor(urlPath) {
  return urlPath === '/' ? 'index.html' : `${urlPath.slice(1)}.html`;
}

/** Every marketing page the build must contain: `{ file, lang, canonical }`. */
export function expectedPages({ baseLocale, locales }) {
  return PAGE_PATHS.flatMap((path) =>
    locales.map((lang) => {
      const urlPath = localizedPath(baseLocale, lang, path);
      return { file: fileFor(urlPath), lang, canonical: SITE_ORIGIN + urlPath };
    })
  );
}

const INDEXABLE = '<meta name="robots" content="index, follow"';

function langOf(html) {
  return /<html\b[^>]*\blang="([^"]*)"/.exec(html)?.[1];
}

/** Undo the escaping Svelte applies to text and attribute values. */
function decode(text) {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * The first and the last string the marketing layout renders: the skip link
 * at the top of `<body>`, and the footer's language-switcher label at the
 * bottom. Each is a key, a pattern that finds it in the HTML, and a name.
 *
 * **Why the body is checked, not only `<html lang>`.** The `lang` attribute
 * comes from the URL, in a hook; the words come from Paraglide's
 * process-wide locale override, which the layout installs while it renders.
 * If that override ever belonged to another page — a `load` calling a
 * message, an `await` in a component — the head would still be right and the
 * text would not. Checking both ends of the render catches a switch part-way
 * through as well as a wrong start.
 */
const LOCALE_MARKERS = [
  {
    key: 'marketing_skip_to_content',
    pattern: /<a href="#main"[^>]*>\s*([^<]*?)\s*<\/a>/,
    where: 'skip link'
  },
  {
    key: 'marketing_footer_language',
    pattern: /<footer[\s\S]*?<nav aria-label="([^"]*)"/,
    where: 'footer language label'
  }
];

/**
 * What is wrong with one marketing page, as sentences. Empty when nothing is.
 *
 * `messages` is the page's own locale catalog; without it the body text is
 * not checked.
 */
export function checkPage(html, { file, lang, canonical }, messages) {
  const errors = [];
  for (const { key, pattern, where } of messages ? LOCALE_MARKERS : []) {
    const want = messages[key];
    const found = pattern.exec(html)?.[1];
    if (found === undefined) errors.push(`${file}: no ${where} found`);
    else if (decode(found) !== want) {
      errors.push(`${file}: ${where} is "${decode(found)}", expected "${want}" (${lang})`);
    }
  }
  const found = langOf(html);
  if (found !== lang)
    errors.push(`${file}: expected <html lang="${lang}">, found ${found ?? 'none'}`);
  if (!html.includes(`<link rel="canonical" href="${canonical}"`)) {
    errors.push(`${file}: expected <link rel="canonical" href="${canonical}">`);
  }
  if (!html.includes(INDEXABLE)) errors.push(`${file}: expected robots "index, follow"`);
  return errors;
}

/**
 * The console shell is English until script corrects it, and must never ask
 * to be indexed: it is served for every console URL.
 */
export function checkShell(html, file = '200.html') {
  const errors = [];
  const found = langOf(html);
  if (found !== 'en') errors.push(`${file}: expected <html lang="en">, found ${found ?? 'none'}`);
  if (html.includes(INDEXABLE)) errors.push(`${file}: must not be "index, follow"`);
  return errors;
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

/** Every problem with the bundle in `dir`. */
export function checkBuild(
  dir,
  settings = readSettings(webRoot),
  catalog = (lang) => readCatalog(lang, webRoot)
) {
  const errors = [];
  const read = (file) => readFileSync(join(dir, file), 'utf8');

  for (const page of expectedPages(settings)) {
    if (!existsSync(join(dir, page.file))) errors.push(`${page.file}: missing`);
    else errors.push(...checkPage(read(page.file), page, catalog(page.lang)));
  }

  for (const file of ['200.html', 'sitemap.xml', 'robots.txt']) {
    if (!existsSync(join(dir, file))) errors.push(`${file}: missing`);
  }
  if (existsSync(join(dir, '200.html'))) errors.push(...checkShell(read('200.html')));

  // The hook's placeholder surviving anywhere means a page skipped the hook.
  for (const path of walk(dir)) {
    if (readFileSync(path, 'utf8').includes('%otto.lang%')) {
      errors.push(`${relative(dir, path)}: still contains %otto.lang%`);
    }
  }
  return errors;
}

// Importable for the unit tests; only the direct invocation exits the process.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const dir = resolve(process.argv[2] ?? join(webRoot, 'build'));
  if (!existsSync(dir)) {
    console.error(`check:build: ${dir} does not exist. Run \`npm run build\` first.`);
    process.exit(1);
  }
  const errors = checkBuild(dir);
  if (errors.length > 0) {
    for (const error of errors) console.error(`check:build: ${error}`);
    console.error(`check:build: ${errors.length} problem(s) in ${relative(webRoot, dir) || dir}`);
    process.exit(1);
  }
  console.log(`check:build: ${expectedPages(readSettings(webRoot)).length} pages, all good.`);
}
