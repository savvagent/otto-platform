#!/usr/bin/env node
/**
 * The built bundle has every marketing page, each one in the right language
 * and indexable, and the console shell is neither.
 *
 * **What this catches that the build does not.** The prerender crawler only
 * writes pages something links to, and it is perfectly happy to write none:
 * a broken `entries`, a matcher that stops matching, or a hook that stops
 * running all produce a green build missing half the site, or a site whose
 * Spanish page says `lang="en"` (or `lang="es"` over English text). Every
 * failure here is one a visitor or a crawler would see and the build would
 * not.
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
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readCatalog, readSettings } from './check-messages.mjs';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Mirrors `SITE_ORIGIN` in `src/lib/site.ts`. */
export const SITE_ORIGIN = 'https://otto.savvagent.com';

/** Mirrors the slugs in `src/lib/services.ts`. */
const PRODUCT_SLUGS = ['tower', 'flags', 'cxp'];

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
 * The `content` of every robots meta tag in `html` (`robots`, or a named
 * crawler's such as `googlebot`), whatever the attribute order, quoting or
 * case.
 */
function robotsDirectives(html) {
  const directives = [];
  for (const [tag] of html.matchAll(/<meta\b[^>]*>/gi)) {
    const attr = (name) =>
      new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i')
        .exec(tag)
        ?.slice(1)
        .find((v) => v !== undefined);
    const name = attr('name')?.toLowerCase();
    if (name === 'robots' || name === 'googlebot' || name === 'bingbot') {
      directives.push(attr('content') ?? '');
    }
  }
  return directives;
}

/**
 * The console shell is English until script corrects it, and must never ask
 * to be indexed: it is served for every console URL.
 *
 * **The shell carries no robots meta tag on purpose** (see `src/app.html`):
 * the template also renders the marketing pages, so the shell's `noindex` is
 * the `X-Robots-Tag` header the server and the Worker put on it. So no tag is
 * fine, and what is refused is a tag that does not say `noindex`: any robots
 * meta without it — `index, follow`, `all`, or an empty one — would at best
 * contradict the header.
 */
export function checkShell(html, file = '200.html') {
  const errors = [];
  const found = langOf(html);
  if (found !== 'en') errors.push(`${file}: expected <html lang="en">, found ${found ?? 'none'}`);
  for (const content of robotsDirectives(html)) {
    if (!/(^|[\s,])noindex([\s,]|$)/i.test(content)) {
      errors.push(`${file}: a robots meta tag says "${content}"; the shell must never be indexed`);
    }
  }
  return errors;
}

/**
 * Whether a `robots.txt` path rule matches `path`: a prefix match, with `*`
 * matching any run of characters and a trailing `$` anchoring the end, as
 * Google and RFC 9309 read it.
 */
function ruleMatches(rule, path) {
  const anchored = rule.endsWith('$');
  const body = anchored ? rule.slice(0, -1) : rule;
  const pattern = body
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${pattern}${anchored ? '$' : ''}`).test(path);
}

/**
 * What is wrong with `robots.txt`: a `Disallow` that would keep a crawler off
 * a marketing page, or no `Sitemap` line naming ours. `paths` are the URL
 * paths of every marketing page, in every locale.
 */
export function checkRobots(text, paths) {
  const errors = [];
  const rules = text
    .split('\n')
    .map((line) => /^\s*disallow\s*:\s*([^#\s]*)/i.exec(line)?.[1])
    .filter((rule) => rule !== undefined && rule !== '');
  for (const rule of rules) {
    const blocked = paths.filter((path) => ruleMatches(rule, path));
    if (blocked.length > 0) {
      errors.push(`robots.txt: "Disallow: ${rule}" blocks marketing page(s) ${blocked.join(', ')}`);
    }
  }
  const sitemap = `${SITE_ORIGIN}/sitemap.xml`;
  const named = text
    .split('\n')
    .some((line) => /^\s*sitemap\s*:\s*(\S+)/i.exec(line)?.[1] === sitemap);
  if (!named) errors.push(`robots.txt: expected "Sitemap: ${sitemap}"`);
  return errors;
}

/** The files the placeholder scan reads; images and fonts are not text. */
const TEXT_EXTENSIONS = new Set(['.html', '.xml', '.txt', '.js']);

/** Every file under `dir`, recursively. */
export function* walk(dir) {
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
  if (existsSync(join(dir, 'robots.txt'))) {
    const paths = expectedPages(settings).map((page) => page.canonical.slice(SITE_ORIGIN.length));
    errors.push(...checkRobots(read('robots.txt'), paths));
  }

  // The hook's placeholder surviving anywhere means a page skipped the hook.
  // Text files only: an image read as UTF-8 is noise, not a page.
  for (const path of walk(dir)) {
    if (!TEXT_EXTENSIONS.has(extname(path))) continue;
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
