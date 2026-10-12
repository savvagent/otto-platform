import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { MARKETING_LOCALES, SITE_ORIGIN as SITE_TS_ORIGIN, localizedPath } from '../src/lib/site';
import { MARKETING_PATHS } from '../src/lib/sitemap';
import {
  PAGE_PATHS,
  SITE_ORIGIN,
  checkBuild,
  checkPage,
  checkRobots,
  checkShell,
  expectedPages,
  fileFor,
  walk
} from './check-build.mjs';

const settings = { baseLocale: 'en', locales: ['en', 'es', 'de', 'fr', 'it', 'hi'] };

describe('the copies this script keeps of the app’s rules', () => {
  it('lists the same pages as the sitemap', () => {
    expect(PAGE_PATHS).toEqual(MARKETING_PATHS);
  });

  it('uses the same origin and locale spelling as $lib/site', () => {
    expect(SITE_ORIGIN).toBe(SITE_TS_ORIGIN);
    const pages = expectedPages(settings);
    for (const lang of MARKETING_LOCALES) {
      for (const path of MARKETING_PATHS) {
        const canonical = SITE_ORIGIN + localizedPath(lang, path);
        expect(pages).toContainEqual(expect.objectContaining({ lang, canonical }));
      }
    }
  });
});

describe('fileFor', () => {
  it.each([
    ['/', 'index.html'],
    ['/pricing', 'pricing.html'],
    ['/es', 'es.html'],
    ['/es/pricing', 'es/pricing.html'],
    ['/products/flags', 'products/flags.html'],
    ['/hi/products/flags', 'hi/products/flags.html']
  ])('%s -> %s', (path, file) => {
    expect(fileFor(path)).toBe(file);
  });
});

describe('expectedPages', () => {
  it('is every page in every locale', () => {
    const pages = expectedPages(settings);
    expect(pages).toHaveLength(PAGE_PATHS.length * settings.locales.length);
    expect(pages).toContainEqual({
      file: 'es/pricing.html',
      lang: 'es',
      canonical: 'https://otto.savvagent.com/es/pricing'
    });
    expect(pages).toContainEqual({
      file: 'index.html',
      lang: 'en',
      canonical: 'https://otto.savvagent.com/'
    });
  });
});

describe('checkPage', () => {
  const expected = { file: 'de.html', lang: 'de', canonical: 'https://otto.savvagent.com/de' };
  const messages = {
    marketing_skip_to_content: 'Zum Inhalt springen',
    marketing_footer_language: 'Sprache'
  };
  const head =
    '<html lang="de" class="h-full"><head><meta name="robots" content="index, follow"/>' +
    '<link rel="canonical" href="https://otto.savvagent.com/de"/></head>';
  const body = (skip, language) =>
    `<body><a href="#main" class="sr-only">${skip}</a><main></main>` +
    `<footer><nav aria-label="${language}"></nav></footer></body></html>`;
  const good = head + body('Zum Inhalt springen', 'Sprache');

  it('passes a correct page', () => {
    expect(checkPage(good, expected, messages)).toEqual([]);
  });

  /**
   * The failure this guards: `<html lang>` comes from the URL in a hook, but
   * the text comes from Paraglide's process-wide locale override. If another
   * page's override were in place while this one rendered, the head would be
   * right and every word on the page wrong. The first and the last string
   * the layout renders are both checked, so a switch part-way through shows.
   */
  it('catches body text in another language, at the top or the bottom', () => {
    const englishTop = head + body('Skip to content', 'Sprache');
    expect(checkPage(englishTop, expected, messages).join('\n')).toMatch(/Zum Inhalt springen/);
    const englishBottom = head + body('Zum Inhalt springen', 'Language');
    expect(checkPage(englishBottom, expected, messages).join('\n')).toMatch(/Sprache/);
  });

  it('compares text as the browser reads it, entities decoded', () => {
    const fr = {
      marketing_skip_to_content: 'Aller au contenu',
      marketing_footer_language: 'L’idiome & co'
    };
    const page = head + body('Aller au contenu', 'L’idiome &amp; co');
    expect(checkPage(page, expected, fr)).toEqual([]);
  });

  it('names each thing that is wrong', () => {
    const bad = '<html lang="en"><head><link rel="canonical" href="https://otto.savvagent.com/"/>';
    const errors = checkPage(bad, expected);
    expect(errors).toHaveLength(3);
    expect(errors.join('\n')).toMatch(/lang="de"/);
    expect(errors.join('\n')).toMatch(/canonical/);
    expect(errors.join('\n')).toMatch(/index, follow/);
  });
});

describe('checkShell', () => {
  it('wants English and no index directive', () => {
    expect(checkShell('<html lang="en" class="h-full"><head></head>')).toEqual([]);
    expect(
      checkShell('<html lang="es"><meta name="robots" content="index, follow"/>')
    ).toHaveLength(2);
  });

  /**
   * The shell has no robots meta tag (its `noindex` is the `X-Robots-Tag`
   * header), so no tag passes; any tag that does not say `noindex` fails,
   * however it is spelled.
   */
  it('refuses any robots meta tag that does not say noindex', () => {
    const shell = (meta) => `<html lang="en"><head>${meta}</head>`;
    for (const meta of [
      '<meta name="robots" content="noindex, nofollow">',
      '<meta content="NOINDEX" name="ROBOTS"/>',
      "<meta name='googlebot' content='nofollow,noindex'>"
    ]) {
      expect(checkShell(shell(meta)), meta).toEqual([]);
    }
    for (const meta of [
      '<meta name="robots" content="index,follow">',
      '<meta content="all" name="robots">',
      '<meta name=robots content=index>',
      '<meta name="robots" content="">',
      '<meta name="googlebot" content="index">',
      // `noindexer` is not `noindex`.
      '<meta name="robots" content="noindexer">'
    ]) {
      expect(checkShell(shell(meta)), meta).toHaveLength(1);
    }
    // Another meta tag's `name` is not a robots tag.
    expect(checkShell(shell('<meta data-name="robots" name="viewport" content="all">'))).toEqual(
      []
    );
  });
});

describe('checkRobots', () => {
  const paths = expectedPages(settings).map((p) => p.canonical.slice(SITE_ORIGIN.length));
  const sitemap = `Sitemap: ${SITE_ORIGIN}/sitemap.xml`;

  it('passes the robots.txt this app ships', () => {
    const shipped = readFileSync(new URL('../static/robots.txt', import.meta.url), 'utf8');
    expect(checkRobots(shipped, paths)).toEqual([]);
  });

  it('refuses a Disallow that matches a marketing page, in any locale', () => {
    for (const rule of ['/', '/pricing', '/es/', '/*/pricing', '/products/', '/de$', '/hi']) {
      const errors = checkRobots(`User-agent: *\nDisallow: ${rule}\n${sitemap}\n`, paths);
      expect(errors, rule).toHaveLength(1);
      expect(errors[0], rule).toMatch(/blocks marketing page/);
    }
    // An empty Disallow allows everything; console paths are not pages.
    expect(
      checkRobots(`User-agent: *\nDisallow:\nDisallow: /o/\nDisallow: /pricingx\n${sitemap}`, paths)
    ).toEqual([]);
  });

  it('wants the sitemap named', () => {
    expect(checkRobots('User-agent: *\nDisallow: /o/\n', paths).join('\n')).toMatch(/Sitemap/);
    expect(
      checkRobots('User-agent: *\nSitemap: https://elsewhere.test/sitemap.xml\n', paths)
    ).toHaveLength(1);
  });
});

/**
 * `checkBuild` and `walk` against a real directory: a small bundle written
 * per test, with two locales and a catalog for each, so every failure here is
 * one the real build could produce.
 */
describe('checkBuild', () => {
  const small = { baseLocale: 'en', locales: ['en', 'es'] };
  const catalogs = {
    en: { marketing_skip_to_content: 'Skip to content', marketing_footer_language: 'Language' },
    es: { marketing_skip_to_content: 'Saltar al contenido', marketing_footer_language: 'Idioma' }
  };
  const catalog = (lang) => catalogs[lang];
  const pageHtml = ({ lang, canonical }) =>
    `<html lang="${lang}"><head><meta name="robots" content="index, follow"/>` +
    `<link rel="canonical" href="${canonical}"/></head>` +
    `<body><a href="#main">${catalogs[lang].marketing_skip_to_content}</a>` +
    `<footer><nav aria-label="${catalogs[lang].marketing_footer_language}"></nav></footer></body></html>`;

  let dirs = [];
  afterEach(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    dirs = [];
  });

  function bundle() {
    const dir = mkdtempSync(join(tmpdir(), 'check-build-'));
    dirs.push(dir);
    const write = (file, body) => {
      mkdirSync(dirname(join(dir, file)), { recursive: true });
      writeFileSync(join(dir, file), body);
    };
    for (const page of expectedPages(small)) write(page.file, pageHtml(page));
    write('200.html', '<html lang="en"><head></head><body></body></html>');
    write('sitemap.xml', '<urlset></urlset>');
    write('robots.txt', `User-agent: *\nDisallow: /o/\nSitemap: ${SITE_ORIGIN}/sitemap.xml\n`);
    write('_app/immutable/app.js', 'console.log(1)');
    return { dir, write };
  }

  it('passes a complete bundle', () => {
    const { dir } = bundle();
    expect(checkBuild(dir, small, catalog)).toEqual([]);
  });

  it('walks every file, nested ones included', () => {
    const { dir } = bundle();
    const files = [...walk(dir)].map((path) => relative(dir, path)).sort();
    expect(files).toContain('es/pricing.html');
    expect(files).toContain('_app/immutable/app.js');
    expect(files).toHaveLength(expectedPages(small).length + 4);
  });

  it('names a missing page', () => {
    const { dir } = bundle();
    rmSync(join(dir, 'es/pricing.html'));
    expect(checkBuild(dir, small, catalog)).toEqual(['es/pricing.html: missing']);
  });

  it('finds the placeholder in a nested text file, and not in binaries', () => {
    const { dir, write } = bundle();
    write('_app/immutable/nodes/0.js', 'const html = "<html lang=\\"%otto.lang%\\"";');
    write('_app/immutable/assets/logo.png', '%otto.lang%');
    expect(checkBuild(dir, small, catalog)).toEqual([
      '_app/immutable/nodes/0.js: still contains %otto.lang%'
    ]);
  });

  it('names a missing robots.txt, and one that blocks a page', () => {
    const { dir, write } = bundle();
    rmSync(join(dir, 'robots.txt'));
    expect(checkBuild(dir, small, catalog)).toEqual(['robots.txt: missing']);

    write('robots.txt', `User-agent: *\nDisallow: /es\nSitemap: ${SITE_ORIGIN}/sitemap.xml\n`);
    expect(checkBuild(dir, small, catalog).join('\n')).toMatch(/Disallow: \/es" blocks/);
  });
});
