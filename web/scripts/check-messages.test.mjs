/**
 * The gate that makes a partial translation unmergeable, pinned.
 *
 * `check()` is pure — it takes the settings and the parsed catalogs — so these
 * cases run in memory and none of them touch `messages/`. Each one is a failure
 * that the Paraglide compiler is documented to let through silently: a missing
 * key falls back to the base locale at runtime with no warning at all, which is
 * precisely the bug that reaches a customer as half a page in the wrong
 * language.
 */

import { describe, expect, it } from 'vitest';

import { check, pluralCategories } from './check-messages.mjs';

const settings = { baseLocale: 'en', locales: ['en', 'de', 'es'] };

/**
 * A plural message, spelled the way the message-format plugin actually wants:
 * the count as an explicit `{count}`. ICU's `#` shorthand is not part of the
 * inlang format — Paraglide prints it literally (#34).
 *
 * @param {Record<string, string>} arms
 * @returns {unknown}
 */
const plural = (arms) => [
  {
    declarations: ['input count', 'local countPlural = count: plural'],
    selectors: ['countPlural'],
    match: Object.fromEntries(Object.entries(arms).map(([k, v]) => [`countPlural=${k}`, v]))
  }
];

/**
 * A complete, correct set. Every case below starts from this and breaks one thing.
 *
 * Deliberately loose: most of these tests exist to build a catalog that is
 * *wrong*, so a precise type here would reject the fixtures before the check
 * under test ever saw them.
 *
 * @returns {Record<string, Record<string, any>>}
 */
function catalogs() {
  return {
    en: {
      $schema: 'x',
      greeting: 'Hello {name}',
      jobs: plural({ one: '{count} job', other: '{count} jobs' })
    },
    de: {
      $schema: 'x',
      greeting: 'Hallo {name}',
      jobs: plural({ one: '{count} Auftrag', other: '{count} Aufträge' })
    },
    es: {
      $schema: 'x',
      greeting: 'Hola {name}',
      // Spanish needs `many`: 1 000 000 is "un millón *de* trabajos".
      jobs: plural({
        one: '{count} trabajo',
        many: '{count} de trabajos',
        other: '{count} trabajos'
      })
    }
  };
}

/**
 * @param {Record<string, Record<string, any>>} c
 * @param {RegExp} about
 */
const complains = (c, about) => {
  const problems = check(settings, c);
  expect(problems.join('\n')).toMatch(about);
  return problems;
};

describe('message catalog completeness', () => {
  it('passes a complete set', () => {
    expect(check(settings, catalogs())).toEqual([]);
  });

  it('catches a key missing from a translation', () => {
    const c = catalogs();
    delete c.de.jobs;
    complains(c, /de\.json is missing 1 key\(s\).*jobs/);
  });

  it('catches a key a translation invented', () => {
    const c = catalogs();
    c.de.surprise = 'Überraschung';
    complains(c, /de\.json defines 1 key\(s\) that en does not: surprise/);
  });

  it('catches a dropped placeholder', () => {
    const c = catalogs();
    c.de.greeting = 'Hallo';
    complains(c, /de\.json "greeting" drops placeholder\(s\) name/);
  });

  it('catches a placeholder the base locale never declared', () => {
    const c = catalogs();
    c.de.greeting = 'Hallo {name}, {title}';
    complains(c, /de\.json "greeting" references title/);
  });

  it('catches a plural category the locale requires but the catalog omits', () => {
    const c = catalogs();
    delete c.es.jobs[0].match['countPlural=many'];
    complains(c, /es\.json "jobs" selector "countPlural" is missing plural category many/);
  });

  it('catches a plural category the locale never selects', () => {
    const c = catalogs();
    c.de.jobs[0].match['countPlural=many'] = '{count} Aufträge';
    complains(c, /de\.json "jobs" selector "countPlural" declares many, which de never selects/);
  });

  it('catches a selector a translation drops while staying a variant', () => {
    const c = catalogs();
    // Still a variant array, but the `countPlural` selector base declares is
    // gone entirely — a translator collapsing `{$count ->}` into one arm
    // rather than dropping just one plural category.
    c.de.jobs = [{ declarations: [], selectors: [], match: { '*': 'Aufträge' } }];
    complains(c, /de\.json "jobs" is missing selector\(s\) countPlural that en declares/);
  });

  it('catches a message whose shape changed between locales', () => {
    const c = catalogs();
    c.de.jobs = 'Aufträge';
    complains(c, /de\.json "jobs" is a plain string but en has a variant/);
  });

  it('refuses a base catalog with nothing in it', () => {
    complains({ ...catalogs(), en: { $schema: 'x' } }, /en\.json defines no messages at all/);
  });

  it('reports every problem at once rather than the first', () => {
    const c = catalogs();
    delete c.de.jobs;
    c.es.greeting = 'Hola';
    expect(check(settings, c)).toHaveLength(2);
  });
});

describe('ICU # shorthand', () => {
  it('catches # in a plural arm of the base locale', () => {
    const c = catalogs();
    c.en.jobs[0].match['countPlural=one'] = '# job';
    complains(c, /en\.json "jobs" arm "countPlural=one" uses "#".*\{count\}/);
  });

  it('catches # in a plural arm of a translation', () => {
    const c = catalogs();
    c.es.jobs[0].match['countPlural=many'] = '# de trabajos';
    complains(c, /es\.json "jobs" arm "countPlural=many" uses "#"/);
  });

  it('names the input the plural selects on', () => {
    const c = catalogs();
    const files = (/** @type {string} */ arm) => [
      {
        declarations: ['input total', 'local totalPlural = total: plural'],
        selectors: ['totalPlural'],
        match: { 'totalPlural=one': arm, 'totalPlural=other': '{total} files' }
      }
    ];
    c.en.files = files('# file');
    c.de.files = files('{total} Datei');
    c.es.files = [
      {
        declarations: ['input total', 'local totalPlural = total: plural'],
        selectors: ['totalPlural'],
        match: {
          'totalPlural=one': '{total} archivo',
          'totalPlural=many': '{total} de archivos',
          'totalPlural=other': '{total} archivos'
        }
      }
    ];
    const problems = check(settings, c);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/en\.json "files" arm "totalPlural=one" uses "#".*\{total\}/);
  });

  it('leaves # alone outside a plural message', () => {
    const c = catalogs();
    for (const locale of ['en', 'de', 'es']) c[locale].tag = '#{name}';
    expect(check(settings, c)).toEqual([]);
  });
});

describe('plural categories', () => {
  /**
   * The reason the check reads `Intl` per locale instead of asserting one set.
   * If this ever fails, the runtime's CLDR data moved and the catalogs, not the
   * check, are what need revisiting.
   */
  it('differ between the six shipped locales', () => {
    expect(Array.from(pluralCategories('en')).sort()).toEqual(['one', 'other']);
    expect(Array.from(pluralCategories('de')).sort()).toEqual(['one', 'other']);
    expect(Array.from(pluralCategories('hi')).sort()).toEqual(['one', 'other']);
    for (const romance of ['es', 'fr', 'it']) {
      expect(Array.from(pluralCategories(romance)).sort()).toEqual(['many', 'one', 'other']);
    }
  });
});
