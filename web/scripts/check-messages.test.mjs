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
 * A plural message, spelled the way the message-format plugin actually wants.
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
      jobs: plural({ one: '# job', other: '# jobs' })
    },
    de: {
      $schema: 'x',
      greeting: 'Hallo {name}',
      jobs: plural({ one: '# Auftrag', other: '# Aufträge' })
    },
    es: {
      $schema: 'x',
      greeting: 'Hola {name}',
      // Spanish needs `many`: 1 000 000 is "un millón *de* trabajos".
      jobs: plural({ one: '# trabajo', many: '# de trabajos', other: '# trabajos' })
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
    c.de.jobs[0].match['countPlural=many'] = '# Aufträge';
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
