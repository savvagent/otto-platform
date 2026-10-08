#!/usr/bin/env node
/**
 * Every locale has every key, with the same placeholders and the right plural
 * categories.
 *
 * **This is the one gate the Paraglide compiler cannot be.** A key present in
 * `en` and missing from `hi` compiles clean and, at runtime, silently returns
 * the English string — no warning, no error, no visible failure until a
 * customer reads half a page in the wrong language. The compiler's own checks
 * are orthogonal and both still matter: `--emit-ts-declarations` makes a
 * *renamed* key a type error, and an undeclared `{variable}` inside a pattern
 * is a hard compile error. Neither one notices an absent translation.
 *
 * Wired into `npm run check` so a partial translation cannot merge, which is
 * the requirement in the platform console.
 *
 * Run: `node scripts/check-messages.mjs`
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** A message key that is metadata, not a translation. */
const NOT_A_MESSAGE = (key) => key.startsWith('$');

/**
 * The locales and the base, read from the inlang project rather than repeated.
 *
 * Duplicating the list here is how a seventh locale gets added to the compiler
 * and silently skipped by the check that is supposed to police it.
 */
export function readSettings(root = webRoot) {
  const settings = JSON.parse(readFileSync(join(root, 'project.inlang', 'settings.json'), 'utf8'));
  return { baseLocale: settings.baseLocale, locales: settings.locales };
}

export function readCatalog(locale, root = webRoot) {
  return JSON.parse(readFileSync(join(root, 'messages', `${locale}.json`), 'utf8'));
}

/**
 * The plural categories a locale actually has.
 *
 * Not a constant, because the answer is genuinely per-locale and not guessable:
 * `en`, `de` and `hi` need `one`/`other`, while `es`, `fr` and `it` also need
 * `many` — Spanish 1 000 000 is "un millón *de* trabajos", not
 * "1000000 trabajos". Requiring an identical set across locales would either
 * reject a correct Spanish catalog or accept a French one missing `many`, so
 * the requirement is read out of `Intl` per locale instead of asserted.
 */
export function pluralCategories(locale) {
  return new Set(new Intl.PluralRules(locale).resolvedOptions().pluralCategories);
}

/** `{name}` references inside one pattern. */
function placeholdersIn(pattern) {
  return new Set([...String(pattern).matchAll(/\{\s*([A-Za-z_$][\w$]*)\s*\}/g)].map((m) => m[1]));
}

/** A message is either a plain string or an array of variant objects. */
function isVariant(value) {
  return Array.isArray(value);
}

/**
 * Every placeholder used anywhere in a message, plain or variant.
 *
 * Compared across locales because a translator who drops `{name}` produces a
 * grammatical sentence that is missing the thing it was supposed to say, and
 * nothing else in the toolchain looks at that.
 */
function messagePlaceholders(value) {
  if (!isVariant(value)) return placeholdersIn(value);
  const found = new Set();
  for (const variant of value) {
    for (const pattern of Object.values(variant.match ?? {})) {
      for (const name of placeholdersIn(pattern)) found.add(name);
    }
  }
  return found;
}

/**
 * The selectors of a variant message, and which of them select on plural.
 *
 * `local countPlural = count: plural` reads as "countPlural is plural(count)".
 * A selector declared that way has to cover the locale's categories; any other
 * selector (`platform`, `userGender`) is an enumeration the locales must agree
 * on exactly, since its arms are not derivable from the locale.
 */
function selectorInfo(value) {
  const variant = value[0] ?? {};
  const declarations = variant.declarations ?? [];
  const plural = new Set();
  for (const declaration of declarations) {
    const m = /^local\s+([\w$]+)\s*=\s*[\w$]+\s*:\s*plural$/.exec(String(declaration).trim());
    if (m) plural.add(m[1]);
  }
  return { selectors: variant.selectors ?? [], plural };
}

/** The arms of one selector, e.g. `{ countPlural: Set{one, other} }`. */
function armsBySelector(value) {
  const { selectors } = selectorInfo(value);
  const arms = new Map(selectors.map((s) => [s, new Set()]));
  for (const variant of value) {
    for (const key of Object.keys(variant.match ?? {})) {
      // "countPlural=one, platform=ios" -> per-selector arm
      for (const part of key.split(',')) {
        const [name, arm] = part.split('=').map((p) => p.trim());
        if (arms.has(name)) arms.get(name).add(arm);
      }
    }
  }
  return arms;
}

const sorted = (set) => [...set].sort();
const difference = (a, b) => new Set([...a].filter((x) => !b.has(x)));

export function check({ baseLocale, locales }, catalogs) {
  const problems = [];
  const base = catalogs[baseLocale];
  const baseKeys = new Set(Object.keys(base).filter((k) => !NOT_A_MESSAGE(k)));

  if (baseKeys.size === 0) {
    problems.push(`messages/${baseLocale}.json defines no messages at all.`);
  }

  for (const locale of locales) {
    if (locale === baseLocale) continue;
    const catalog = catalogs[locale];
    const keys = new Set(Object.keys(catalog).filter((k) => !NOT_A_MESSAGE(k)));

    const missing = difference(baseKeys, keys);
    const extra = difference(keys, baseKeys);
    if (missing.size > 0) {
      problems.push(
        `messages/${locale}.json is missing ${missing.size} key(s) present in ` +
          `${baseLocale}: ${sorted(missing).join(', ')}`
      );
    }
    if (extra.size > 0) {
      problems.push(
        `messages/${locale}.json defines ${extra.size} key(s) that ${baseLocale} does not: ` +
          `${sorted(extra).join(', ')} — remove them, or add them to ${baseLocale} first.`
      );
    }

    for (const key of sorted(difference(baseKeys, missing))) {
      const here = catalog[key];
      const there = base[key];

      const minePlaceholders = messagePlaceholders(here);
      const basePlaceholders = messagePlaceholders(there);
      const lost = difference(basePlaceholders, minePlaceholders);
      const invented = difference(minePlaceholders, basePlaceholders);
      if (lost.size > 0) {
        problems.push(
          `messages/${locale}.json "${key}" drops placeholder(s) ${sorted(lost).join(', ')} — ` +
            `the value would never be shown.`
        );
      }
      if (invented.size > 0) {
        problems.push(
          `messages/${locale}.json "${key}" references ${sorted(invented).join(', ')}, which ` +
            `${baseLocale} does not declare — it would compile to nothing.`
        );
      }

      if (isVariant(there) !== isVariant(here)) {
        problems.push(
          `messages/${locale}.json "${key}" is ${isVariant(here) ? 'a variant' : 'a plain string'} ` +
            `but ${baseLocale} has ${isVariant(there) ? 'a variant' : 'a plain string'} — ` +
            `the shapes have to match.`
        );
        continue;
      }
      if (!isVariant(there)) continue;

      const { plural } = selectorInfo(there);
      const baseArms = armsBySelector(there);
      const mineArms = armsBySelector(here);
      const required = pluralCategories(locale);

      // A selector `base` declares but this locale's variant drops entirely
      // is invisible to the loop below, which only walks `mineArms` — and a
      // translator deleting a whole `{$count ->}` branch is exactly the kind
      // of drift the placeholder checks above are meant to catch.
      const droppedSelectors = difference(new Set(baseArms.keys()), new Set(mineArms.keys()));
      if (droppedSelectors.size > 0) {
        problems.push(
          `messages/${locale}.json "${key}" is missing selector(s) ` +
            `${sorted(droppedSelectors).join(', ')} that ${baseLocale} declares — ` +
            `the variant shapes have to match.`
        );
      }

      for (const [selector, armsHere] of mineArms) {
        // `*` is the catch-all; a message that supplies it covers every arm.
        if (armsHere.has('*')) continue;

        if (plural.has(selector)) {
          const missingArms = difference(required, armsHere);
          const uselessArms = difference(armsHere, required);
          if (missingArms.size > 0) {
            problems.push(
              `messages/${locale}.json "${key}" selector "${selector}" is missing plural ` +
                `categor${missingArms.size === 1 ? 'y' : 'ies'} ${sorted(missingArms).join(', ')} — ` +
                `${locale} needs ${sorted(required).join(', ')}.`
            );
          }
          if (uselessArms.size > 0) {
            problems.push(
              `messages/${locale}.json "${key}" selector "${selector}" declares ` +
                `${sorted(uselessArms).join(', ')}, which ${locale} never selects — ` +
                `${locale} needs ${sorted(required).join(', ')}.`
            );
          }
        } else {
          const expected = baseArms.get(selector) ?? new Set();
          const missingArms = difference(expected, armsHere);
          if (missingArms.size > 0) {
            problems.push(
              `messages/${locale}.json "${key}" selector "${selector}" is missing arm(s) ` +
                `${sorted(missingArms).join(', ')} — a non-plural selector has to match ${baseLocale}.`
            );
          }
        }
      }
    }
  }

  return problems;
}

/** Catalog filenames that no locale claims — a rename that left a stray behind. */
export function orphanCatalogs({ locales }, root = webRoot) {
  const known = new Set(locales.map((l) => `${l}.json`));
  return readdirSync(join(root, 'messages'))
    .filter((f) => f.endsWith('.json') && !known.has(f))
    .sort();
}

function main() {
  const settings = readSettings();
  const catalogs = Object.fromEntries(settings.locales.map((l) => [l, readCatalog(l)]));
  const problems = check(settings, catalogs);

  for (const orphan of orphanCatalogs(settings)) {
    problems.push(
      `messages/${orphan} is not a locale in project.inlang/settings.json — ` +
        `it is compiled by nothing and translated by nobody.`
    );
  }

  if (problems.length === 0) {
    const count = Object.keys(catalogs[settings.baseLocale]).filter(
      (k) => !NOT_A_MESSAGE(k)
    ).length;
    console.log(`messages: ${count} keys × ${settings.locales.length} locales, complete.`);
    return;
  }

  console.error(`\n${problems.length} message catalog problem(s):\n`);
  for (const problem of problems) console.error(`  • ${problem}`);
  console.error('');
  process.exit(1);
}

// Importable for the unit tests; only the direct invocation exits the process.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
