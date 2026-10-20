import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { m } from '$lib/paraglide/messages';
import { locales } from '$lib/paraglide/runtime';

/**
 * The console's usage, budget and billing copy, in every locale.
 *
 * Usage is priced per service, by value meter. The old model, one family-wide
 * bucket of "operations" every service drew down, is retired, and with it
 * every sentence that described it. A stale translation is the way such a
 * sentence survives (nobody re-reads Hindi when the English changes), so each
 * locale's own word for it is listed and every console message is checked,
 * not only the ones this change rewrote. Marketing copy has the same check in
 * `pricing.test.ts`.
 */
const RETIRED: Record<string, RegExp> = {
  en: /\boperations?\b|\bops\b|\bbucket\b/i,
  es: /operaci[oó]n/i,
  de: /operation|vorgänge|kontingent/i,
  fr: /op[ée]ration/i,
  it: /operazion/i,
  hi: /ऑपरेशन/
};

const MARKETING = /^(pricing|landing|product|marketing)_/;

function catalog(locale: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(fileURLToPath(new URL(`../../messages/${locale}.json`, import.meta.url)), 'utf8')
  ) as Record<string, unknown>;
}

describe('console usage copy', () => {
  it.each(locales)('no console message in %s speaks of operations or a shared bucket', (locale) => {
    const pattern = RETIRED[locale];
    expect(pattern, `a retired-word pattern for ${locale}`).toBeDefined();
    for (const [key, value] of Object.entries(catalog(locale))) {
      if (key.startsWith('$') || MARKETING.test(key)) continue;
      expect(JSON.stringify(value), `${locale} ${key}`).not.toMatch(pattern!);
    }
  });

  it.each(locales)('the retired meter captions are gone from %s', (locale) => {
    const keys = Object.keys(catalog(locale));
    for (const key of [
      'meter_billable_ratio',
      'meter_calls_recorded',
      'meter_calls_billable',
      'usage_field_included',
      'usage_field_remaining'
    ]) {
      expect(keys, `${locale} still has ${key}`).not.toContain(key);
    }
  });

  /**
   * Every value a sentence carries reaches it in every locale. A translation
   * that drops `{spend}` reads fine and says nothing; the message check
   * catches a missing placeholder in the JSON, and this catches one that
   * Paraglide would print literally.
   */
  for (const locale of locales) {
    it(`fills every meter, budget and billing sentence in ${locale}`, () => {
      const cases: Array<[string, string, string[]]> = [
        [
          'meter_spend_of_budget',
          m.meter_spend_of_budget({ spend: 'S$1', budget: 'B$2', percent: 'P3' }, { locale }),
          ['S$1', 'B$2', 'P3']
        ],
        [
          'meter_aria_valuetext',
          m.meter_aria_valuetext({ spend: 'S$1', budget: 'B$2', percent: 'P3' }, { locale }),
          ['S$1', 'B$2', 'P3']
        ],
        ['meter_aria_label', m.meter_aria_label({ service: 'Svc' }, { locale }), ['Svc']],
        ['meter_spend', m.meter_spend({ spend: 'S$1' }, { locale }), ['S$1']],
        ['meter_budget', m.meter_budget({ budget: 'B$2' }, { locale }), ['B$2']],
        ['usage_meters_caption', m.usage_meters_caption({ service: 'Svc' }, { locale }), ['Svc']],
        [
          'budget_alert_threshold',
          m.budget_alert_threshold({ service: 'Svc', percent: 'P80' }, { locale }),
          ['Svc', 'P80']
        ],
        ['budget_alert_blocked', m.budget_alert_blocked({ service: 'Svc' }, { locale }), ['Svc']],
        ['budget_saved', m.budget_saved({ service: 'Svc' }, { locale }), ['Svc']],
        ['budget_cleared', m.budget_cleared({ service: 'Svc' }, { locale }), ['Svc']],
        ['budget_amount_hint', m.budget_amount_hint({ max: 'M$9' }, { locale }), ['M$9']],
        ['budget_error_too_small', m.budget_error_too_small({ min: 'm$1' }, { locale }), ['m$1']],
        ['budget_error_too_large', m.budget_error_too_large({ max: 'M$9' }, { locale }), ['M$9']]
      ];
      for (const [key, text, values] of cases) {
        for (const value of values) expect(text, `${locale} ${key}`).toContain(value);
        expect(text, `${locale} ${key}`).not.toMatch(/\{\w+\}|#/);
      }
    });
  }
});
