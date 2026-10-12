import { afterEach, describe, expect, it } from 'vitest';

import { m } from '$lib/paraglide/messages';
import { getLocale, locales, overwriteGetLocale } from '$lib/paraglide/runtime';

import { featureLabels, formatOps, priceLabel } from './pricing';
import type { Plan } from './types';

/** A plan with the seeded Team values, overridden per test. */
function plan(fields: Partial<Plan> = {}): Plan {
  return {
    plan: 'team',
    displayName: 'Team',
    includedOps: 10_000,
    hardStop: false,
    monthlyCents: 2900,
    features: { auto_rollback: true },
    ...fields
  };
}

/** The runtime's own getter, put back after a test speaks another language. */
const defaultGetLocale = getLocale;

afterEach(() => overwriteGetLocale(defaultGetLocale));

describe('priceLabel', () => {
  it('formats a whole-dollar list price with no decimals', () => {
    expect(priceLabel(plan(), 'en')).toEqual({ kind: 'monthly', amount: '$29' });
    expect(priceLabel(plan({ monthlyCents: 19_900 }), 'en')).toEqual({
      kind: 'monthly',
      amount: '$199'
    });
  });

  it('keeps the cents when the price is not a whole dollar', () => {
    expect(priceLabel(plan({ monthlyCents: 2950 }), 'en')).toEqual({
      kind: 'monthly',
      amount: '$29.50'
    });
  });

  it('formats in the page language, still in US dollars', () => {
    const label = priceLabel(plan(), 'es');
    expect(label.kind).toBe('monthly');
    // `\s` covers the no-break space Intl puts between number and symbol.
    expect(label.kind === 'monthly' && label.amount).toMatch(/^29\sUS\$$/);
    expect(JSON.stringify(label)).not.toContain('€');
  });

  it('calls a zero price free, on every tier but enterprise', () => {
    expect(priceLabel(plan({ plan: 'free', monthlyCents: 0 }), 'en')).toEqual({
      kind: 'free',
      amount: '$0'
    });
  });

  /** `0` on enterprise is "negotiated", not "free" — the schema says so. */
  it('never prices enterprise, whatever its cents say', () => {
    expect(priceLabel(plan({ plan: 'enterprise', monthlyCents: 0 }), 'en')).toEqual({
      kind: 'contact'
    });
    expect(priceLabel(plan({ plan: 'enterprise', monthlyCents: 99_900 }), 'en')).toEqual({
      kind: 'contact'
    });
  });
});

describe('formatOps', () => {
  it('groups digits the way the page language does', () => {
    expect(formatOps(10_000, 'en')).toBe('10,000');
    expect(formatOps(10_000, 'de')).toBe('10.000');
    expect(formatOps(1_000_000, 'hi')).toBe('10,00,000');
  });
});

describe('featureLabels', () => {
  it('names a known feature that is on, in the current language', () => {
    const labels = featureLabels({ auto_rollback: true });
    expect(labels.map((label) => label())).toEqual(['Automatic rollback in Otto Flags']);

    overwriteGetLocale(() => 'es');
    expect(labels[0]?.()).toBe(m.pricing_feature_auto_rollback({}, { locale: 'es' }));
  });

  it('drops features that are off, and keys it has no words for', () => {
    expect(featureLabels({ auto_rollback: false })).toEqual([]);
    expect(featureLabels({ teleportation: true })).toEqual([]);
    expect(featureLabels({})).toEqual([]);
  });

  it('ignores a value that is not literally true', () => {
    expect(featureLabels({ auto_rollback: 'yes' as unknown as boolean })).toEqual([]);
  });
});

describe('the pricing copy', () => {
  /**
   * Same budget as the product pages: a longer meta description is cut off
   * mid-word in a search result, in whichever language ran long.
   */
  it('keeps the meta description within 160 characters in every locale', () => {
    for (const locale of locales) {
      expect(m.pricing_description({}, { locale }).length, locale).toBeLessThanOrEqual(160);
    }
  });
});
