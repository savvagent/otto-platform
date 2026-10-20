import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { m } from '$lib/paraglide/messages';
import { getLocale, locales, overwriteGetLocale } from '$lib/paraglide/runtime';

import {
  featureLabels,
  meterTiers,
  parseCatalog,
  priceLabel,
  unitPrice,
  usageByService
} from './pricing';
import type { Plan, PricedMeter } from './types';

/** A plan with the seeded Team values, overridden per test. */
function plan(fields: Partial<Plan> = {}): Plan {
  return {
    plan: 'team',
    displayName: 'Team',
    monthlyCents: 2900,
    features: { auto_rollback: true },
    ...fields
  };
}

/** The meter the server's own serialization test uses, overridden per test. */
function meter(fields: Partial<PricedMeter> = {}): PricedMeter {
  return {
    service: 'otto-flags',
    meter: 'evaluations',
    displayName: 'Flag evaluations',
    unit: 'evaluation',
    tiers: [
      { upTo: 1000, unitAmountUcents: 0 },
      { upTo: null, unitAmountUcents: 7 }
    ],
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

  it('keeps the cents in the page language too', () => {
    const label = priceLabel(plan({ monthlyCents: 1999 }), 'es');
    expect(label.kind === 'monthly' && label.amount).toMatch(/^19,99\sUS\$$/);
  });

  it('writes dollars the Hindi way, symbol first', () => {
    expect(priceLabel(plan({ monthlyCents: 19_900 }), 'hi')).toEqual({
      kind: 'monthly',
      amount: '$199'
    });
  });

  it('calls a zero price free, on every tier but enterprise', () => {
    expect(priceLabel(plan({ plan: 'free', monthlyCents: 0 }), 'en')).toEqual({ kind: 'free' });
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

describe('unitPrice', () => {
  it('turns millionths of a cent into an exact dollar amount', () => {
    expect(unitPrice(150_000, 'en')).toEqual({ kind: 'unit', amount: '$0.0015' });
    expect(unitPrice(1_000_000, 'en')).toEqual({ kind: 'unit', amount: '$0.01' });
    expect(unitPrice(100_000_000, 'en')).toEqual({ kind: 'unit', amount: '$1.00' });
    expect(unitPrice(250_000_000, 'en')).toEqual({ kind: 'unit', amount: '$2.50' });
  });

  /** The smallest price the book can hold, which a float would round away or smear. */
  it('keeps every digit of the smallest amounts, with no float noise', () => {
    expect(unitPrice(1, 'en')).toEqual({ kind: 'unit', amount: '$0.00000001' });
    expect(unitPrice(7, 'en')).toEqual({ kind: 'unit', amount: '$0.00000007' });
    expect(unitPrice(30, 'en')).toEqual({ kind: 'unit', amount: '$0.0000003' });
    expect(unitPrice(123_456_789, 'en')).toEqual({ kind: 'unit', amount: '$1.23456789' });
  });

  it('is exact for amounts too large for a float to hold', () => {
    // 2^53 + 1 millionths of a cent: as a float this would end in ...992.
    expect(unitPrice(Number.MAX_SAFE_INTEGER, 'en')).toEqual({
      kind: 'unit',
      amount: '$90,071,992.54740991'
    });
  });

  it('calls a zero price free', () => {
    expect(unitPrice(0, 'en')).toEqual({ kind: 'free' });
  });

  it('writes the amount in the page language, still in US dollars', () => {
    const es = unitPrice(150_000, 'es');
    expect(es.kind === 'unit' && es.amount).toMatch(/^0,0015\sUS\$$/);
    const de = unitPrice(150_000, 'de');
    expect(de.kind === 'unit' && de.amount).toMatch(/^0,0015\s\$$/);
    expect(unitPrice(150_000, 'hi')).toEqual({ kind: 'unit', amount: '$0.0015' });
  });
});

describe('meterTiers', () => {
  it('reads a free first tier as an allowance, then prices the rest', () => {
    expect(meterTiers(meter(), 'en')).toEqual({
      freeAllowance: '1,000',
      rows: [
        { range: { kind: 'upTo', to: '1,000' }, price: { kind: 'free' } },
        { range: { kind: 'above', from: '1,001' }, price: { kind: 'unit', amount: '$0.00000007' } }
      ]
    });
  });

  it('labels a middle tier by both ends, the first unit after the tier before it', () => {
    const tiers = meterTiers(
      meter({
        tiers: [
          { upTo: 10_000, unitAmountUcents: 200_000 },
          { upTo: 1_000_000, unitAmountUcents: 150_000 },
          { upTo: null, unitAmountUcents: 100_000 }
        ]
      }),
      'en'
    );
    expect(tiers.freeAllowance).toBeNull();
    expect(tiers.rows.map((row) => row.range)).toEqual([
      { kind: 'upTo', to: '10,000' },
      { kind: 'between', from: '10,001', to: '1,000,000' },
      { kind: 'above', from: '1,000,001' }
    ]);
    expect(tiers.rows.map((row) => row.price)).toEqual([
      { kind: 'unit', amount: '$0.002' },
      { kind: 'unit', amount: '$0.0015' },
      { kind: 'unit', amount: '$0.001' }
    ]);
  });

  it('prices a single unbounded tier as every unit', () => {
    expect(meterTiers(meter({ tiers: [{ upTo: null, unitAmountUcents: 150_000 }] }), 'en')).toEqual(
      {
        freeAllowance: null,
        rows: [{ range: { kind: 'all' }, price: { kind: 'unit', amount: '$0.0015' } }]
      }
    );
  });

  /** "First N free" is only true when N is a bound; free with no bound is just free. */
  it('names no allowance when the only tier is free and unbounded', () => {
    expect(meterTiers(meter({ tiers: [{ upTo: null, unitAmountUcents: 0 }] }), 'en')).toEqual({
      freeAllowance: null,
      rows: [{ range: { kind: 'all' }, price: { kind: 'free' } }]
    });
  });

  it('groups unit counts the way the page language does', () => {
    const tiers = meterTiers(
      meter({
        tiers: [
          { upTo: 1_000_000, unitAmountUcents: 0 },
          { upTo: null, unitAmountUcents: 1 }
        ]
      }),
      'hi'
    );
    expect(tiers.freeAllowance).toBe('10,00,000');
    expect(meterTiers(meter(), 'de').freeAllowance).toBe('1.000');
  });
});

describe('usageByService', () => {
  it('lists every described service in site order, each with its meters', () => {
    const flags = meter();
    const cxp = meter({ service: 'otto-cxp', meter: 'tickets', displayName: 'Tickets' });
    const groups = usageByService([cxp, flags]);
    expect(groups.map((g) => [g.service, g.name, g.meters])).toEqual([
      ['otto-factory', 'Otto Factory', []],
      ['otto-flags', 'Otto Flags', [flags]],
      ['otto-cxp', 'Otto CXP', [cxp]]
    ]);
  });

  /** A service the server prices before this site describes it is still shown, last. */
  it('appends a priced service it does not describe, named by its slug', () => {
    const groups = usageByService([meter({ service: 'otto-new' })]);
    expect(groups.at(-1)?.service).toBe('otto-new');
    expect(groups.at(-1)?.name).toBe('otto-new');
    expect(groups.at(-1)?.meters).toHaveLength(1);
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

  it('names nothing when features is not an object at all', () => {
    for (const features of [null, undefined, [], 'auto_rollback', 1, true]) {
      expect(featureLabels(features as never), JSON.stringify(features)).toEqual([]);
    }
  });
});

describe('parseCatalog', () => {
  it('accepts the contract as the server sends it', () => {
    const team = plan();
    const flags = meter();
    expect(parseCatalog({ plans: [team], meters: [flags] })).toEqual({
      plans: [team],
      meters: [flags]
    });
    expect(parseCatalog({ plans: [], meters: [] })).toEqual({ plans: [], meters: [] });
  });

  it('refuses a body without a plans array', () => {
    for (const body of [null, undefined, [], 'plans', { plans: {} }, { unexpected: true }]) {
      expect(() => parseCatalog(body), JSON.stringify(body)).toThrow(/plans array/);
    }
  });

  /** Missing is not "no prices yet": the page would say "coming soon" about a broken answer. */
  it('refuses a body without a meters array', () => {
    for (const meters of [undefined, null, {}, 'x']) {
      expect(() => parseCatalog({ plans: [plan()], meters }), String(meters)).toThrow(
        /meters array/
      );
    }
  });

  it('drops the retired allowance fields rather than passing them on', () => {
    const { plans } = parseCatalog({
      plans: [{ ...plan(), includedOps: 10_000, hardStop: false }],
      meters: []
    });
    expect(plans[0]).toEqual(plan());
  });

  it('refuses a plan with a missing or mistyped field, naming it', () => {
    const cases: Array<[field: string, value: unknown]> = [
      ['plan', undefined],
      ['plan', 'platinum'],
      ['plan', 3],
      ['displayName', undefined],
      ['displayName', ''],
      ['displayName', 7],
      ['monthlyCents', undefined],
      ['monthlyCents', null],
      ['monthlyCents', '2900'],
      ['monthlyCents', Number.NaN]
    ];
    for (const [field, value] of cases) {
      const bad = { ...plan(), [field]: value };
      expect(
        () => parseCatalog({ plans: [plan(), bad], meters: [] }),
        `${field}=${String(value)}`
      ).toThrow(`plans[1].${field}`);
    }
    expect(() => parseCatalog({ plans: [null], meters: [] })).toThrow('plans[0]');
  });

  it('reads features that are not an object as none, rather than failing', () => {
    for (const features of [null, undefined, [], 'x']) {
      const {
        plans: [parsed]
      } = parseCatalog({ plans: [{ ...plan(), features }], meters: [] });
      expect(parsed?.features, JSON.stringify(features)).toEqual({});
    }
  });

  it('refuses a meter with a missing or mistyped field, naming it', () => {
    const cases: Array<[field: string, value: unknown]> = [
      ['service', undefined],
      ['service', ''],
      ['meter', 3],
      ['displayName', ''],
      ['unit', null],
      ['tiers', undefined],
      ['tiers', []],
      ['tiers', 'free']
    ];
    for (const [field, value] of cases) {
      const bad = { ...meter(), [field]: value };
      expect(
        () => parseCatalog({ plans: [], meters: [meter(), bad] }),
        `${field}=${String(value)}`
      ).toThrow(`meters[1].${field}`);
    }
    expect(() => parseCatalog({ plans: [], meters: ['x'] })).toThrow('meters[0]');
  });

  /**
   * A tier table the page would have to guess about — a price that is not a
   * whole number of millionths, a bound that goes backwards, an unbounded tier
   * that is not last — would print a wrong price, so it fails the answer.
   */
  it('refuses tiers that do not form a graduated table, naming the tier', () => {
    const cases: Array<[tiers: unknown[], where: string]> = [
      [[{ upTo: null, unitAmountUcents: -1 }], 'tiers[0].unitAmountUcents'],
      [[{ upTo: null, unitAmountUcents: 1.5 }], 'tiers[0].unitAmountUcents'],
      [[{ upTo: null, unitAmountUcents: '7' }], 'tiers[0].unitAmountUcents'],
      [[{ upTo: null }], 'tiers[0].unitAmountUcents'],
      [
        [
          { upTo: 0, unitAmountUcents: 0 },
          { upTo: null, unitAmountUcents: 1 }
        ],
        'tiers[0].upTo'
      ],
      [[{ unitAmountUcents: 1 }], 'tiers[0].upTo'],
      [[{ upTo: 100, unitAmountUcents: 1 }], 'tiers[0].upTo'],
      [
        [
          { upTo: 100, unitAmountUcents: 0 },
          { upTo: 100, unitAmountUcents: 1 },
          { upTo: null, unitAmountUcents: 1 }
        ],
        'tiers[1].upTo'
      ],
      [
        [
          { upTo: null, unitAmountUcents: 0 },
          { upTo: null, unitAmountUcents: 1 }
        ],
        'tiers[0].upTo'
      ],
      [[null], 'tiers[0]']
    ];
    for (const [tiers, where] of cases) {
      expect(
        () => parseCatalog({ plans: [], meters: [meter({ tiers: tiers as never })] }),
        JSON.stringify(tiers)
      ).toThrow(`meters[0].${where}`);
    }
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

  /**
   * Usage is billed per service, by each service's own value meters. The old
   * model — one allowance of "operations" shared by every service — must not
   * survive in a translation that nobody re-read: each locale's word for it is
   * listed, so a stale Hindi sentence fails as surely as an English one.
   */
  it('no longer describes usage as operations or as one shared allowance, in any locale', () => {
    const retired: Record<string, RegExp> = {
      en: /\boperations?\b|\bops\b|bucket|allowance|one plan covers/i,
      es: /operaci[oó]n|cuota|un solo plan cubre/i,
      de: /operation|kontingent|ein tarif gilt für alle/i,
      fr: /op[ée]ration|enveloppe|un seul forfait couvre/i,
      it: /operazion|quota|un solo piano copre/i,
      hi: /ऑपरेशन|कोटा|एक प्लान में otto की सभी/i
    };
    for (const locale of locales) {
      const catalog = JSON.parse(
        readFileSync(
          fileURLToPath(new URL(`../../messages/${locale}.json`, import.meta.url)),
          'utf8'
        )
      ) as Record<string, unknown>;
      for (const [key, value] of Object.entries(catalog)) {
        if (!/^(pricing|landing|product)_/.test(key)) continue;
        expect(JSON.stringify(value), `${locale} ${key}`).not.toMatch(retired[locale]!);
      }
    }
  });
});
