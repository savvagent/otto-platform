import { describe, expect, it } from 'vitest';

import {
  MAX_MONTHLY_BUDGET_CENTS,
  budgetAlerts,
  dollarsInput,
  formatCents,
  formatPercent,
  parseDollars,
  serviceName
} from './billing';
import type { ServiceBudget } from './types';

describe('parseDollars', () => {
  it('turns dollars into exact integer cents, with no float rounding', () => {
    expect(parseDollars('250')).toEqual({ ok: true, cents: 25_000 });
    expect(parseDollars('250.5')).toEqual({ ok: true, cents: 25_050 });
    expect(parseDollars('250.50')).toEqual({ ok: true, cents: 25_050 });
    // 0.29 * 100 is 28.999999999999996 as a float.
    expect(parseDollars('0.29')).toEqual({ ok: true, cents: 29 });
    expect(parseDollars('1.15')).toEqual({ ok: true, cents: 115 });
    expect(parseDollars('0.01')).toEqual({ ok: true, cents: 1 });
  });

  it('accepts a comma as the decimal mark, a leading dollar sign and surrounding space', () => {
    expect(parseDollars(' 250,50 ')).toEqual({ ok: true, cents: 25_050 });
    expect(parseDollars('$99')).toEqual({ ok: true, cents: 9_900 });
  });

  it('says why an amount is refused', () => {
    expect(parseDollars('')).toEqual({ ok: false, reason: 'empty' });
    expect(parseDollars('   ')).toEqual({ ok: false, reason: 'empty' });
    for (const bad of ['abc', '1.234', '1,234,567', '-5', '1e3', '12.', '.5', '0x10', '1 000']) {
      expect(parseDollars(bad), bad).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(parseDollars('0')).toEqual({ ok: false, reason: 'too_small' });
    expect(parseDollars('0.00')).toEqual({ ok: false, reason: 'too_small' });
  });

  it('is bounded by the server maximum, exactly', () => {
    expect(MAX_MONTHLY_BUDGET_CENTS).toBe(1_000_000_000);
    expect(parseDollars('10000000')).toEqual({ ok: true, cents: MAX_MONTHLY_BUDGET_CENTS });
    expect(parseDollars('10000000.01')).toEqual({ ok: false, reason: 'too_large' });
    // Far past Number.MAX_SAFE_INTEGER: still a clean refusal, not a wrapped value.
    expect(parseDollars('99999999999999999999999')).toEqual({ ok: false, reason: 'too_large' });
  });
});

describe('dollarsInput', () => {
  it('writes cents back as an editable dollar amount that parses to the same cents', () => {
    for (const cents of [1, 29, 100, 25_000, 25_050, MAX_MONTHLY_BUDGET_CENTS]) {
      expect(parseDollars(dollarsInput(cents))).toEqual({ ok: true, cents });
    }
    expect(dollarsInput(25_000)).toBe('250');
    expect(dollarsInput(25_050)).toBe('250.50');
    expect(dollarsInput(7)).toBe('0.07');
  });
});

describe('formatCents', () => {
  it('formats US dollars in the page language, always with cents', () => {
    expect(formatCents(25_050, 'en')).toBe('$250.50');
    expect(formatCents(0, 'en')).toBe('$0.00');
    expect(formatCents(MAX_MONTHLY_BUDGET_CENTS, 'en')).toBe('$10,000,000.00');
    expect(formatCents(25_050, 'de')).toContain('250,50');
    expect(formatCents(25_050, 'de')).toContain('$');
  });
});

describe('formatPercent', () => {
  it('writes a whole percentage the locale way', () => {
    expect(formatPercent(80, 'en')).toBe('80%');
    expect(formatPercent(125, 'en')).toBe('125%');
    expect(formatPercent(80, 'de')).toMatch(/^80\s%$/u);
  });
});

describe('serviceName', () => {
  it('names a described service, and shows any other slug as given', () => {
    expect(serviceName('otto-flags')).toBe('Otto Flags');
    expect(serviceName('otto-factory')).toBe('Otto Factory');
    expect(serviceName('otto-new')).toBe('otto-new');
  });
});

describe('budgetAlerts', () => {
  const row = (fields: Partial<ServiceBudget>): ServiceBudget => ({
    service: 'otto-flags',
    spendCents: 0,
    spendError: null,
    thresholdsReached: [],
    budget: {
      monthlyBudgetCents: 10_000,
      hardStop: false,
      percentUsed: 0,
      blocked: false,
      updatedAt: '2026-10-01T00:00:00Z'
    },
    ...fields
  });

  it('reports the highest threshold reached per budgeted service', () => {
    const alerts = budgetAlerts([
      row({ service: 'otto-flags', thresholdsReached: [50, 80] }),
      row({ service: 'otto-cxp', thresholdsReached: [] }),
      row({ service: 'otto-factory', thresholdsReached: [50] })
    ]);
    expect(alerts).toEqual([
      { service: 'otto-flags', threshold: 80, blocked: false },
      { service: 'otto-factory', threshold: 50, blocked: false }
    ]);
  });

  it('marks a hard-stopped service as blocked, and ignores a service with no budget', () => {
    const budget = {
      monthlyBudgetCents: 100,
      hardStop: true,
      percentUsed: 100,
      blocked: true,
      updatedAt: '2026-10-01T00:00:00Z'
    };
    expect(
      budgetAlerts([
        row({ thresholdsReached: [50, 80, 100], budget }),
        row({ service: 'otto-cxp', thresholdsReached: [50], budget: null })
      ])
    ).toEqual([{ service: 'otto-flags', threshold: 100, blocked: true }]);
  });

  it('lists the most urgent first', () => {
    const alerts = budgetAlerts([
      row({ service: 'otto-a', thresholdsReached: [50] }),
      row({ service: 'otto-b', thresholdsReached: [50, 80, 100] }),
      row({ service: 'otto-c', thresholdsReached: [50, 80] })
    ]);
    expect(alerts.map((a) => a.service)).toEqual(['otto-b', 'otto-c', 'otto-a']);
  });
});
