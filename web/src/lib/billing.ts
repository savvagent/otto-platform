/**
 * Money, budgets and service names for the console's usage, budgets and
 * billing pages.
 *
 * Pure, and free of English, like `$lib/pricing`: each helper returns a
 * formatted value or a structured one the component puts into words.
 *
 * **Money is integer US cents, end to end.** Spend and budgets arrive as
 * cents and go back as cents. The one place a person types dollars, the
 * budget input, is parsed as a *string* into cents (`parseDollars`): never
 * through a float, where `0.29 * 100` is `28.999999999999996`.
 */

import type { Locale } from '$lib/locale';
import { formatUsd } from '$lib/pricing';
import { SERVICES, connectorName } from '$lib/services';
import type { BudgetThreshold, ServiceBudget } from '$lib/types';

/**
 * The largest monthly budget the server accepts, in cents ($10,000,000):
 * `otto_billing::budgets::MAX_MONTHLY_BUDGET_CENTS`.
 */
export const MAX_MONTHLY_BUDGET_CENTS = 1_000_000_000;

/** The smallest, in cents. The server's range starts at 1. */
export const MIN_MONTHLY_BUDGET_CENTS = 1;

/** Cents as the locale writes US dollars, always with two decimals: `$250.50`. */
export function formatCents(cents: number, locale: Locale): string {
  return formatUsd(cents, 2, 2, locale);
}

/** A whole percentage the locale way: `80%`, `80 %`. */
export function formatPercent(percent: number, locale: Locale): string {
  return new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 0 }).format(
    percent / 100
  );
}

export type DollarsError = 'empty' | 'invalid' | 'too_small' | 'too_large';

export type ParsedDollars = { ok: true; cents: number } | { ok: false; reason: DollarsError };

/**
 * Whole dollars, then optionally a decimal mark (`.` or `,`, since half the
 * console's languages write `250,50`) and up to two digits of cents. Either
 * side may be empty, so `.5` and `12.` read as people mean them, but not
 * both. Grouping separators are refused rather than guessed at: `1,234` is a
 * thousand-odd dollars in English and one dollar and change in German.
 */
const DOLLARS = /^(?=[.,]?\d)(\d*)(?:[.,](\d{0,2}))?$/;

/**
 * A typed dollar amount, as exact integer cents within the server's range.
 *
 * Computed with `BigInt`, so an absurdly long number is refused as too large
 * rather than wrapping or losing digits on its way to the bound check.
 */
export function parseDollars(input: string): ParsedDollars {
  // A dollar sign either side, as `$250` or the `250 $` some locales write.
  const trimmed = input
    .trim()
    .replace(/^\$\s*/, '')
    .replace(/\s*\$$/, '');
  if (trimmed === '') return { ok: false, reason: 'empty' };
  const match = DOLLARS.exec(trimmed);
  if (!match) return { ok: false, reason: 'invalid' };
  const whole = BigInt(match[1] || '0');
  const fraction = BigInt((match[2] ?? '').padEnd(2, '0'));
  const cents = whole * 100n + fraction;
  if (cents < BigInt(MIN_MONTHLY_BUDGET_CENTS)) return { ok: false, reason: 'too_small' };
  if (cents > BigInt(MAX_MONTHLY_BUDGET_CENTS)) return { ok: false, reason: 'too_large' };
  return { ok: true, cents: Number(cents) };
}

/** Cents as an editable amount (`250`, `250.50`) that `parseDollars` reads back exactly. */
export function dollarsInput(cents: number): string {
  const whole = Math.trunc(cents / 100);
  const rest = cents % 100;
  return rest === 0 ? `${whole}` : `${whole}.${String(rest).padStart(2, '0')}`;
}

/**
 * Service slugs that were renamed. Usage and budget rows written before the
 * rename still carry the old slug, and must keep a display name.
 */
const LEGACY_SERVICE_NAMES: ReadonlyMap<string, string> = new Map([
  ['otto-factory', 'Savvagent Tower']
]);

/**
 * The name a service slug (`otto-flags`) goes by in the header and on the
 * product pages, or the slug itself for a service this console does not
 * describe yet: its usage is real either way.
 */
export function serviceName(slug: string): string {
  return (
    SERVICES.find((s) => connectorName(s) === slug)?.name ?? LEGACY_SERVICE_NAMES.get(slug) ?? slug
  );
}

/** One budget alert to show in the console. */
export interface BudgetAlert {
  service: string;
  /** The highest threshold reached this month. */
  threshold: BudgetThreshold;
  /** The hard stop is refusing billable calls to this service. */
  blocked: boolean;
}

/**
 * The budget alerts to show: per budgeted service, the highest threshold
 * whose alert has fired this month, most urgent first.
 *
 * A service with no budget shows none, even with thresholds on record from
 * a budget since removed: there is nothing left for it to be at a share of.
 * A blocked service always shows, at 100.
 */
export function budgetAlerts(services: readonly ServiceBudget[]): BudgetAlert[] {
  const alerts: BudgetAlert[] = [];
  for (const s of services) {
    if (!s.budget) continue;
    const blocked = s.budget.blocked;
    const highest = s.thresholdsReached.reduce<number>((a, b) => Math.max(a, b), 0);
    if (!blocked && highest === 0) continue;
    alerts.push({
      service: s.service,
      threshold: (blocked ? 100 : highest) as BudgetThreshold,
      blocked
    });
  }
  // A stable sort keeps the server's order between equals.
  return alerts.sort((a, b) => Number(b.blocked) - Number(a.blocked) || b.threshold - a.threshold);
}
