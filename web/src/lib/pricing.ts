/**
 * How the catalog from `GET /api/plans` — plans, and the metered usage prices
 * in effect this month — is put into words on the pricing page.
 *
 * Pure, and free of English: each helper returns either a formatted number or
 * a structured value the component renders with messages, so the same plan
 * reads correctly in every catalog and the tests can pin the rules without a
 * DOM.
 *
 * **The locale is a parameter, not `currentLocale()`.** `$lib/format` reads the
 * console's resolved locale, which on a marketing page is whatever the visitor
 * last chose in the console, not the language of the URL they are reading. The
 * page passes its own `lang`, so `/de/pricing` groups digits the German way
 * even for someone whose console is in English.
 *
 * **Prices are always US dollars**, in the page language's notation: a Spanish
 * reader sees `29 US$`, never a euro amount nobody charges.
 */

import { m } from '$lib/paraglide/messages';
import type { Locale } from '$lib/locale';
import { SERVICES, connectorName } from '$lib/services';
import type { Plan, PlanTier, PlansResponse, PriceTier, PricedMeter } from '$lib/types';

const TIERS: readonly PlanTier[] = ['free', 'team', 'business', 'enterprise'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

/**
 * The catalog in a `GET /api/plans` body, or a thrown `Error` naming the first
 * field that is not what `PlansResponse` promises.
 *
 * The page renders straight from these fields, so a contract drift that
 * reached it unchecked would not fail; it would mislead. A missing
 * `monthlyCents` prints `$NaN`, an unknown tier would be priced as if it were
 * self-serve, and a tier table that goes backwards would print a price nobody
 * charges. Refusing the whole answer turns any of those into the page's
 * existing "could not be loaded" state, and the error says which field.
 *
 * **Usage prices degrade instead of blanking the page.** The plans are the
 * page's core, so a fault in `meters` costs only the usage prices it
 * touches, and each fault is handed to `report` (by default
 * `console.error`) so it is not mistaken for "no prices yet" by whoever
 * debugs it:
 *
 * - no `meters` array at all reads as no published usage prices;
 * - a meter with a missing or mistyped field, or tiers that do not form a
 *   graduated table, is dropped on its own — a wrong price is never shown,
 *   and the other meters still are;
 * - a second meter with the same `service` and `meter` is dropped, keeping
 *   the first, so one meter never shows two price tables.
 *
 * Fields the contract no longer has (the retired `includedOps` and
 * `hardStop`) are dropped, not copied: an older cached answer cannot put an
 * allowance back on the page.
 *
 * `features` is the exception to strictness: it only ever adds a line, so a
 * value that is not an object is read as no features (see `featureLabels`)
 * rather than failing the page.
 */
export function parseCatalog(body: unknown, report: ReportProblem = logProblem): PlansResponse {
  if (!isRecord(body) || !Array.isArray(body.plans)) {
    throw new Error('GET /api/plans answered without a plans array');
  }
  const plans = body.plans.map(parsePlan);

  if (!Array.isArray(body.meters)) {
    report(new Error('GET /api/plans answered without a meters array; showing no usage prices'));
    return { plans, meters: [] };
  }

  const meters: PricedMeter[] = [];
  const seen = new Set<string>();
  body.meters.forEach((raw: unknown, i) => {
    let meter: PricedMeter;
    try {
      meter = parseMeter(raw, i);
    } catch (problem) {
      report(problem instanceof Error ? problem : new Error(String(problem)));
      return;
    }
    const key = `${meter.service}/${meter.meter}`;
    if (seen.has(key)) {
      report(new Error(`GET /api/plans: meters[${i}] repeats ${key}; keeping the first`));
      return;
    }
    seen.add(key);
    meters.push(meter);
  });
  return { plans, meters };
}

/** Where `parseCatalog` sends a fault it recovered from. */
export type ReportProblem = (problem: Error) => void;

const logProblem: ReportProblem = (problem) => console.error('pricing:', problem);

function parsePlan(raw: unknown, i: number): Plan {
  const bad = (field: string) =>
    new Error(`GET /api/plans: plans[${i}].${field} is missing or the wrong type`);
  if (!isRecord(raw)) throw bad('(plan)');
  const { plan, displayName, monthlyCents, features } = raw;
  if (typeof plan !== 'string' || !TIERS.includes(plan as PlanTier)) throw bad('plan');
  if (!isText(displayName)) throw bad('displayName');
  if (!isCount(monthlyCents)) throw bad('monthlyCents');
  return {
    plan: plan as PlanTier,
    displayName,
    monthlyCents,
    features: (isRecord(features) ? features : {}) as Plan['features']
  };
}

const isText = (value: unknown): value is string =>
  typeof value === 'string' && value.trim() !== '';

/**
 * One meter, with its tiers checked to form a graduated table: every bound a
 * positive whole number above the one before, only the last unbounded, and
 * every price a whole, non-negative number of millionths of a cent.
 */
function parseMeter(raw: unknown, i: number): PricedMeter {
  const bad = (field: string) =>
    new Error(`GET /api/plans: meters[${i}].${field} is missing or the wrong type`);
  if (!isRecord(raw)) throw bad('(meter)');
  const { service, meter, displayName, unit, tiers } = raw;
  if (!isText(service)) throw bad('service');
  if (!isText(meter)) throw bad('meter');
  if (!isText(displayName)) throw bad('displayName');
  if (!isText(unit)) throw bad('unit');
  if (!Array.isArray(tiers) || tiers.length === 0) throw bad('tiers');

  let floor = 0;
  const parsed = tiers.map((tier: unknown, t): PriceTier => {
    const where = `tiers[${t}]`;
    if (!isRecord(tier)) throw bad(where);
    const { upTo, unitAmountUcents } = tier;
    if (!isCount(unitAmountUcents)) throw bad(`${where}.unitAmountUcents`);
    const last = t === tiers.length - 1;
    if (last ? upTo !== null : !isCount(upTo) || upTo <= floor) throw bad(`${where}.upTo`);
    if (!last) floor = upTo as number;
    return { upTo: upTo as number | null, unitAmountUcents };
  });
  return { service, meter, displayName, unit, tiers: parsed };
}

/**
 * What a plan's price slot says.
 *
 * Only `monthly` carries an amount. `contact` has none on purpose: Enterprise
 * is negotiated, and its `monthlyCents` (`0` in the seed) is not a price to
 * show anyone. `free` has none because the page says the word, which reads
 * better than "$0 per month" and needs no currency at all.
 */
export type PriceLabel =
  { kind: 'contact' } | { kind: 'free' } | { kind: 'monthly'; amount: string };

/**
 * A whole number of `10^-scale` dollars (cents are scale 2, millionths of a
 * cent scale 8), as the page language writes US dollars — exactly.
 *
 * **Never a float.** The integer is split into whole dollars and a
 * `scale`-digit fraction with `BigInt`, and the resulting decimal *string* is
 * what `Intl.NumberFormat` formats: it formats a numeric string at full
 * precision, so `7` millionths of a cent prints as $0.00000007 rather than
 * rounding noise, and a large amount keeps every digit. Trailing zeros past
 * `minimumFractionDigits` are dropped.
 */
export function formatUsd(
  amount: number,
  scale: number,
  minimumFractionDigits: number,
  locale: Locale
): string {
  const value = BigInt(amount);
  const one = 10n ** BigInt(scale);
  const whole = value / one;
  const fraction = (value % one).toString().padStart(scale, '0').replace(/0+$/, '');
  const decimal = fraction === '' ? `${whole}` : `${whole}.${fraction}`;
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits,
    maximumFractionDigits: scale
  }).format(decimal as `${number}`);
}

function dollars(cents: number, locale: Locale): string {
  // Whole dollars drop the `.00` a list price never shows; anything else keeps
  // both decimals rather than rounding a real price to a wrong one.
  return formatUsd(cents, 2, cents % 100 === 0 ? 0 : 2, locale);
}

/**
 * The price, as the page should present it.
 *
 * Enterprise is checked first and by tier, not by amount: the schema defines
 * `0` on enterprise as "negotiated", so reading the cents alone would
 * advertise the largest plan as free.
 */
export function priceLabel(plan: Pick<Plan, 'plan' | 'monthlyCents'>, locale: Locale): PriceLabel {
  if (plan.plan === 'enterprise') return { kind: 'contact' };
  if (plan.monthlyCents === 0) return { kind: 'free' };
  return { kind: 'monthly', amount: dollars(plan.monthlyCents, locale) };
}

/** A unit count with the page language's digit grouping (`10,000`, `10.000`, `10,00,000`). */
function formatCount(count: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(count);
}

/** A per-unit price: the word "free", or an exact dollar amount. */
export type UnitPrice = { kind: 'free' } | { kind: 'unit'; amount: string };

/** Decimal places in a price stored in millionths of a cent. */
const UCENT_SCALE = 8;

/**
 * A price in millionths of a US cent, as the page language writes dollars:
 * exact (see `formatUsd`), with at least two decimals as money reads, so
 * 150 000 is `$0.0015` and 100 000 000 is `$1.00`.
 *
 * `0` is the word "free" rather than `$0.00`.
 */
export function unitPrice(ucents: number, locale: Locale): UnitPrice {
  if (ucents === 0) return { kind: 'free' };
  return { kind: 'unit', amount: formatUsd(ucents, UCENT_SCALE, 2, locale) };
}

/**
 * Which units of the month one tier row covers.
 *
 * `upTo` is the first tier ("up to 1,000"), `between` a middle one, `above`
 * the unbounded last tier when there are others ("1,001 and above"), and
 * `all` a meter with a single unbounded tier. Counts are already formatted.
 */
export type TierRange =
  | { kind: 'upTo'; to: string }
  | { kind: 'between'; from: string; to: string }
  | { kind: 'above'; from: string }
  | { kind: 'all' };

export interface TierRow {
  range: TierRange;
  price: UnitPrice;
}

export interface MeterTiers {
  /**
   * The size of the free allowance — "first N free" — when the first tier is
   * priced at 0 and bounded, else `null`: `count` to choose the plural form,
   * `units` to print. A single free, unbounded tier has no N to name, so it
   * is just a "free" row.
   */
  freeAllowance: { count: number; units: string } | null;
  rows: TierRow[];
}

/**
 * A meter's graduated tiers as table rows.
 *
 * Each tier after the first starts at the unit after the previous tier's
 * `upTo`, which is how graduated pricing reads to a person ("1,001 to
 * 10,000") even though the wire only carries upper bounds.
 */
export function meterTiers(meter: PricedMeter, locale: Locale): MeterTiers {
  const { tiers } = meter;
  const first = tiers[0];
  const freeAllowance =
    first && first.unitAmountUcents === 0 && first.upTo !== null
      ? { count: first.upTo, units: formatCount(first.upTo, locale) }
      : null;

  const rows = tiers.map((tier, i): TierRow => {
    const previous = i === 0 ? null : (tiers[i - 1]?.upTo ?? null);
    const from = previous === null ? null : formatCount(previous + 1, locale);
    let range: TierRange;
    if (tier.upTo === null) {
      range = from === null ? { kind: 'all' } : { kind: 'above', from };
    } else {
      const to = formatCount(tier.upTo, locale);
      range = from === null ? { kind: 'upTo', to } : { kind: 'between', from, to };
    }
    return { range, price: unitPrice(tier.unitAmountUcents, locale) };
  });

  return { freeAllowance, rows };
}

export interface ServiceUsageGroup {
  /** The slug meters carry, e.g. `otto-flags`. */
  service: string;
  /**
   * The name the header and product pages use ("Otto Flags"), or the slug
   * for a service this site does not describe yet: its price is real either
   * way, so it is shown rather than hidden.
   */
  name: string;
  /** Empty for a service with no usage price published yet. */
  meters: PricedMeter[];
}

/**
 * The meters, grouped by service: every service this site describes, in the
 * site's order, with its priced meters (possibly none), then any other
 * service the server prices, in the order it listed them.
 *
 * Every described service is listed even with nothing priced, so the page can
 * say so per service rather than letting a service silently vanish.
 */
export function usageByService(meters: readonly PricedMeter[]): ServiceUsageGroup[] {
  const groups = new Map<string, ServiceUsageGroup>();
  for (const s of SERVICES) {
    const service = connectorName(s);
    groups.set(service, { service, name: s.name, meters: [] });
  }
  for (const meter of meters) {
    let group = groups.get(meter.service);
    if (!group) {
      group = { service: meter.service, name: meter.service, meters: [] };
      groups.set(meter.service, group);
    }
    group.meters.push(meter);
  }
  return [...groups.values()];
}

/**
 * The words for each feature key the server advertises.
 *
 * The server publishes only an allowlist, but this page still names only the
 * keys it has a translation for: a key added server-side first renders as
 * nothing rather than as a raw `snake_case` identifier, and appears once its
 * copy lands in every catalog. Listed in display order.
 */
const FEATURE_LABELS: ReadonlyArray<readonly [key: string, label: () => string]> = [
  ['auto_rollback', () => m.pricing_feature_auto_rollback()]
];

/**
 * The features a plan turns on, as message functions to call while rendering.
 *
 * Functions rather than strings for the same reason as `ServiceCopy`: a
 * message reads the locale when it is called, and only the component's render
 * is guaranteed to run under this page's locale override. Only a value that is
 * literally `true` counts — the schema's rule, and the safe reading of
 * anything else. `features` that are not an object at all (`null`, an array)
 * name nothing.
 */
export function featureLabels(features: Plan['features'] | null | undefined): Array<() => string> {
  if (!isRecord(features)) return [];
  return FEATURE_LABELS.filter(([key]) => features[key] === true).map(([, label]) => label);
}
