/**
 * How a plan from `GET /api/plans` is put into words on the pricing page.
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
import type { Plan } from '$lib/types';

/**
 * What a plan's price slot says.
 *
 * `contact` carries no amount on purpose: Enterprise is negotiated, and its
 * `monthlyCents` (`0` in the seed) is not a price to show anyone.
 */
export type PriceLabel =
  { kind: 'contact' } | { kind: 'free'; amount: string } | { kind: 'monthly'; amount: string };

function dollars(cents: number, locale: Locale): string {
  // Whole dollars drop the `.00` a list price never shows; anything else keeps
  // both decimals rather than rounding a real price to a wrong one.
  const whole = cents % 100 === 0;
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: whole ? 0 : 2,
    maximumFractionDigits: whole ? 0 : 2
  }).format(cents / 100);
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
  const amount = dollars(plan.monthlyCents, locale);
  return plan.monthlyCents === 0 ? { kind: 'free', amount } : { kind: 'monthly', amount };
}

/** An operation count with the page language's digit grouping (`10,000`, `10.000`, `10,00,000`). */
export function formatOps(ops: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(ops);
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
 * anything else.
 */
export function featureLabels(features: Plan['features']): Array<() => string> {
  return FEATURE_LABELS.filter(([key]) => features[key] === true).map(([, label]) => label);
}
