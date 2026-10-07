/**
 * Display helpers. Nothing here decides anything; it only renders.
 *
 * Every date and number here takes the console's resolved locale rather than
 * the browser's. Those were the same thing until the language became a choice;
 * now a Spanish console on an `en-US` machine would print `9/5/2026` beside
 * Spanish prose, which reads as a bug even though each half is defensible.
 *
 * The locale is read through `currentLocale()` at call time rather than
 * captured at import, so these stay ordinary functions and this stays an
 * ordinary module — no runes, nothing to keep in sync.
 */

import { currentLocale } from '$lib/locale';

/**
 * "3 minutes ago", "in 2 days".
 *
 * `Intl.RelativeTimeFormat` rather than a date library: it is in every browser
 * this console supports, it localizes, and a dependency for one function is a
 * supply-chain surface for one function.
 */
export function relative(iso: string | null | undefined): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';

  const seconds = (then - Date.now()) / 1000;
  const format = new Intl.RelativeTimeFormat(currentLocale(), { numeric: 'auto' });

  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1]
  ];

  for (const [unit, size] of steps) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return format.format(Math.round(seconds / size), unit);
    }
  }
  return '—';
}

export function absolute(iso: string | null | undefined): string {
  if (!iso) return '—';
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? '—' : at.toLocaleString(currentLocale());
}

/**
 * A `YYYY-MM-DD` value, as a date.
 *
 * Not `absolute()`. `new Date('2026-09-01')` parses as **UTC midnight**, and
 * rendering that in a local timezone west of Greenwich moves it to the previous
 * day — a billing period that visibly starts before it starts. Splitting the
 * parts and building a local date keeps the day the server meant.
 */
export function day(iso: string | null | undefined): string {
  if (!iso) return '—';
  const [year, month, date] = iso.split('-').map(Number);
  if (!year || !month || !date) return iso;
  return new Date(year, month - 1, date).toLocaleDateString(currentLocale(), {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
}

/**
 * A slug as the server will store it, shown live under the input.
 *
 * The server lowercases and normalizes on its own — this is a preview, never a
 * validation. Duplicating the rule as a gate is how a client starts rejecting
 * names the server would have accepted.
 */
export function slugPreview(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/**
 * Copy to the clipboard, reporting whether it worked.
 *
 * `navigator.clipboard` is unavailable in an insecure context and can be
 * refused by permissions policy, and a "Copied!" that silently copied nothing
 * is worse than a button that admits it failed — particularly for a token shown
 * exactly once.
 */
export async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * How to write someone's name when the account may not have set one.
 *
 * An account exists from the moment a passkey is registered, so there is a real
 * window — and, for anyone who never bothers, a permanent state — where there
 * is no address and no name.
 *
 * **The last resort is the server's `label`, not a translated "unnamed
 * account".** The label is the same generated pair of words the account is
 * filed under in a credential vault, so someone reading a member list and
 * someone reading their password manager see the same account named the same
 * way — which a per-language placeholder could never do, and which is the whole
 * reason `label` exists.
 */
export function person(name: string | null, email: string | null, label: string): string {
  return name ?? email ?? label;
}
