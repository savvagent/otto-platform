import { describe, expect, it } from 'vitest';

import { m } from '$lib/paraglide/messages';
import { locales } from '$lib/paraglide/runtime';

/**
 * The usage meter's captions, rendered with real counts in every locale.
 *
 * They were written with ICU's `#` shorthand, which Paraglide prints
 * literally, so the org usage page read "# tool calls recorded this period."
 * (#34). The counts reach every plural category the shipped locales select:
 * 0 is `one` in fr and hi, 1 is `one`, 2 and 5 are `other`, and 1 000 000 is
 * `many` in es, fr and it. Paraglide inserts the number unformatted, hence
 * `String(count)`.
 */
const counts = [0, 1, 2, 5, 1_000_000];

const captions = {
  meter_calls_recorded: m.meter_calls_recorded,
  meter_calls_billable: m.meter_calls_billable
};

describe('usage meter captions', () => {
  for (const locale of locales) {
    for (const [key, caption] of Object.entries(captions)) {
      it(`${key} shows the count in ${locale}`, () => {
        for (const count of counts) {
          const text = caption({ count }, { locale });
          expect(text).toContain(String(count));
          expect(text).not.toContain('#');
        }
      });
    }
  }
});
