/**
 * The words a reader sees for values the wire keeps in English.
 *
 * **The wire values do not change.** `owner` / `admin` / `member` stay the
 * wire values in every request body and comparison; this is only what a human
 * reads.
 */

import { m } from '$lib/paraglide/messages';
import type { Role } from '$lib/types';

/**
 * The word for a role.
 *
 * `owner` / `admin` / `member` stay the wire values in every
 * `<option value=…>`, comparison and request body, and this is only what a
 * reader sees. Shared rather than page-local because the members roster and the
 * org overview both print it, and one of them printing the raw enum while the
 * other translates it is exactly the drift this prevents.
 */
export function roleLabel(role: Role): string {
  switch (role) {
    case 'owner':
      return m.members_role_owner();
    case 'admin':
      return m.members_role_admin();
    case 'member':
      return m.members_role_member();
  }
}

/**
 * Split a message around the place a link goes.
 *
 * A sentence with a link inside it is still one sentence, and the link does not
 * sit in the same place in every language — German puts the verb at the end,
 * Hindi puts it later still. So the message carries a marker, the page splits
 * on it, and the anchor is rendered between the halves. The alternative is two
 * message fragments concatenated around an `<a>`, which no translator can
 * reorder.
 *
 * Returns `[before, after]`; a message with no marker yields the whole sentence
 * and an empty tail, so a translation that drops the marker degrades to a
 * sentence with the link appended rather than to a blank page.
 */
export const LINK = '::link::';

export function around(sentence: string): [string, string] {
  const at = sentence.indexOf(LINK);
  if (at === -1) return [sentence, ''];
  // `slice`, not `split` + destructure: a translation where the marker
  // appears twice must keep everything after the first occurrence, not
  // silently drop it at the second.
  return [sentence.slice(0, at), sentence.slice(at + LINK.length)];
}
