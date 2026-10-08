/**
 * The code-to-sentence lookup, and the fallback that makes it safe to ship.
 *
 * Issue #42 names the fallback test specifically, and for a good reason: this
 * bundle is a static artifact that can be months older than the server it talks
 * to. A code it has never heard of must produce the server's English sentence,
 * never a blank alert and never the literal key.
 */

import { describe, expect, it } from 'vitest';

import { ApiError } from './api';
import { messageFor } from './errors';
import { WebauthnError } from './webauthn';

const FALLBACK = 'fallback sentence';

describe('messageFor', () => {
  it('translates a code it knows, ignoring the server prose beside it', () => {
    const known = messageFor(new ApiError(404, 'org_not_found', 'raw server text'), FALLBACK);
    expect(known).not.toBe('raw server text');
    expect(known).toBe('No such organization.');
  });

  /**
   * The path the issue calls out. A server deployed ahead of this bundle sends
   * a code that is not in the table; the reader gets an untranslated sentence
   * rather than nothing at all.
   */
  it('falls back to the server message for a code it has never seen', () => {
    const rendered = messageFor(
      new ApiError(409, 'a_code_invented_next_year', 'The widget frobnicator is jammed.'),
      FALLBACK
    );
    expect(rendered).toBe('The widget frobnicator is jammed.');
    expect(rendered).not.toBe('');
    expect(rendered).not.toBe(FALLBACK);
  });

  it('never renders a bare code or an empty string', () => {
    for (const code of ['', 'unheard_of', 'org_not_found', 'rate_limited']) {
      const rendered = messageFor(new ApiError(400, code, 'server prose'), FALLBACK);
      expect(rendered.trim()).not.toBe('');
      expect(rendered).not.toBe(code);
    }
  });

  it('translates a WebauthnError by its code', () => {
    const cancelled = new WebauthnError('passkey_cancelled', 'English original');
    expect(messageFor(cancelled, FALLBACK)).toBe(
      'No passkey was used. Try again when you are ready.'
    );
  });

  /**
   * The one webauthn code carrying data. The `DOMException` name is not a word
   * in anybody's language, so the sentence around it is translated and the name
   * is placed into it.
   */
  it('places the DOMException name into the refusal sentence', () => {
    const refused = new WebauthnError('passkey_refused', 'ignored', 'AbortError');
    expect(messageFor(refused, FALLBACK)).toContain('AbortError');
  });

  it('survives a refusal with no detail', () => {
    const refused = new WebauthnError('passkey_refused', 'ignored');
    const rendered = messageFor(refused, FALLBACK);
    expect(rendered.trim()).not.toBe('');
    expect(rendered).not.toContain('undefined');
  });

  /**
   * Anything that is neither of our error types had its message written for a
   * developer. Callers pass a keyed sentence instead of leaking `String(e)`.
   */
  it('uses the caller fallback for an error that is neither of ours', () => {
    expect(messageFor(new TypeError('x is not a function'), FALLBACK)).toBe(FALLBACK);
    expect(messageFor('a bare string', FALLBACK)).toBe(FALLBACK);
    expect(messageFor(undefined, FALLBACK)).toBe(FALLBACK);
  });

  /**
   * The console mirrors the server's rule rather than softening it: the API
   * answers 404 for both a nonexistent org and one the caller is not in,
   * precisely so the two cannot be told apart. A console that said "you do not
   * have access" would undo that from the client side.
   */
  it('does not distinguish a missing org from one the caller is not in', () => {
    const rendered = messageFor(new ApiError(404, 'org_not_found', 'x'), FALLBACK).toLowerCase();
    expect(rendered).not.toContain('access');
    expect(rendered).not.toContain('permission');
  });
});
