import { describe, expect, it } from 'vitest';

import { around, LINK, roleLabel } from './labels';

describe('roleLabel', () => {
  it('gives every wire role a word', () => {
    for (const role of ['owner', 'admin', 'member'] as const) {
      expect(roleLabel(role).length).toBeGreaterThan(0);
    }
  });
});

describe('around', () => {
  it('splits a sentence around the link marker', () => {
    expect(around(`See ${LINK} for more.`)).toEqual(['See ', ' for more.']);
  });

  it('degrades to the whole sentence when a translation drops the marker', () => {
    expect(around('No marker.')).toEqual(['No marker.', '']);
  });
});
