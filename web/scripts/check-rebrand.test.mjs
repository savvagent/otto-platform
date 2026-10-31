/**
 * The rebrand gate (#134), pinned.
 *
 * The last case runs the real check over the repo, so a new user-visible
 * "otto" fails `npm test` unless `docs/rebrand-allowlist.md` explains it. The
 * others pin the pieces that decide what counts as a hit.
 */

import { describe, expect, it } from 'vitest';

import { findHits, parseAllowlist, rustStrings, unexplained } from './check-rebrand.mjs';

describe('parseAllowlist', () => {
  it('reads one pattern per line from the allowlist block, skipping comments', () => {
    const doc = '# Title\n\n```allowlist\n# why\n_otto-verify\\b\n\n\\botto-flags\\b\n```\n';
    expect(parseAllowlist(doc).map((p) => p.source)).toEqual([
      '_otto-verify\\b',
      '\\botto-flags\\b'
    ]);
  });

  it('refuses a doc with no allowlist block', () => {
    expect(() => parseAllowlist('# nothing here')).toThrow(/allowlist/);
  });
});

describe('unexplained', () => {
  const patterns = parseAllowlist('```allowlist\n\\botto-flags\\b\n```\n');

  it('reports "otto" in any case', () => {
    expect(unexplained('Welcome to Otto', patterns)).toHaveLength(1);
    expect(unexplained('OTTO console', patterns)).toHaveLength(1);
  });

  it('lets through what a pattern matches', () => {
    expect(unexplained('meter otto-flags/evaluations', patterns)).toEqual([]);
  });

  it('ignores words that only contain the letters', () => {
    expect(unexplained('il prodotto e i sottocomandi', patterns)).toEqual([]);
  });
});

describe('rustStrings', () => {
  it('returns literals with their line, skipping comments and test modules', () => {
    const src = [
      '// "otto in a comment"',
      'const A: &str = "first";',
      "let q = '\"';",
      'let r = r#"raw "quoted""#;',
      '#[cfg(test)]',
      'mod tests {',
      '    fn f() { let _ = "in a test"; }',
      '}',
      'const B: &str = "last";'
    ].join('\n');
    expect(rustStrings(src)).toEqual([
      { line: 2, text: 'first' },
      { line: 4, text: 'raw "quoted"' },
      { line: 9, text: 'last' }
    ]);
  });
});

describe('the repo', () => {
  it('has no user-visible "otto" outside the allow-list', () => {
    expect(findHits()).toEqual([]);
  });
});
