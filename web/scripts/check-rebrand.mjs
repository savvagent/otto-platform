#!/usr/bin/env node
/**
 * No user-visible "otto" survives the rebrand except what
 * `docs/rebrand-allowlist.md` keeps on purpose.
 *
 * The allow-list is read from that file's `allowlist` code block, so the doc
 * that explains why an identifier stays is also the only place that lets it
 * through. A hit is "otto" with no letter before it, case-insensitive, so
 * Italian "prodotto" is not one; text an allow-list pattern matches is removed
 * first.
 *
 * What it reads is listed in the doc: the message catalogs, the console's
 * source (not its tests), its static files and Worker, and the string literals
 * of the Rust files that render copy.
 *
 * Run: `node scripts/check-rebrand.mjs`
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(webRoot, '..');

export const ALLOWLIST_DOC = 'docs/rebrand-allowlist.md';

/** The Rust files whose string literals a person reads. */
export const RUST_COPY_FILES = [
  'crates/otto-web/src/i18n.rs',
  'crates/otto-web/src/routes/sso.rs',
  'crates/otto-web/src/openapi.rs',
  'crates/otto-core/src/i18n.rs',
  'crates/otto-platform-server/src/email.rs',
  'crates/otto-billing/src/budgets.rs',
  'crates/otto-auth/src/passkeys.rs'
];

const HIT = /(?<!\p{L})otto/giu;

/** The patterns in the doc's `allowlist` block, one per line, `#` for comments. */
export function parseAllowlist(markdown) {
  const block = /^```allowlist\n([\s\S]*?)^```/m.exec(markdown);
  if (!block) throw new Error(`${ALLOWLIST_DOC} has no allowlist code block`);
  return block[1]
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map((source) => new RegExp(source, 'giu'));
}

/** Each "otto" in `text` that no pattern accounts for, as the text around it. */
export function unexplained(text, patterns) {
  let rest = text;
  for (const pattern of patterns) rest = rest.replace(pattern, ' ');
  return [...rest.matchAll(HIT)].map((m) =>
    rest.slice(Math.max(0, m.index - 20), m.index + 24).trim()
  );
}

/**
 * The string literals in Rust source, outside comments and `#[cfg(test)]`
 * modules, each with the line it starts on.
 *
 * A small lexer rather than a regex, because a `"` inside a comment, a char
 * literal or a raw string would otherwise throw every later literal off.
 */
export function rustStrings(source) {
  const src = source;
  const out = [];
  let line = 1;
  let i = 0;
  // Brace depth, and the depth a `#[cfg(test)] mod … {` opened at, if inside one.
  let depth = 0;
  let testDepth = -1;
  let testPending = false;
  const keep = (literal) => {
    if (testDepth === -1) out.push(literal);
  };
  const advance = (to) => {
    for (; i < to; i++) if (src[i] === '\n') line++;
  };
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      const end = src.indexOf('\n', i);
      advance(end === -1 ? src.length : end);
    } else if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      advance(end === -1 ? src.length : end + 2);
    } else if (c === 'r' && /^r#*"/.test(src.slice(i, i + 40)) && !/\w/.test(src[i - 1] ?? '')) {
      const hashes = /^r(#*)"/.exec(src.slice(i))[1];
      const open = i + 2 + hashes.length;
      const end = src.indexOf(`"${hashes}`, open);
      const start = line;
      const close = end === -1 ? src.length : end;
      keep({ line: start, text: src.slice(open, close) });
      advance(close + 1 + hashes.length);
    } else if (c === '"') {
      const start = line;
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
      keep({ line: start, text: src.slice(i + 1, j) });
      advance(j + 1);
    } else if (c === "'") {
      // A char literal ('x', '\n', '"'), or else a lifetime ('a), which has
      // no closing quote and is stepped over like any other character.
      const char = /^'(?:\\(?:u\{[0-9a-fA-F]+\}|.)|[^\\'])'/u.exec(src.slice(i, i + 12));
      advance(i + (char ? char[0].length : 1));
    } else if (src.startsWith('#[cfg(test)]', i)) {
      testPending = /^#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{/.test(
        src.slice(i, i + 80)
      );
      advance(i + 12);
    } else {
      if (c === '{') {
        if (testPending && testDepth === -1) testDepth = depth;
        testPending = false;
        depth++;
      } else if (c === '}') {
        depth--;
        if (depth === testDepth) testDepth = -1;
      }
      advance(i + 1);
    }
  }
  return out;
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

const TEXT = /\.(?:svelte|ts|js|mjs|css|html|json|txt|svg|xml|webmanifest)$/;
const TEST = /\.test\.|test-fixtures\.ts$/;

/** The console files the check reads, relative to the repo root. */
export function consoleFiles(root = repoRoot) {
  const web = join(root, 'web');
  const src = walk(join(web, 'src')).filter(
    (p) => TEXT.test(p) && !TEST.test(p) && !p.includes(`${join('src', 'lib', 'paraglide')}`)
  );
  return [
    ...walk(join(web, 'messages')).filter((p) => p.endsWith('.json')),
    ...src,
    ...walk(join(web, 'static')).filter((p) => TEXT.test(p)),
    join(web, 'worker', 'index.ts')
  ].map((p) => relative(root, p));
}

/** Every unexplained hit, as `file:line: context`. */
export function findHits(root = repoRoot) {
  const patterns = parseAllowlist(readFileSync(join(root, ALLOWLIST_DOC), 'utf8'));
  const hits = [];
  for (const file of consoleFiles(root)) {
    readFileSync(join(root, file), 'utf8')
      .split('\n')
      .forEach((text, n) => {
        for (const context of unexplained(text, patterns))
          hits.push(`${file}:${n + 1}: ${context}`);
      });
  }
  for (const file of RUST_COPY_FILES) {
    for (const { line, text } of rustStrings(readFileSync(join(root, file), 'utf8'))) {
      for (const context of unexplained(text, patterns)) hits.push(`${file}:${line}: ${context}`);
    }
  }
  return hits;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const hits = findHits();
  if (hits.length > 0) {
    console.error(
      `User-visible "otto" not in ${ALLOWLIST_DOC}:\n${hits.map((h) => `  ${h}`).join('\n')}`
    );
    process.exit(1);
  }
  console.log('No user-visible "otto" outside the allow-list.');
}
