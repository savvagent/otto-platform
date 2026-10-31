// @vitest-environment jsdom
/**
 * The CLI page: what `savctl` is, a download link per platform, the install and
 * first-use commands as copyable text, and the same page in another language.
 *
 * Commands and URLs are not translated, so the Spanish test checks that the
 * prose follows the URL's locale while the commands stay byte-for-byte the same.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { getLocale, overwriteGetLocale } from '$lib/paraglide/runtime';
import { SERVICES } from '$lib/services';
import { session } from '$lib/session.svelte';
import Page from './+page.svelte';

const LATEST = 'https://github.com/savvagent/otto-platform/releases/latest';
const DOCS = 'https://github.com/savvagent/otto-platform/blob/main/docs/savctl.md';

const ARCHIVES = [
  'savctl-x86_64-unknown-linux-musl.tar.gz',
  'savctl-aarch64-unknown-linux-musl.tar.gz',
  'savctl-aarch64-apple-darwin.tar.gz',
  'savctl-x86_64-apple-darwin.tar.gz',
  'savctl-x86_64-pc-windows-msvc.zip'
];

/** Heading levels in document order, so a skip (h1 → h3) is visible as a jump of two. */
function headingLevels(root: HTMLElement): number[] {
  return Array.from(root.querySelectorAll('h1, h2, h3, h4, h5, h6')).map((h) =>
    Number(h.tagName.slice(1))
  );
}

function expectNoSkips(levels: number[]): void {
  expect(levels[0]).toBe(1);
  levels.reduce((previous, level) => {
    expect(level - previous, `h${previous} → h${level}`).toBeLessThanOrEqual(1);
    return level;
  });
}

const defaultGetLocale = getLocale;

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  session.clear();
  overwriteGetLocale(defaultGetLocale);
});

function mountPage(lang: 'en' | 'es' = 'en') {
  const instance = mount(Page, { target: container, props: { data: { lang } } });
  flushSync();
  return instance;
}

/** The text of every copyable `<code>` block. */
function snippets(): string[] {
  return Array.from(container.querySelectorAll('code')).map((c) => c.textContent ?? '');
}

describe('the CLI page', () => {
  it('has one h1, no skipped heading levels and a section per topic', () => {
    const instance = mountPage();

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(container.querySelector('h1')?.textContent?.trim()).toBe(
      'Sign in once. Keep your secrets out of the chat.'
    );
    expectNoSkips(headingLevels(container));
    const sections = Array.from(container.querySelectorAll('h2')).map((h) => h.textContent?.trim());
    expect(sections).toEqual([
      'Why a command-line tool',
      'Download',
      'Install',
      'The binaries are not code-signed',
      'First use',
      'Read the full documentation'
    ]);

    unmount(instance);
  });

  it('links every platform to its archive at the latest-release address', () => {
    const instance = mountPage();

    const list = container.querySelector('ul[aria-label="Downloads by platform"]');
    const hrefs = Array.from(list?.querySelectorAll('a') ?? []).map((a) => a.getAttribute('href'));
    expect(hrefs).toEqual(ARCHIVES.map((archive) => `${LATEST}/download/${archive}`));
    expect(list?.textContent).toContain('macOS Apple silicon');
    expect(list?.textContent).toContain('Windows x86_64');

    const link = (text: string) =>
      Array.from(container.querySelectorAll('a')).find((a) => a.textContent?.includes(text));
    expect(link('SHA256SUMS')?.getAttribute('href')).toBe(`${LATEST}/download/SHA256SUMS`);
    expect(link('All releases')?.getAttribute('href')).toBe(LATEST);
    expect(link('savctl.md')?.getAttribute('href')).toBe(DOCS);

    unmount(instance);
  });

  it('offers copyable install commands for Linux/macOS, Windows and cargo', () => {
    const instance = mountPage();
    const all = snippets();

    const unix = all.find((s) => s.includes('shasum -a 256 -c'));
    expect(unix).toContain(`base=${LATEST}/download`);
    expect(unix).toContain('curl -fsSLO "$base/savctl-$target.tar.gz"');
    expect(unix).toContain(
      'install -m 0755 "savctl-$target/savctl" "savctl-$target/savctl-flags" ~/.local/bin/'
    );

    const windows = all.find((s) => s.includes('Invoke-WebRequest'));
    expect(windows).toContain(`$base = "${LATEST}/download"`);
    expect(windows).toContain('savctl-x86_64-pc-windows-msvc.zip');
    expect(windows).toContain('Get-FileHash savctl.zip -Algorithm SHA256');

    expect(all).toContain(
      'cargo install --locked --git https://github.com/savvagent/otto-platform ottoctl otto-flags-cli'
    );

    unmount(instance);
  });

  it('says the binaries are unsigned, with the macOS and Windows workarounds', () => {
    const instance = mountPage();

    expect(snippets()).toContain('xattr -d com.apple.quarantine savctl');
    expect(container.textContent).toContain('SmartScreen');
    expect(container.textContent).toContain('Run anyway');

    unmount(instance);
  });

  it('shows the login command, generic and for each service with an MCP address', () => {
    const instance = mountPage();
    const all = snippets();

    expect(all).toContain('savctl login');
    expect(all.some((s) => s.includes('<service MCP URL>'))).toBe(false);
    for (const service of SERVICES) {
      if (service.mcpUrl) expect(all).toContain(`savctl login --resource ${service.mcpUrl}`);
    }

    unmount(instance);
  });

  it('speaks Spanish and leaves the commands alone', () => {
    overwriteGetLocale(() => 'es');
    const english = (() => {
      const instance = mountPage('en');
      const text = snippets();
      unmount(instance);
      container.innerHTML = '';
      return text;
    })();
    const instance = mountPage('es');

    expect(container.querySelector('h1')?.textContent?.trim()).toBe(
      'Inicia sesión una vez. Mantén tus secretos fuera del chat.'
    );
    expect(container.textContent).toContain('Descarga');
    expect(container.textContent).not.toContain('Download');
    expect(snippets()).toEqual(english);

    unmount(instance);
  });
});
