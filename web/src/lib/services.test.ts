import { afterEach, describe, expect, it } from 'vitest';

import { m } from '$lib/paraglide/messages';
import { getLocale, locales, overwriteGetLocale } from '$lib/paraglide/runtime';

import {
  SERVICES,
  claudeCodeCommand,
  connectorName,
  serviceBySlug,
  serviceLink,
  servicesIn,
  type Service
} from './services';

/** A candidate with throwaway copy, so a test names only what it is about. */
function candidate(fields: Pick<Service, 'slug' | 'name'> & Partial<Service>): Service {
  return {
    copy: {
      title: () => 'T',
      description: () => 'd',
      tagline: () => 't',
      summary: () => 's',
      features: () => ['f']
    },
    ...fields
  };
}

/** The runtime's own getter, put back after a test overrides it. */
const defaultGetLocale = getLocale;

afterEach(() => overwriteGetLocale(defaultGetLocale));

describe('the services list', () => {
  it('ships Otto Tower, Otto Flags and Otto CXP, over https', () => {
    expect(SERVICES.map((s) => [s.slug, s.name])).toEqual([
      ['tower', 'Otto Tower'],
      ['flags', 'Otto Flags'],
      ['cxp', 'Otto CXP']
    ]);
    for (const service of SERVICES) {
      expect(service.mcpUrl).toBe(`https://otto-${service.slug}.savvagent.com/mcp`);
    }
  });

  /**
   * Only Otto Tower serves a web console. Flags and CXP answer a browser
   * at their origin with a JSON 404, so a `consoleUrl` on either would put a
   * dead end back in the header.
   */
  it('gives a web console to Otto Tower only', () => {
    expect(SERVICES.map((s) => [s.slug, s.consoleUrl])).toEqual([
      ['tower', 'https://otto-tower.savvagent.com'],
      ['flags', undefined],
      ['cxp', undefined]
    ]);
  });

  it('has copy for every entry, read at call time', () => {
    for (const service of SERVICES) {
      expect(service.copy.tagline().length).toBeGreaterThan(0);
      expect(service.copy.summary().length).toBeGreaterThan(0);
      const features = service.copy.features();
      expect(features.length).toBeGreaterThanOrEqual(4);
      expect(features.length).toBeLessThanOrEqual(6);
    }
  });

  /**
   * A meta description longer than this is cut off in a search result, and
   * the cut lands mid-word in whichever language ran long — so every locale
   * is measured, not just English. Counted in code points, as a reader sees
   * them, so Hindi's combining marks are not each charged as a character
   * twice over.
   */
  it('keeps every product description within 160 characters, in every locale', () => {
    for (const locale of locales) {
      overwriteGetLocale(() => locale);
      for (const service of SERVICES) {
        const description = service.copy.description();
        expect(description.length, `${service.slug} (${locale})`).toBeGreaterThan(0);
        expect([...description].length, `${service.slug} (${locale})`).toBeLessThanOrEqual(160);
      }
    }
  });

  it('has a page title with no closing punctuation, in every locale', () => {
    for (const locale of locales) {
      overwriteGetLocale(() => locale);
      for (const service of SERVICES) {
        expect(service.copy.title(), `${service.slug} (${locale})`).toMatch(/[^\s.!?।:;]$/u);
      }
    }
  });

  it('finds a service by its slug, and nothing for a slug no service owns', () => {
    expect(serviceBySlug('flags')?.name).toBe('Otto Flags');
    expect(serviceBySlug('nope')).toBeUndefined();
    expect(serviceBySlug('')).toBeUndefined();
  });

  it('drops a console that is not an https link', () => {
    const good = candidate({ slug: 'good', name: 'Good', consoleUrl: 'https://good.example' });
    const kept = servicesIn([
      good,
      candidate({ slug: 'plain', name: 'Plain', consoleUrl: 'http://plain.example' }),
      candidate({ slug: 'script', name: 'Script', consoleUrl: 'javascript:alert(1)' }),
      candidate({ slug: 'garbage', name: 'Garbage', consoleUrl: 'not a url' }),
      candidate({ slug: 'nameless', name: '  ', consoleUrl: 'https://nameless.example' })
    ]);
    expect(kept).toEqual([good]);
  });

  it('keeps a connector-only service, and drops one with nowhere to send anyone', () => {
    const connector = candidate({ slug: 'conn', name: 'Conn', mcpUrl: 'https://c.example/mcp' });
    const kept = servicesIn([connector, candidate({ slug: 'bare', name: 'Bare' })]);
    expect(kept).toEqual([connector]);
  });

  it('drops a slug that cannot be a single path segment', () => {
    const kept = servicesIn(
      ['ok-1', 'Upper', 'has space', '../up', 'a/b', ''].map((slug) =>
        candidate({ slug, name: slug || 'x', consoleUrl: 'https://x.example' })
      )
    );
    expect(kept.map((s) => s.slug)).toEqual(['ok-1']);
  });

  it('drops an MCP endpoint that is not https, and keeps an absent one', () => {
    const kept = servicesIn([
      candidate({ slug: 'none', name: 'None', consoleUrl: 'https://a.example' }),
      candidate({
        slug: 'tls',
        name: 'Tls',
        consoleUrl: 'https://a.example',
        mcpUrl: 'https://a.example/mcp'
      }),
      candidate({
        slug: 'plain',
        name: 'Plain',
        consoleUrl: 'https://a.example',
        mcpUrl: 'http://a.example/mcp'
      }),
      candidate({ slug: 'junk', name: 'Junk', consoleUrl: 'https://a.example', mcpUrl: 'nope' })
    ]);
    expect(kept.map((s) => s.slug)).toEqual(['none', 'tls']);
  });
});

describe('where a link to a service goes', () => {
  it('leaves for the web console when there is one', () => {
    const tower = serviceBySlug('tower')!;
    expect(serviceLink(tower, 'en')).toEqual({
      kind: 'console',
      href: 'https://otto-tower.savvagent.com'
    });
  });

  it("goes to the product page's connect card, in the given language, when there is not", () => {
    const cxp = serviceBySlug('cxp')!;
    expect(serviceLink(cxp, 'en')).toEqual({ kind: 'connector', href: '/products/cxp#connect' });
    expect(serviceLink(cxp, 'es')).toEqual({
      kind: 'connector',
      href: '/es/products/cxp#connect'
    });
  });

  it('never links to the bare origin of a service with no console', () => {
    for (const service of SERVICES.filter((s) => !s.consoleUrl)) {
      expect(serviceLink(service, 'en').href.startsWith('https://')).toBe(false);
    }
  });
});

describe('the Claude Code command', () => {
  it("names each server after its host, so it matches the service's own docs", () => {
    expect(SERVICES.map(connectorName)).toEqual(['otto-tower', 'otto-flags', 'otto-cxp']);
    for (const service of SERVICES) {
      expect(new URL(service.mcpUrl!).hostname.split('.')[0]).toBe(connectorName(service));
    }
  });

  it('adds the MCP endpoint over HTTP', () => {
    expect(claudeCodeCommand(serviceBySlug('cxp')!)).toBe(
      'claude mcp add --transport http otto-cxp https://otto-cxp.savvagent.com/mcp'
    );
    expect(claudeCodeCommand(candidate({ slug: 'x', name: 'X' }))).toBeUndefined();
  });
});

/**
 * The product page renders "Usage and billing are in your {console}." by
 * splitting the message around a sentinel and putting the link between the
 * halves. A translation that dropped or repeated the placeholder would lose
 * the link or half the sentence without an error, so it is counted here.
 */
describe('the agent-only billing sentence', () => {
  it('has the console link exactly once, in every locale', () => {
    for (const locale of locales) {
      const parts = m.product_agent_only_billing({ console: '\u0000' }, { locale }).split('\u0000');
      expect(parts, locale).toHaveLength(2);
    }
  });
});
