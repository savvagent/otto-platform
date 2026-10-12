import { afterEach, describe, expect, it } from 'vitest';

import { getLocale, locales, overwriteGetLocale } from '$lib/paraglide/runtime';

import { SERVICES, serviceBySlug, servicesIn, type Service } from './services';

/** A candidate with throwaway copy, so a test names only what it is about. */
function candidate(fields: Pick<Service, 'slug' | 'name' | 'url'> & Partial<Service>): Service {
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
  it('ships Otto Factory and Otto Flags, over https', () => {
    expect(SERVICES.map((s) => [s.slug, s.name])).toEqual([
      ['factory', 'Otto Factory'],
      ['flags', 'Otto Flags']
    ]);
    for (const service of SERVICES) {
      expect(service.url.startsWith('https://')).toBe(true);
      expect(service.mcpUrl).toBe(`${service.url}/mcp`);
    }
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

  it('drops anything that is not an https link', () => {
    const good = candidate({ slug: 'good', name: 'Good', url: 'https://good.example' });
    const kept = servicesIn([
      good,
      candidate({ slug: 'plain', name: 'Plain', url: 'http://plain.example' }),
      candidate({ slug: 'script', name: 'Script', url: 'javascript:alert(1)' }),
      candidate({ slug: 'garbage', name: 'Garbage', url: 'not a url' }),
      candidate({ slug: 'nameless', name: '  ', url: 'https://nameless.example' })
    ]);
    expect(kept).toEqual([good]);
  });

  it('drops a slug that cannot be a single path segment', () => {
    const kept = servicesIn(
      ['ok-1', 'Upper', 'has space', '../up', 'a/b', ''].map((slug) =>
        candidate({ slug, name: slug || 'x', url: 'https://x.example' })
      )
    );
    expect(kept.map((s) => s.slug)).toEqual(['ok-1']);
  });

  it('drops an MCP endpoint that is not https, and keeps an absent one', () => {
    const kept = servicesIn([
      candidate({ slug: 'none', name: 'None', url: 'https://a.example' }),
      candidate({
        slug: 'tls',
        name: 'Tls',
        url: 'https://a.example',
        mcpUrl: 'https://a.example/mcp'
      }),
      candidate({
        slug: 'plain',
        name: 'Plain',
        url: 'https://a.example',
        mcpUrl: 'http://a.example/mcp'
      }),
      candidate({ slug: 'junk', name: 'Junk', url: 'https://a.example', mcpUrl: 'nope' })
    ]);
    expect(kept.map((s) => s.slug)).toEqual(['none', 'tls']);
  });
});
