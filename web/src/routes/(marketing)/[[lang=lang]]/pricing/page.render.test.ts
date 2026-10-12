// @vitest-environment jsdom
/**
 * The pricing page: a prerendered explanation, and the plans fetched live
 * after mount.
 *
 * `api.plans` is mocked so each state — waiting, loaded, failed, empty — can
 * be held still and looked at. The seeded catalog below is the one the server
 * ships, so "Team shows $29" is a check against what a visitor would really
 * read, not against numbers made up for the test.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/api')>();
  return { ...actual, api: { ...actual.api, plans: vi.fn() } };
});

import { ApiError, api } from '$lib/api';
import { getLocale, overwriteGetLocale } from '$lib/paraglide/runtime';
import { session } from '$lib/session.svelte';
import type { Plan } from '$lib/types';
import Page from './+page.svelte';

const SEEDED: Plan[] = [
  {
    plan: 'free',
    displayName: 'Free',
    includedOps: 500,
    hardStop: true,
    monthlyCents: 0,
    features: {}
  },
  {
    plan: 'team',
    displayName: 'Team',
    includedOps: 10_000,
    hardStop: false,
    monthlyCents: 2900,
    features: { auto_rollback: true }
  },
  {
    plan: 'business',
    displayName: 'Business',
    includedOps: 100_000,
    hardStop: false,
    monthlyCents: 19_900,
    features: { auto_rollback: true }
  },
  {
    plan: 'enterprise',
    displayName: 'Enterprise',
    includedOps: 1_000_000,
    hardStop: false,
    monthlyCents: 0,
    features: { auto_rollback: true }
  }
];

const plans = vi.mocked(api.plans);

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

/** The runtime's own getter, put back after a test speaks another language. */
const defaultGetLocale = getLocale;

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  plans.mockReset();
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

/** The region the live plans render into. */
function region(): HTMLElement {
  return container.querySelector('#plans') as HTMLElement;
}

/** The card whose heading is `name`. */
function card(name: string): HTMLElement {
  const heading = Array.from(container.querySelectorAll('h3')).find(
    (h) => h.textContent?.trim() === name
  );
  expect(heading, `a card headed "${name}"`).toBeDefined();
  return heading!.closest('article') as HTMLElement;
}

/** Let the mocked fetch settle and the page re-render. */
async function settle(): Promise<void> {
  await vi.waitFor(() => expect(region().getAttribute('aria-busy')).toBe('false'));
  flushSync();
}

describe('the pricing page', () => {
  it('shows four placeholder cards while the plans load', () => {
    plans.mockReturnValue(new Promise(() => {}));
    const instance = mountPage();

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(region().getAttribute('aria-busy')).toBe('true');
    const status = region().querySelector('[role="status"]');
    // Announced as text, not only labelled: a live region speaks its content.
    expect(status?.textContent?.trim()).toBe('Loading plans');
    const skeletons = region().querySelectorAll('.otto-card');
    expect(skeletons).toHaveLength(4);
    expect(skeletons[0]?.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(plans).toHaveBeenCalledTimes(1);

    unmount(instance);
  });

  it('renders every seeded plan, with its price, allowance, overage and features', async () => {
    plans.mockResolvedValue({ plans: SEEDED });
    const instance = mountPage();
    await settle();

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expectNoSkips(headingLevels(container));

    const free = card('Free');
    expect(free.textContent).toContain('$0');
    expect(free.textContent).toContain('500 operations included per month');
    expect(free.textContent).toContain('Billable calls stop at the limit');
    expect(free.textContent).not.toContain('Automatic rollback in Otto Flags');
    expect(free.querySelector('a[href="/signup"]')?.textContent?.trim()).toBe('Create account');

    const team = card('Team');
    expect(team.textContent).toContain('$29');
    expect(team.textContent).toContain('10,000 operations included per month');
    expect(team.textContent).toContain('Keeps working past the limit; overage is metered');
    expect(team.textContent).toContain('Automatic rollback in Otto Flags');
    expect(team.querySelector('a[href="/signup"]')).not.toBeNull();

    const business = card('Business');
    expect(business.textContent).toContain('$199');
    expect(business.textContent).toContain('100,000 operations included per month');

    const enterprise = card('Enterprise');
    expect(enterprise.textContent).toContain('Contact us');
    expect(enterprise.textContent).not.toContain('$0');
    expect(enterprise.textContent).toContain('1,000,000 operations included per month');
    expect(enterprise.querySelector('a[href="mailto:sales@savvagent.com"]')).not.toBeNull();
    expect(enterprise.querySelector('a[href="/signup"]')).toBeNull();

    unmount(instance);
  });

  it('sends a signed-in visitor to the console from the self-serve plans', async () => {
    plans.mockResolvedValue({ plans: SEEDED });
    const instance = mountPage();
    await settle();

    session.me = {
      orgs: [
        { orgId: 'o1', userId: 'u1', role: 'owner', orgSlug: 'acme', orgName: 'Acme', plan: 'free' }
      ]
    } as unknown as import('$lib/types').Me;
    flushSync();

    for (const name of ['Free', 'Team', 'Business']) {
      const open = card(name).querySelector('a[href="/o/acme"]');
      expect(open?.textContent?.trim()).toBe('Open console');
      expect(open?.hasAttribute('data-sveltekit-reload')).toBe(true);
    }

    unmount(instance);
  });

  it('offers a retry when the plans cannot be loaded, and renders them once it works', async () => {
    plans.mockRejectedValueOnce(new ApiError(0, 'network', 'offline'));
    plans.mockResolvedValueOnce({ plans: SEEDED });
    const instance = mountPage();
    await settle();

    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain('Pricing could not be loaded.');
    const retry = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Retry'
    );
    expect(retry).toBeDefined();

    retry!.click();
    flushSync();
    await settle();

    expect(plans).toHaveBeenCalledTimes(2);
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(card('Team').textContent).toContain('$29');

    unmount(instance);
  });

  it('points to sales when no plan is listed', async () => {
    plans.mockResolvedValue({ plans: [] });
    const instance = mountPage();
    await settle();

    expect(region().textContent).toContain('No plans are listed right now.');
    expect(region().querySelector('a[href="mailto:sales@savvagent.com"]')).not.toBeNull();
    expect(container.querySelectorAll('article')).toHaveLength(0);

    unmount(instance);
  });

  /**
   * As the landing page's test does: install the URL's locale as Paraglide's
   * getter, then check the words and the numbers both follow it. The price
   * stays in US dollars — only its notation is Spanish.
   */
  it('speaks Spanish, with US dollar prices in Spanish notation', async () => {
    overwriteGetLocale(() => 'es');
    plans.mockResolvedValue({ plans: SEEDED });
    const instance = mountPage('es');
    await settle();

    expect(container.querySelector('#plans-title')?.textContent?.trim()).toBe('Planes');
    const team = card('Team');
    expect(team.textContent).toMatch(/29\sUS\$/);
    expect(team.textContent).not.toContain('€');
    expect(team.textContent).toContain('10.000 operaciones incluidas al mes');
    expect(team.textContent).toContain('Reversión automática en Otto Flags');
    expect(card('Enterprise').textContent).toContain('Contáctanos');
    expect(card('Enterprise').textContent).toContain('1.000.000 de operaciones incluidas al mes');

    unmount(instance);
  });
});
