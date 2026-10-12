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
import { CONTACT_EMAIL } from '$lib/site';
import type { Me, Plan } from '$lib/types';
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
let consoleError: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  plans.mockReset();
  // The page logs every failed load; a test that expects one asserts on it.
  consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  consoleError.mockRestore();
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

/** The page's one live region. */
function status(): HTMLElement {
  const found = container.querySelectorAll('[role="status"]');
  expect(found).toHaveLength(1);
  return found[0] as HTMLElement;
}

const MAILTO = `a[href="mailto:${CONTACT_EMAIL}"]`;

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
    // Announced as text, not only labelled: a live region speaks its content.
    // It sits outside the busy region, which would otherwise mute it.
    expect(status().textContent?.trim()).toBe('Loading plans');
    expect(status().closest('[aria-busy]')).toBeNull();
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

    expect(status().textContent?.trim()).toBe('Plans loaded');

    const free = card('Free');
    // The price slot says the word; there is no "$0 per month".
    expect(free.querySelector('p')?.textContent?.trim()).toBe('Free');
    expect(free.textContent).not.toContain('$0');
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
    // A floor, since a contract can include more.
    expect(enterprise.textContent).toContain('From 1,000,000 operations per month');
    expect(enterprise.querySelector(MAILTO)).not.toBeNull();
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
    } as unknown as Me;
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
    // The button is gone; focus went to what replaced it, not to <body>.
    await vi.waitFor(() => expect(document.activeElement).toBe(region()));
    expect(consoleError).toHaveBeenCalledTimes(1);

    unmount(instance);
  });

  it('keeps focus on the plans region when a retry fails again', async () => {
    plans.mockRejectedValue(new ApiError(503, 'unavailable', 'down'));
    const instance = mountPage();
    await settle();

    (
      Array.from(container.querySelectorAll('button')).find(
        (b) => b.textContent?.trim() === 'Retry'
      ) as HTMLButtonElement
    ).click();
    flushSync();
    await settle();

    expect(plans).toHaveBeenCalledTimes(2);
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    await vi.waitFor(() => expect(document.activeElement).toBe(region()));

    unmount(instance);
  });

  it('treats a 200 with no plans array as a failure, not a crash', async () => {
    plans.mockResolvedValue({ unexpected: true } as never);
    const instance = mountPage();
    await settle();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Pricing could not be loaded.'
    );
    expect(container.querySelectorAll('article')).toHaveLength(0);
    expect(consoleError).toHaveBeenCalledTimes(1);
    expect(String(consoleError.mock.calls[0]?.[0])).toContain('plans array');

    unmount(instance);
  });

  /**
   * The sequence token's other half: a page torn down mid-request. (Two
   * requests cannot overlap through the UI today — Retry exists only once the
   * first has failed — so the token guards a future caller, and this checks
   * the path that is reachable.)
   */
  it('ignores an answer that arrives after the page is gone', async () => {
    let answer!: (value: { plans: Plan[] }) => void;
    plans.mockReturnValueOnce(new Promise((resolve) => (answer = resolve)));
    const instance = mountPage();
    unmount(instance);

    answer({ plans: SEEDED });
    await vi.waitFor(() => expect(plans).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(container.innerHTML).toBe('');
    expect(consoleError).not.toHaveBeenCalled();
  });

  it('points to sales when no plan is listed', async () => {
    plans.mockResolvedValue({ plans: [] });
    const instance = mountPage();
    await settle();

    expect(region().textContent).toContain('No plans are listed right now.');
    expect(region().querySelector(MAILTO)).not.toBeNull();
    // Nothing to announce as loaded; the visible message says it.
    expect(status().textContent?.trim()).toBe('');
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
    expect(card('Enterprise').textContent).toContain('Desde 1.000.000 de operaciones al mes');
    expect(card('Free').querySelector('p')?.textContent?.trim()).toBe('Gratis');

    unmount(instance);
  });
});
