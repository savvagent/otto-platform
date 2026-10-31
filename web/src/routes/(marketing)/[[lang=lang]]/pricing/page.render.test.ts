// @vitest-environment jsdom
/**
 * The pricing page: a prerendered explanation, and the plans fetched live
 * after mount.
 *
 * `api.plans` is mocked so each state — waiting, loaded, failed, empty — can
 * be held still and looked at. The seeded plans below are the ones the server
 * ships, so "Team shows $29" is a check against what a visitor would really
 * read, not against numbers made up for the test.
 *
 * No usage price is set in production yet, so `meters` is empty in the
 * seeded answer; the priced meters below are the server's own serialization
 * test's, plus a second tier table, to exercise the graduated rendering.
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
import type { Me, Plan, PlansResponse, PricedMeter } from '$lib/types';
import Page from './+page.svelte';

const SEEDED: Plan[] = [
  {
    plan: 'free',
    displayName: 'Free',
    monthlyCents: 0,
    features: {}
  },
  {
    plan: 'team',
    displayName: 'Team',
    monthlyCents: 2900,
    features: { auto_rollback: true }
  },
  {
    plan: 'business',
    displayName: 'Business',
    monthlyCents: 19_900,
    features: { auto_rollback: true }
  },
  {
    plan: 'enterprise',
    displayName: 'Enterprise',
    monthlyCents: 0,
    features: { auto_rollback: true }
  }
];

const SEEDED_CATALOG: PlansResponse = { plans: SEEDED, meters: [] };

const FLAG_EVALUATIONS: PricedMeter = {
  service: 'otto-flags',
  meter: 'evaluations',
  displayName: 'Flag evaluations',
  unit: 'evaluation',
  tiers: [
    { upTo: 1000, unitAmountUcents: 0 },
    { upTo: null, unitAmountUcents: 7 }
  ]
};

const TOWER_JOBS: PricedMeter = {
  service: 'otto-tower',
  meter: 'jobs',
  displayName: 'Jobs completed',
  unit: 'job',
  tiers: [
    { upTo: 10_000, unitAmountUcents: 200_000 },
    { upTo: 1_000_000, unitAmountUcents: 150_000 },
    { upTo: null, unitAmountUcents: 100_000 }
  ]
};

const PRICED: PlansResponse = { plans: SEEDED, meters: [TOWER_JOBS, FLAG_EVALUATIONS] };

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

/** The region the live usage prices render into. */
function usageRegion(): HTMLElement {
  return container.querySelector('#usage') as HTMLElement;
}

/** The meter table captioned `name`, as rows of [units, price] text. */
function meterRows(name: string): string[][] {
  const table = Array.from(container.querySelectorAll('table')).find((t) =>
    t.caption?.textContent?.includes(name)
  );
  expect(table, `a table captioned "${name}"`).toBeDefined();
  return Array.from(table!.tBodies[0]!.rows).map((row) =>
    Array.from(row.cells).map((cell) => cell.textContent?.trim() ?? '')
  );
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
    const skeletons = region().querySelectorAll('.sav-card');
    expect(skeletons).toHaveLength(4);
    expect(skeletons[0]?.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(plans).toHaveBeenCalledTimes(1);

    unmount(instance);
  });

  it('renders every seeded plan, with its price and features, and no allowance', async () => {
    plans.mockResolvedValue(SEEDED_CATALOG);
    const instance = mountPage();
    await settle();

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expectNoSkips(headingLevels(container));

    expect(status().textContent?.trim()).toBe('Plans loaded');

    const free = card('Free');
    // The price slot says the word; there is no "$0 per month".
    expect(free.querySelector('p')?.textContent?.trim()).toBe('Free');
    expect(free.textContent).not.toContain('$0');
    expect(free.textContent).toContain('Usage is billed separately, per service');
    expect(free.textContent).not.toContain('Automatic rollback in Savvagent Flags');
    expect(free.querySelector('a[href="/signup"]')?.textContent?.trim()).toBe('Create account');

    const team = card('Team');
    expect(team.textContent).toContain('$29');
    expect(team.textContent).toContain('Usage is billed separately, per service');
    expect(team.textContent).toContain('Automatic rollback in Savvagent Flags');
    expect(team.querySelector('a[href="/signup"]')).not.toBeNull();

    const business = card('Business');
    expect(business.textContent).toContain('$199');

    const enterprise = card('Enterprise');
    expect(enterprise.textContent).toContain('Contact us');
    expect(enterprise.textContent).not.toContain('$0');
    expect(enterprise.querySelector(MAILTO)).not.toBeNull();
    expect(enterprise.querySelector('a[href="/signup"]')).toBeNull();

    // Plans buy features: no card speaks of operations, allowances or limits.
    expect(region().textContent).not.toMatch(/operation|allowance|limit/i);

    unmount(instance);
  });

  /**
   * Production today: no meter has a price. The usage section must say that
   * plainly, once, rather than list every service as "free" or show nothing.
   */
  it('says usage prices are still to come when no meter is priced', async () => {
    plans.mockResolvedValue(SEEDED_CATALOG);
    const instance = mountPage();
    await settle();

    expect(usageRegion().getAttribute('aria-busy')).toBe('false');
    expect(usageRegion().textContent?.trim()).toBe(
      'Usage prices have not been published yet. They will appear here, service by service, as soon as they are set.'
    );
    expect(usageRegion().querySelectorAll('table')).toHaveLength(0);
    expect(usageRegion().textContent).not.toContain('$');

    unmount(instance);
  });

  it('renders a graduated tier table per priced meter, grouped by service', async () => {
    plans.mockResolvedValue(PRICED);
    const instance = mountPage();
    await settle();

    expectNoSkips(headingLevels(container));
    const services = Array.from(usageRegion().querySelectorAll('h3')).map((h) =>
      h.textContent?.trim()
    );
    expect(services).toEqual(['Savvagent Tower', 'Savvagent Flags', 'Savvagent CXP']);

    // Exact prices from millionths of a cent; the first unit of each tier is
    // the one after the tier before.
    expect(meterRows('Jobs completed')).toEqual([
      ['Up to 10,000', '$0.002'],
      ['10,001 to 1,000,000', '$0.0015'],
      ['1,000,001 and above', '$0.001']
    ]);
    expect(meterRows('Flag evaluations')).toEqual([
      ['Up to 1,000', 'Free'],
      ['1,001 and above', '$0.00000007']
    ]);

    const flags = card('Savvagent Flags');
    expect(flags.textContent).toContain('Billed per evaluation');
    expect(flags.textContent).toContain('First 1,000 units free every month');
    // No free first tier, so no "free" claim.
    expect(card('Savvagent Tower').textContent).not.toContain('free every month');
    // A service with nothing priced says so, rather than vanishing or reading as free.
    expect(card('Savvagent CXP').textContent).toContain('No usage price published yet.');
    expect(card('Savvagent CXP').querySelector('table')).toBeNull();

    const headers = Array.from(usageRegion().querySelectorAll('th[scope="col"]')).map((th) =>
      th.textContent?.trim()
    );
    expect(headers.slice(0, 2)).toEqual(['Units each month', 'Price per unit']);

    unmount(instance);
  });

  it('shows placeholders for the usage prices while they load', () => {
    plans.mockReturnValue(new Promise(() => {}));
    const instance = mountPage();

    expect(usageRegion().getAttribute('aria-busy')).toBe('true');
    expect(usageRegion().querySelector('[aria-hidden="true"]')).not.toBeNull();

    unmount(instance);
  });

  it('sends a signed-in visitor to the console from the self-serve plans', async () => {
    plans.mockResolvedValue(SEEDED_CATALOG);
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
    plans.mockResolvedValueOnce(PRICED);
    const instance = mountPage();
    await settle();

    // Reported once, beside its Retry; the usage region does not repeat it.
    expect(container.querySelectorAll('[role="alert"]')).toHaveLength(1);
    expect(usageRegion().textContent?.trim()).toBe('');

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
    expect(meterRows('Flag evaluations')).toHaveLength(2);
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
    // The error object itself, not only its message, so its stack survives.
    const logged = consoleError.mock.calls[0]?.[1];
    expect(logged).toBeInstanceOf(Error);
    expect((logged as Error).message).toContain('plans array');

    unmount(instance);
  });

  it('treats a plan with a missing field as a failure, never $NaN', async () => {
    const { monthlyCents: _dropped, ...withoutPrice } = SEEDED[1]!;
    plans.mockResolvedValue({ plans: [SEEDED[0]!, withoutPrice as Plan], meters: [] });
    const instance = mountPage();
    await settle();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Pricing could not be loaded.'
    );
    expect(container.querySelectorAll('article')).toHaveLength(0);
    expect(container.textContent).not.toContain('NaN');
    expect(consoleError).toHaveBeenCalledTimes(1);
    expect((consoleError.mock.calls[0]?.[1] as Error).message).toContain('plans[1].monthlyCents');

    unmount(instance);
  });

  it('still shows the plans when the answer has no meters array, and logs it', async () => {
    plans.mockResolvedValue({ plans: SEEDED } as never);
    const instance = mountPage();
    await settle();

    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(card('Team').textContent).toContain('$29');
    expect(usageRegion().textContent).toContain('Usage prices have not been published yet.');
    expect(consoleError).toHaveBeenCalledOnce();
    expect((consoleError.mock.calls[0]?.[1] as Error).message).toContain('meters array');

    unmount(instance);
  });

  it('drops only a meter with a broken tier table, never showing a wrong price', async () => {
    plans.mockResolvedValue({
      plans: SEEDED,
      meters: [TOWER_JOBS, { ...FLAG_EVALUATIONS, tiers: [{ upTo: null, unitAmountUcents: 1.5 }] }]
    });
    const instance = mountPage();
    await settle();

    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(card('Team').textContent).toContain('$29');
    expect(usageRegion().querySelectorAll('table')).toHaveLength(1);
    expect(meterRows('Jobs completed')).toHaveLength(3);
    expect(card('Savvagent Flags').textContent).toContain('No usage price published yet.');
    expect(consoleError).toHaveBeenCalledOnce();
    expect((consoleError.mock.calls[0]?.[1] as Error).message).toContain(
      'meters[1].tiers[0].unitAmountUcents'
    );

    unmount(instance);
  });

  it('shows one table for a meter the answer lists twice', async () => {
    plans.mockResolvedValue({
      plans: SEEDED,
      meters: [FLAG_EVALUATIONS, { ...FLAG_EVALUATIONS, displayName: 'Flag evaluations (copy)' }]
    });
    const instance = mountPage();
    await settle();

    expect(card('Savvagent Flags').querySelectorAll('table')).toHaveLength(1);
    expect(card('Savvagent Flags').textContent).not.toContain('(copy)');
    expect(consoleError).toHaveBeenCalledOnce();

    unmount(instance);
  });

  it('wraps each tier table so a narrow screen scrolls it, not the page', async () => {
    plans.mockResolvedValue(PRICED);
    const instance = mountPage();
    await settle();

    for (const table of usageRegion().querySelectorAll('table')) {
      expect(table.parentElement?.classList.contains('overflow-x-auto')).toBe(true);
    }

    unmount(instance);
  });

  it('renders a plan whose features are null, with no feature lines', async () => {
    plans.mockResolvedValue({ plans: [{ ...SEEDED[1]!, features: null as never }], meters: [] });
    const instance = mountPage();
    await settle();

    const team = card('Team');
    expect(team.textContent).toContain('$29');
    expect(team.textContent).not.toContain('Automatic rollback in Savvagent Flags');
    expect(consoleError).not.toHaveBeenCalled();

    unmount(instance);
  });

  /**
   * The sequence token's other half: a page torn down mid-request. (Two
   * requests cannot overlap through the UI today — Retry exists only once the
   * first has failed — so the token guards a future caller, and this checks
   * the path that is reachable.)
   */
  it('ignores an answer that arrives after the page is gone', async () => {
    let answer!: (value: PlansResponse) => void;
    plans.mockReturnValueOnce(new Promise((resolve) => (answer = resolve)));
    const instance = mountPage();
    unmount(instance);

    answer(SEEDED_CATALOG);
    await vi.waitFor(() => expect(plans).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(container.innerHTML).toBe('');
    expect(consoleError).not.toHaveBeenCalled();
  });

  it('points to sales when no plan is listed, and warns', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    plans.mockResolvedValue({ plans: [], meters: [] });
    const instance = mountPage();
    await settle();

    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).toContain('no plans');
    expect(consoleError).not.toHaveBeenCalled();
    warn.mockRestore();

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
    plans.mockResolvedValue(PRICED);
    const instance = mountPage('es');
    await settle();

    expect(container.querySelector('#plans-title')?.textContent?.trim()).toBe('Planes');
    const team = card('Team');
    expect(team.textContent).toMatch(/29\sUS\$/);
    expect(team.textContent).not.toContain('€');
    expect(team.textContent).toContain('El uso se factura aparte, por servicio');
    expect(team.textContent).toContain('Reversión automática en Savvagent Flags');
    expect(card('Enterprise').textContent).toContain('Contáctanos');

    expect(meterRows('Jobs completed')).toEqual([
      ['Hasta 10.000', expect.stringMatching(/^0,002\sUS\$$/)],
      ['De 10.001 a 1.000.000', expect.stringMatching(/^0,0015\sUS\$$/)],
      ['1.000.001 en adelante', expect.stringMatching(/^0,001\sUS\$$/)]
    ]);
    expect(meterRows('Flag evaluations')[0]).toEqual(['Hasta 1000', 'Gratis']);
    expect(card('Savvagent Flags').textContent).toContain(
      'Las primeras 1000 unidades gratis cada mes'
    );
    expect(usageRegion().textContent).not.toContain('€');
    expect(card('Free').querySelector('p')?.textContent?.trim()).toBe('Gratis');

    unmount(instance);
  });
});
