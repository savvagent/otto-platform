/**
 * Server answers for the org pages' render tests, shaped exactly as
 * `savvagent-web` serializes them, and a `fetch` stand-in that routes by method
 * and path.
 *
 * The usage body carries the legacy bucket fields too, as the server still
 * sends them, so a page that started presenting them again would have
 * something to render and a test could catch it.
 */

import { vi } from 'vitest';

import type { BudgetsResponse, ServiceBudget, UsageStatus } from '$lib/types';

export const FLAGS_BUDGET = {
  monthlyBudgetCents: 10_000,
  hardStop: false,
  percentUsed: 82,
  blocked: false,
  updatedAt: '2026-10-02T10:00:00Z'
};

export const USAGE = {
  plan: 'Free',
  includedOps: 1000,
  billableUsed: 12,
  remaining: 988,
  totalCalls: 40,
  periodStart: '2026-10-01',
  warning: false,
  hardStop: false,
  enforced: false,
  services: [
    {
      service: 'otto-flags',
      meters: [
        {
          meter: 'otto-flags/evaluations',
          displayName: 'Flag evaluations',
          unit: 'evaluation',
          quantity: 1_234_567
        }
      ],
      spendCents: 8_250,
      spendError: null,
      budget: FLAGS_BUDGET,
      paymentRequired: false
    },
    {
      service: 'otto-cxp',
      meters: [
        {
          meter: 'otto-cxp/tickets',
          displayName: 'Tickets',
          unit: 'ticket',
          quantity: 0
        }
      ],
      spendCents: null,
      spendError: 'pricing_unavailable',
      budget: null,
      paymentRequired: false
    }
  ]
} satisfies UsageStatus & Record<string, unknown>;

/**
 * `USAGE` for an org with no live subscription whose Savvagent Flags spend is past
 * its free allowance: the server refuses Flags' billable calls with
 * `payment_required` until a card is on file. CXP's spend is unknown, so it
 * is never flagged.
 */
export const USAGE_PAYMENT_REQUIRED = {
  ...USAGE,
  services: USAGE.services.map((s) =>
    s.service === 'otto-flags' ? { ...s, paymentRequired: true } : s
  )
} satisfies UsageStatus & Record<string, unknown>;

export const FLAGS_ROW: ServiceBudget = {
  service: 'otto-flags',
  spendCents: 8_250,
  spendError: null,
  thresholdsReached: [50, 80],
  budget: FLAGS_BUDGET
};

export const CXP_ROW: ServiceBudget = {
  service: 'otto-cxp',
  spendCents: null,
  spendError: 'pricing_unavailable',
  thresholdsReached: [],
  budget: null
};

export const BUDGETS: BudgetsResponse = {
  periodStart: '2026-10-01',
  services: [FLAGS_ROW, CXP_ROW]
};

export type Route = (body: unknown) => Response | Promise<Response>;

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

export const failure = (status: number, code: string) =>
  json({ error: { code, message: `server says ${code}` } }, status);

/**
 * A `fetch` that answers `"<METHOD> <path>"` from `routes`, and anything else
 * with a `500 unexpected_request`, so a page that asks for something a test
 * did not expect shows an error instead of the state the test asserts.
 */
export function serve(routes: Record<string, Route>) {
  return vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    const route = routes[`${method} ${path}`];
    if (!route) return failure(500, 'unexpected_request');
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    return route(body);
  });
}

/** Every request a `serve` mock received, as `"<METHOD> <path>"`. */
export function requests(mock: ReturnType<typeof serve>): string[] {
  return mock.mock.calls.map(([path, init]) => `${init?.method ?? 'GET'} ${path}`);
}
