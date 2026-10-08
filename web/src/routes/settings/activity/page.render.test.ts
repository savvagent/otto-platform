// @vitest-environment jsdom
/**
 * The account's security activity, asserted where a user would see it: the
 * page reads the caller's own trail (`/api/me/audit`, never an org's), shows
 * each row's address, and says what it deliberately does not list — so a
 * short list is not mistaken for "nothing ever tried".
 */

import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import Page from './+page.svelte';

const events = [
  {
    id: 2,
    orgId: null,
    actorUserId: 'u1',
    actorLabel: null,
    action: 'auth.login.succeeded',
    targetType: null,
    targetId: null,
    ip: '203.0.113.7',
    userAgent: null,
    detail: { method: 'passkey' },
    createdAt: '2026-10-01T12:00:00Z'
  },
  {
    id: 1,
    orgId: null,
    actorUserId: 'u1',
    actorLabel: null,
    action: 'auth.passkey.registered',
    targetType: null,
    targetId: null,
    ip: null,
    userAgent: null,
    detail: { via: 'signup' },
    createdAt: '2026-09-30T12:00:00Z'
  }
];

let container: HTMLElement;

function serve(body: unknown) {
  return vi.fn(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
    )
  );
}

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  vi.unstubAllGlobals();
});

describe('the security activity page', () => {
  it("reads the caller's own trail and shows each row", async () => {
    const fetchMock = serve(events);
    vi.stubGlobal('fetch', fetchMock);
    const instance = mount(Page, { target: container });

    await vi.waitFor(() => {
      expect(container.querySelectorAll('tbody tr')).toHaveLength(2);
    });

    const paths = fetchMock.mock.calls.map((call: unknown[]) => call[0]);
    expect(paths).toEqual(['/api/me/audit?limit=200']);

    const text = container.textContent ?? '';
    expect(text).toContain('auth.login.succeeded');
    expect(text).toContain('auth.passkey.registered');
    expect(text).toContain('203.0.113.7');
    expect(text).toContain('cannot be attributed to anyone');

    unmount(instance);
  });

  it('says so when nothing is recorded', async () => {
    vi.stubGlobal('fetch', serve([]));
    const instance = mount(Page, { target: container });

    await vi.waitFor(() => {
      expect(container.textContent).toContain('Nothing recorded yet.');
    });
    expect(container.querySelector('table')).toBeNull();

    unmount(instance);
  });
});
