// @vitest-environment jsdom
/**
 * Where a new account lands once its profile is saved. `/` is the public
 * marketing page now, so the console's home is `/home`, and an explicit
 * `next=/` (from a link written before that change) means the console too.
 * An account created mid-OAuth-flow goes back to `/oauth/authorize` with a
 * full navigation, which the client router cannot do.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/navigation', () => ({
  goto: vi.fn(() => Promise.resolve())
}));

vi.mock('$app/state', async () => await import('$lib/components/marketing/fake-app-state.svelte'));

vi.mock('$lib/webauthn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/webauthn')>();
  return {
    ...actual,
    isSupported: vi.fn(() => true),
    hasPlatformAuthenticator: vi.fn(async () => true),
    register: vi.fn(async () => ({ rawId: 'cred-1' })),
    signalAccount: vi.fn(async () => {})
  };
});

vi.mock('$lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      signupStart: vi.fn(async () => ({ ceremonyId: 'c1', challenge: {} })),
      signupFinish: vi.fn(async () => ({})),
      setProfile: vi.fn(async () => ({})),
      me: vi.fn(async () => ({ orgs: [] }))
    }
  };
});

import { goto } from '$app/navigation';
import { page } from '$lib/components/marketing/fake-app-state.svelte';
import { session } from '$lib/session.svelte';
import Page from './+page.svelte';

let container: HTMLElement;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  page.url = new URL('http://localhost/');
  session.clear();
  vi.unstubAllGlobals();
});

/** Mount at `/signup?…`, create the passkey, save the profile, and wait for the landing. */
async function signUpAt(search: string) {
  page.url = new URL(`http://localhost/signup${search}`);
  vi.mocked(goto).mockClear();
  // jsdom cannot navigate; the page calls `location.assign` for a server route.
  const assign = vi.fn();
  vi.stubGlobal('location', { href: window.location.href, assign });

  const instance = mount(Page, { target: container });
  flushSync();
  (container.querySelector('button') as HTMLButtonElement).click();

  await vi.waitFor(() => expect(container.querySelector('form')).not.toBeNull());
  const email = container.querySelector('input[type="email"]') as HTMLInputElement;
  email.value = 'alice@acme.test';
  email.dispatchEvent(new Event('input', { bubbles: true }));
  (container.querySelector('form') as HTMLFormElement).requestSubmit();

  await vi.waitFor(() =>
    expect(vi.mocked(goto).mock.calls.length + assign.mock.calls.length).toBe(1)
  );
  unmount(instance);
  return { goto: vi.mocked(goto), assign };
}

describe('where the signup page lands', () => {
  it('lands on /home with no next', async () => {
    const { goto, assign } = await signUpAt('');
    expect(goto).toHaveBeenCalledWith('/home', { replaceState: true });
    expect(assign).not.toHaveBeenCalled();
  });

  it('lands on /home for next=/, never on the marketing page', async () => {
    const { goto } = await signUpAt('?next=%2F');
    expect(goto).toHaveBeenCalledWith('/home', { replaceState: true });
  });

  it('navigates fully to a server route such as /oauth/authorize', async () => {
    const next = '/oauth/authorize?response_type=code&client_id=c';
    const { goto, assign } = await signUpAt(`?next=${encodeURIComponent(next)}`);
    expect(assign).toHaveBeenCalledWith(next);
    expect(goto).not.toHaveBeenCalled();
  });
});
