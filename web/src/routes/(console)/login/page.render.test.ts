// @vitest-environment jsdom
/**
 * The regression this file guards: signing in with SSO needs no WebAuthn at
 * all (it's a plain POST + redirect), so its entry point must stay reachable
 * on exactly the browsers where the passkey button is hidden — otherwise a
 * browser with no WebAuthn support has no way to sign in at all, including
 * into an `enforce_sso` org where SSO is the *only* path in. An earlier
 * version of this page nested the whole "sign in with SSO" block inside the
 * `{:else}` of the WebAuthn-`supported` check, so it disappeared exactly
 * when it was needed most.
 */

import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/navigation', () => ({
  goto: vi.fn(() => Promise.resolve())
}));

vi.mock('$app/state', async () => await import('$lib/components/marketing/fake-app-state.svelte'));

const { isSupportedMock } = vi.hoisted(() => ({
  isSupportedMock: vi.fn(() => true)
}));

vi.mock('$lib/webauthn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/webauthn')>();
  return {
    ...actual,
    isSupported: isSupportedMock,
    authenticate: vi.fn(async () => ({ rawId: 'cred-1' })),
    signalAccount: vi.fn(async () => {})
  };
});

vi.mock('$lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      loginStart: vi.fn(async () => ({ ceremonyId: 'c1', challenge: {} })),
      loginFinish: vi.fn(async () => ({})),
      me: vi.fn(async () => ({ orgs: [] })),
      ssoStart: vi.fn(async () => ({ redirectUrl: 'https://idp.test/authorize' }))
    }
  };
});

import { goto } from '$app/navigation';
import { api } from '$lib/api';
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
  isSupportedMock.mockReset();
  isSupportedMock.mockReturnValue(true);
  page.url = new URL('http://localhost/login');
  session.clear();
  vi.unstubAllGlobals();
});

/**
 * `location.assign`, replaced: jsdom cannot navigate, and the page calls it
 * for a server route and for the IdP. `location.href` is kept so URL
 * resolution elsewhere still works.
 */
function stubLocation() {
  const assign = vi.fn();
  vi.stubGlobal('location', { href: window.location.href, assign });
  return assign;
}

/** Mount at `/login?…`, press the passkey button, and wait for the landing. */
async function signInAt(search: string) {
  page.url = new URL(`http://localhost/login${search}`);
  vi.mocked(goto).mockClear();
  const assign = stubLocation();
  const instance = mount(Page, { target: container });
  flushSync();
  const button = Array.from(container.querySelectorAll('button')).find(
    (b) => b.getAttribute('aria-expanded') === null && b.getAttribute('type') !== 'submit'
  ) as HTMLButtonElement;
  button.click();
  await vi.waitFor(() =>
    expect(vi.mocked(goto).mock.calls.length + assign.mock.calls.length).toBe(1)
  );
  unmount(instance);
  return { goto: vi.mocked(goto), assign };
}

/**
 * Where a sign-in lands. `/` is the public marketing page now, so the
 * console's home is `/home`, and an explicit `next=/` (from a link written
 * before that change) means the console too. A server route such as
 * `/oauth/authorize` needs a full navigation, not the client router.
 */
describe('where the login page lands', () => {
  it('lands on /home with no next', async () => {
    const { goto, assign } = await signInAt('');
    expect(goto).toHaveBeenCalledWith('/home', { replaceState: true });
    expect(assign).not.toHaveBeenCalled();
  });

  it('lands on /home for next=/, never on the marketing page', async () => {
    const { goto } = await signInAt('?next=%2F');
    expect(goto).toHaveBeenCalledWith('/home', { replaceState: true });
  });

  it('navigates fully to a server route such as /oauth/authorize', async () => {
    const next = '/oauth/authorize?response_type=code&client_id=c';
    const { goto, assign } = await signInAt(`?next=${encodeURIComponent(next)}`);
    expect(assign).toHaveBeenCalledWith(next);
    expect(goto).not.toHaveBeenCalled();
  });

  it('starts SSO with /home for next=/', async () => {
    page.url = new URL('http://localhost/login?next=%2F');
    const assign = stubLocation();
    vi.mocked(api.ssoStart).mockClear();
    const instance = mount(Page, { target: container });
    flushSync();

    (
      Array.from(container.querySelectorAll('button')).find(
        (b) => b.getAttribute('aria-expanded') !== null
      ) as HTMLButtonElement
    ).click();
    flushSync();
    const email = container.querySelector('input[type="email"]') as HTMLInputElement;
    email.value = 'alice@acme.test';
    email.dispatchEvent(new Event('input', { bubbles: true }));
    (email.closest('form') as HTMLFormElement).requestSubmit();

    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith('https://idp.test/authorize'));
    expect(api.ssoStart).toHaveBeenCalledWith('alice@acme.test', '/home');
    unmount(instance);
  });
});

describe('the login page', () => {
  it('shows the "sign in with SSO" toggle when WebAuthn is unsupported', async () => {
    isSupportedMock.mockReturnValue(false);

    const instance = mount(Page, { target: container });

    // `supported` flips inside an $effect, which runs after the initial
    // mount — wait for the "browser can't do passkeys" alert to actually
    // appear before asserting on what else is (or isn't) present.
    await vi.waitFor(() => {
      expect(container.querySelector('[role="alert"]')).not.toBeNull();
    });
    // SSO must still be reachable — this is the one assertion that would
    // have failed before the fix, since the toggle used to live inside the
    // branch that renders only when WebAuthn *is* supported.
    const buttons = Array.from(container.querySelectorAll('button'));
    expect(buttons.some((b) => b.getAttribute('aria-expanded') !== null)).toBe(true);

    unmount(instance);
  });

  it('still shows the SSO toggle when WebAuthn is supported', async () => {
    isSupportedMock.mockReturnValue(true);

    const instance = mount(Page, { target: container });

    await vi.waitFor(() => {
      const buttons = Array.from(container.querySelectorAll('button'));
      expect(buttons.some((b) => b.getAttribute('aria-expanded') !== null)).toBe(true);
    });

    unmount(instance);
  });

  it('expands the SSO email form on toggle click, regardless of WebAuthn support', async () => {
    isSupportedMock.mockReturnValue(false);

    const instance = mount(Page, { target: container });
    const toggle = Array.from(container.querySelectorAll('button')).find(
      (b) => b.getAttribute('aria-expanded') !== null
    ) as HTMLButtonElement;
    expect(toggle).toBeDefined();
    expect(toggle.getAttribute('aria-expanded')).toBe('false');

    toggle.click();
    await vi.waitFor(() => {
      expect(container.querySelector('input[type="email"]')).not.toBeNull();
    });
    expect(toggle.getAttribute('aria-expanded')).toBe('true');

    unmount(instance);
  });
});
