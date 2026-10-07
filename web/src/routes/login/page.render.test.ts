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

import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/navigation', () => ({
  goto: vi.fn(() => Promise.resolve())
}));

const { isSupportedMock } = vi.hoisted(() => ({
  isSupportedMock: vi.fn(() => true)
}));

vi.mock('$lib/webauthn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/webauthn')>();
  return { ...actual, isSupported: isSupportedMock };
});

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
