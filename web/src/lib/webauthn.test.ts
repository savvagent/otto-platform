/**
 * The signal helpers, and the one encoding they cannot be allowed to get wrong.
 *
 * `userHandle` is the console half of an encoding pair: `webauthn-rs` puts
 * `uuid.as_bytes()` — sixteen raw bytes, not the thirty-six character text —
 * into the challenge's `user.id`, and every signal method matches on that same
 * handle. Encode the text by mistake and every call is *accepted* by the
 * browser and matches nothing, forever, with no error anywhere. A server-side
 * test pins the wire encoding; these two cases are the other half of it.
 *
 * The rest of the file exists because a signal is fire-and-forget by design:
 * absent interface, absent method, absent rp_id, and a rejected call all have
 * to end the same way — a resolved promise and an untouched flow. Every one of
 * those is a silent no-op if it regresses, so each gets a test rather than a
 * reading.
 *
 * No jsdom: `PublicKeyCredential` is stubbed on `globalThis` and the rp_id
 * arrives through a stubbed `fetch`, which is all these helpers touch.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Me, Passkey } from './types';

const RP_ID = 'passkeys.example';
const USER_ID = '00112233-4455-6677-8899-aabbccddeeff';
const HANDLE = 'ABEiM0RVZneImaq7zN3u_w';

/**
 * A fresh copy of the module.
 *
 * `rpId()` caches its answer for the lifetime of the page on purpose, so a
 * suite that imported once would be testing one fetch and five stale reads.
 */
async function load() {
  vi.resetModules();
  return await import('./webauthn');
}

/** Stub `fetch` with one canned answer and hand back the spy. */
function serving(body: unknown, status = 200) {
  const answer = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' }
      })
  );
  vi.stubGlobal('fetch', answer);
  return answer;
}

/** Stub `PublicKeyCredential` with exactly the methods named. */
function browserWith(methods: Record<string, unknown>) {
  vi.stubGlobal('PublicKeyCredential', methods);
}

function fakeMe(overrides: Partial<Me> = {}): Me {
  return {
    user: {
      id: USER_ID,
      email: 'ada@example.test',
      name: null,
      label: 'brisk-harbor-42',
      locale: null,
      createdAt: '2026-01-01T00:00:00Z',
      disabledAt: null
    },
    orgs: [],
    shouldAddPasskey: false,
    passkeyCount: 1,
    credentialName: 'ada@example.test',
    credentialDisplayName: 'Otto Platform · brisk-harbor-42',
    ...overrides
  };
}

function fakeKey(credentialId: string): Passkey {
  return {
    id: 'd9b4b1b0-0000-4000-8000-000000000000',
    credentialId,
    nickname: null,
    createdAt: '2026-01-01T00:00:00Z',
    lastUsedAt: null
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('userHandle', () => {
  it('encodes the sixteen raw bytes of the UUID, not its text', async () => {
    const { userHandle } = await load();
    // btoa of the text form would start "MDAxMTIy…" and is 48 characters long.
    expect(userHandle(USER_ID)).toBe(HANDLE);
  });

  it('uses the URL-safe alphabet and no padding', async () => {
    const { userHandle } = await load();
    // Bytes chosen so the output needs both substituted characters: standard
    // base64 would put `+` and `/` here, which the server's URL_SAFE_NO_PAD
    // decoder rejects.
    expect(userHandle('fbf0ffbe-fbef-bfbe-fbef-bfbefbefbfbe')).toBe('-_D_vvvvv77777-----_vg');
  });

  it('refuses an id that is not a UUID rather than encoding a plausible wrong one', async () => {
    // `parseInt('zz', 16)` is NaN and Uint8Array writes NaN as 0, so without the
    // guard every one of these returns a well-formed handle of the right length
    // that matches no credential anywhere, silently and forever.
    const { userHandle } = await load();
    for (const bad of ['', 'not-a-uuid', '00112233', 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz']) {
      expect(() => userHandle(bad), `${JSON.stringify(bad)} should be refused`).toThrow(TypeError);
    }
  });
});

describe('signal helpers, with no browser support', () => {
  // Both cases below assert the rp_id was never *fetched*, and that assertion is
  // the whole test. Asserting only that the promise resolves proves nothing
  // here: the `catch` inside each helper swallows the `TypeError` from calling
  // an absent method just as quietly as the guard skips it, so a suite that
  // stopped at `resolves.toBeUndefined()` passes with every guard deleted —
  // verified by deleting them. The guard's observable job is to return *before*
  // `await rpId()`, so a silent fetch is the thing that catches its removal.

  it('resolve without fetching anything when PublicKeyCredential is undefined', async () => {
    const fetched = serving({ rpId: RP_ID });
    vi.stubGlobal('PublicKeyCredential', undefined);
    const w = await load();

    await expect(w.signalAccount(fakeMe())).resolves.toBeUndefined();
    await expect(w.signalAcceptedCredentials(fakeMe(), [])).resolves.toBeUndefined();
    await expect(w.signalUnknownCredential('abc')).resolves.toBeUndefined();
    expect(fetched).not.toHaveBeenCalled();
  });

  it('resolve without fetching anything when the interface has no signal methods', async () => {
    const fetched = serving({ rpId: RP_ID });
    browserWith({});
    const w = await load();

    await expect(w.signalAccount(fakeMe())).resolves.toBeUndefined();
    await expect(w.signalAcceptedCredentials(fakeMe(), [])).resolves.toBeUndefined();
    await expect(w.signalUnknownCredential('abc')).resolves.toBeUndefined();
    expect(fetched).not.toHaveBeenCalled();
  });

  it('detect per method rather than per interface', async () => {
    // A browser that shipped one of the three and not the others is not
    // hypothetical, and the two missing ones must no-op without dragging the
    // present one in.
    serving({ rpId: RP_ID });
    const signalCurrentUserDetails = vi.fn(async () => {});
    browserWith({ signalCurrentUserDetails });
    const w = await load();

    await w.signalAcceptedCredentials(fakeMe(), [fakeKey('abc')]);
    await w.signalUnknownCredential('abc');
    expect(signalCurrentUserDetails).not.toHaveBeenCalled();

    await w.signalAccount(fakeMe());
    expect(signalCurrentUserDetails).toHaveBeenCalledOnce();
  });
});

describe('signalAccount', () => {
  it('forwards the pair from /api/me verbatim, composing nothing', async () => {
    const fetched = serving({ rpId: RP_ID });
    const signalCurrentUserDetails = vi.fn(async () => {});
    browserWith({ signalCurrentUserDetails });
    const w = await load();

    // Sentinels, deliberately unlike anything the console could derive from
    // `email` or `label`: the server composes this pair in one function
    // (`passkeys::credential_names`) and a browser that re-derived it would
    // write words subtly unlike what registering again writes.
    await w.signalAccount(
      fakeMe({
        credentialName: 'name-as-the-server-composed-it',
        credentialDisplayName: 'display-name-as-the-server-composed-it'
      })
    );

    expect(fetched).toHaveBeenCalledWith('/api/auth/webauthn', expect.anything());
    expect(signalCurrentUserDetails).toHaveBeenCalledWith({
      rpId: RP_ID,
      userId: HANDLE,
      name: 'name-as-the-server-composed-it',
      displayName: 'display-name-as-the-server-composed-it'
    });
  });
});

describe('signalAcceptedCredentials', () => {
  it('forwards each credentialId un-re-encoded', async () => {
    serving({ rpId: RP_ID });
    const signalAllAcceptedCredentials = vi.fn(async () => {});
    browserWith({ signalAllAcceptedCredentials });
    const w = await load();

    // The server already hands these over base64url-unpadded, "so the console
    // can compare without re-encoding". Anything applied here is a second
    // encoding of an already-encoded string, and it would match nothing.
    const ids = ['ABEiM0RVZneImaq7zN3u_w', '-_D_vvvvv77777-----_vg'];
    await w.signalAcceptedCredentials(fakeMe(), ids.map(fakeKey));

    expect(signalAllAcceptedCredentials).toHaveBeenCalledWith({
      rpId: RP_ID,
      userId: HANDLE,
      allAcceptedCredentialIds: ids
    });
  });

  it('sends an empty list rather than skipping the call', async () => {
    // Legal, and the right thing to say after an admin reset: this account has
    // no accepted credentials.
    serving({ rpId: RP_ID });
    const signalAllAcceptedCredentials = vi.fn(async () => {});
    browserWith({ signalAllAcceptedCredentials });
    const w = await load();

    await w.signalAcceptedCredentials(fakeMe(), []);

    expect(signalAllAcceptedCredentials).toHaveBeenCalledWith({
      rpId: RP_ID,
      userId: HANDLE,
      allAcceptedCredentialIds: []
    });
  });
});

describe('signalUnknownCredential', () => {
  it('names the rp and the credential the browser just offered', async () => {
    serving({ rpId: RP_ID });
    const signalUnknownCredential = vi.fn(async () => {});
    browserWith({ signalUnknownCredential });
    const w = await load();

    await w.signalUnknownCredential('ABEiM0RVZneImaq7zN3u_w');

    expect(signalUnknownCredential).toHaveBeenCalledWith({
      rpId: RP_ID,
      credentialId: 'ABEiM0RVZneImaq7zN3u_w'
    });
  });
});

describe('failures never reach the caller', () => {
  it('resolves when the underlying method rejects', async () => {
    serving({ rpId: RP_ID });
    const refuse = vi.fn(async () => {
      throw new Error('the password manager refused the hint');
    });
    browserWith({
      signalCurrentUserDetails: refuse,
      signalAllAcceptedCredentials: refuse,
      signalUnknownCredential: refuse
    });
    const w = await load();

    await expect(w.signalAccount(fakeMe())).resolves.toBeUndefined();
    await expect(w.signalAcceptedCredentials(fakeMe(), [])).resolves.toBeUndefined();
    await expect(w.signalUnknownCredential('abc')).resolves.toBeUndefined();
    expect(refuse).toHaveBeenCalledTimes(3);
  });

  it('does nothing at all when the rp_id could not be fetched', async () => {
    // Not `location.hostname`: an rp_id may be a registrable parent of the
    // origin, so a guess is accepted, matches nothing, and looks like it
    // worked.
    serving({ error: { code: 'internal', message: 'no' } }, 500);
    const called = vi.fn(async () => {});
    browserWith({
      signalCurrentUserDetails: called,
      signalAllAcceptedCredentials: called,
      signalUnknownCredential: called
    });
    const w = await load();

    await expect(w.signalAccount(fakeMe())).resolves.toBeUndefined();
    await expect(w.signalAcceptedCredentials(fakeMe(), [])).resolves.toBeUndefined();
    await expect(w.signalUnknownCredential('abc')).resolves.toBeUndefined();
    expect(called).not.toHaveBeenCalled();
  });
});

describe('the rp_id', () => {
  it('is fetched once for the lifetime of the page', async () => {
    const fetched = serving({ rpId: RP_ID });
    browserWith({
      signalCurrentUserDetails: vi.fn(async () => {}),
      signalAllAcceptedCredentials: vi.fn(async () => {}),
      signalUnknownCredential: vi.fn(async () => {})
    });
    const w = await load();

    await w.signalAccount(fakeMe());
    await w.signalAcceptedCredentials(fakeMe(), []);
    await w.signalUnknownCredential('abc');

    expect(fetched).toHaveBeenCalledOnce();
  });

  it('is retried after a failure rather than giving up for the session', async () => {
    // The value is cached; the rejection is not. This module lives as long as
    // the tab does — adapter-static means a navigation is not a reload — so
    // caching the failure would let one 502 during a rolling deploy disable
    // every signal until a hard refresh, including a passkey deletion later in
    // the session, which is exactly when a stale credential gets stranded.
    const signalCurrentUserDetails = vi.fn(async () => {});
    browserWith({ signalCurrentUserDetails });
    const fetched = vi
      .fn()
      .mockRejectedValueOnce(new Error('gateway'))
      .mockResolvedValue(
        new Response(JSON.stringify({ rpId: RP_ID }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
      );
    vi.stubGlobal('fetch', fetched);
    const w = await load();

    await w.signalAccount(fakeMe());
    expect(signalCurrentUserDetails).not.toHaveBeenCalled();

    await w.signalAccount(fakeMe());
    expect(fetched).toHaveBeenCalledTimes(2);
    expect(signalCurrentUserDetails).toHaveBeenCalledOnce();
  });
});
