/**
 * The browser half of a WebAuthn ceremony.
 *
 * `navigator.credentials` speaks `ArrayBuffer`; JSON does not. Everything here
 * exists to cross that boundary in both directions, and to do it in exactly the
 * shape the server's `webauthn-rs` types deserialize from — `rawId`,
 * `clientDataJSON`, `attestationObject`, `authenticatorData`, `userHandle`,
 * `type`, all base64url with no padding.
 *
 * **Written out by hand rather than using `PublicKeyCredential.toJSON()`.**
 * That method produces very nearly this shape and is not available everywhere
 * yet; the failure when it is missing, or when a field is named slightly
 * differently, is a server-side "invalid credentials" that looks like a broken
 * authenticator rather than a broken serializer. Thirty lines of explicit
 * conversion is worth not debugging that.
 */

import { api } from './api';
import type { Me, Passkey } from './types';

/** base64url → bytes. Tolerates padding and the standard alphabet. */
function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** bytes → base64url, unpadded, which is what the server's decoder expects. */
function toBase64Url(buffer: ArrayBufferLike): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Whether this browser can do WebAuthn at all. */
export function isSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator?.credentials?.create === 'function'
  );
}

/**
 * Whether this device can *store* a passkey itself — a fingerprint reader, Face
 * ID, Windows Hello.
 *
 * Used only to word the prompt. A false here does not mean the user cannot
 * register: a security key or a phone over Bluetooth works fine, and telling
 * someone they cannot sign up because their laptop has no sensor would be
 * wrong.
 */
export async function hasPlatformAuthenticator(): Promise<boolean> {
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/** The server's challenge, as JSON, before the buffers are decoded. */
type CreationChallenge = {
  publicKey: {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    excludeCredentials?: { id: string; type: string; transports?: string[] }[];
    [k: string]: unknown;
  };
};

type RequestChallenge = {
  publicKey: {
    challenge: string;
    allowCredentials?: { id: string; type: string; transports?: string[] }[];
    [k: string]: unknown;
  };
  mediation?: string | null;
};

/**
 * Run a registration ceremony and return what the server needs back.
 *
 * Throws `WebauthnError` with a message written for a person: the browser's own
 * exceptions say things like "The operation either timed out or was not
 * allowed", which is what a user sees when they simply changed their mind.
 */
export async function register(challenge: CreationChallenge): Promise<unknown> {
  const publicKey = {
    ...challenge.publicKey,
    challenge: fromBase64Url(challenge.publicKey.challenge),
    user: {
      ...challenge.publicKey.user,
      id: fromBase64Url(challenge.publicKey.user.id)
    },
    excludeCredentials: (challenge.publicKey.excludeCredentials ?? []).map((c) => ({
      ...c,
      id: fromBase64Url(c.id)
    }))
  } as unknown as PublicKeyCredentialCreationOptions;

  const credential = (await navigator.credentials
    .create({ publicKey })
    .catch(rethrow)) as PublicKeyCredential | null;

  if (!credential) throw new WebauthnError('no_passkey_created', 'No passkey was created.');
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64Url(response.attestationObject),
      clientDataJSON: toBase64Url(response.clientDataJSON),
      // Present on most browsers, and worth sending: it is how the server can
      // later tell a phone from a security key in the list of keys.
      transports:
        typeof response.getTransports === 'function' ? response.getTransports() : undefined
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

/**
 * Run an authentication ceremony.
 *
 * `allowCredentials` arrives empty and stays empty: the point of a discoverable
 * credential is that the browser resolves who is signing in, so nothing here
 * tells it which account to look for. The server's `mediation` field is ignored
 * — it asks for the autofill flow, and this is a button.
 */
export async function authenticate(
  challenge: RequestChallenge
): Promise<{ rawId: string; [k: string]: unknown }> {
  const publicKey = {
    ...challenge.publicKey,
    challenge: fromBase64Url(challenge.publicKey.challenge),
    allowCredentials: (challenge.publicKey.allowCredentials ?? []).map((c) => ({
      ...c,
      id: fromBase64Url(c.id)
    }))
  } as unknown as PublicKeyCredentialRequestOptions;

  const credential = (await navigator.credentials
    .get({ publicKey })
    .catch(rethrow)) as PublicKeyCredential | null;

  if (!credential) throw new WebauthnError('no_passkey_offered', 'No passkey was offered.');
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64Url(response.authenticatorData),
      clientDataJSON: toBase64Url(response.clientDataJSON),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : null
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

/**
 * A ceremony that did not produce a credential.
 *
 * **Carries a `code` for the same reason `ApiError` does**: an error has a code
 * before it has a message. The code is the stable branch point a UI switches on
 * — here, what `$lib/errors` looks up to render the message in the reader's
 * language — and the `message` is the English fallback for a code nothing has
 * been taught yet. This type was the one error surface in the console exempt
 * from that rule, which meant the login page — the first page anyone sees —
 * could not be translated at all.
 */
export class WebauthnError extends Error {
  readonly code: WebauthnErrorCode;
  /**
   * The `DOMException` name, when the browser refused for a reason we have no
   * specific code for.
   *
   * Carried as data rather than baked into the message, because it is not a
   * word in anybody's language and the sentence around it has to be
   * translatable without losing it.
   */
  readonly detail?: string;

  constructor(code: WebauthnErrorCode, message: string, detail?: string) {
    super(message);
    this.name = 'WebauthnError';
    this.code = code;
    this.detail = detail;
  }
}

export type WebauthnErrorCode =
  /** The ceremony resolved, but with nothing in it. */
  | 'no_passkey_created'
  | 'no_passkey_offered'
  /** Dismissed, or timed out — by far the most common outcome. */
  | 'passkey_cancelled'
  /** This authenticator already holds a credential for this account. */
  | 'passkey_already_registered'
  /** An `rp_id` that does not match the origin: a deployment error. */
  | 'passkey_misconfigured'
  /** Anything else the browser refused, named by its `DOMException`. */
  | 'passkey_refused';

/**
 * Turn the browser's exception into something worth showing.
 *
 * `NotAllowedError` covers both "the user cancelled" and "the operation timed
 * out", and it is by far the most common outcome — it is what a dismissed
 * prompt produces. Rendering the raw DOMException text there tells someone
 * their device failed when they simply pressed Escape.
 */
function rethrow(e: unknown): never {
  if (e instanceof DOMException) {
    if (e.name === 'NotAllowedError') {
      throw new WebauthnError(
        'passkey_cancelled',
        'No passkey was used. Try again when you are ready.'
      );
    }
    if (e.name === 'InvalidStateError') {
      throw new WebauthnError(
        'passkey_already_registered',
        'That authenticator is already registered to this account.'
      );
    }
    if (e.name === 'SecurityError') {
      // Almost always an rp_id that does not match the page's origin, which is
      // a deployment error rather than anything the user did.
      throw new WebauthnError(
        'passkey_misconfigured',
        'This site is not configured correctly for passkeys. Tell whoever runs it that the ' +
          'relying party ID does not match this origin.'
      );
    }
    throw new WebauthnError(
      'passkey_refused',
      `Your browser refused the passkey: ${e.name}.`,
      e.name
    );
  }
  throw e;
}

/**
 * A UUID's *bytes*, base64url — the handle every signal method matches on.
 *
 * `webauthn-rs` puts `uuid.as_bytes()` into the challenge's `user.id`: sixteen
 * raw bytes, not the thirty-six characters anyone reads. **Encoding the text
 * instead is the one silent failure in this whole area.** The browser accepts
 * either, and the wrong one matches no stored credential, forever, with no
 * error on any side. Exported so it can be tested directly against the
 * server's own encoding test rather than only through a signal nobody can
 * observe.
 */
export function userHandle(uuid: string): string {
  const hex = uuid.replace(/-/g, '');
  // Refuse rather than guess, because guessing here is invisible.
  // `Number.parseInt('zz', 16)` is `NaN` and `Uint8Array` writes `NaN` as `0`,
  // so a malformed id would silently produce a *well-formed* handle of the
  // right length that the browser accepts and that matches no credential ever.
  // That is the failure this module's docs call the one silent one in the area;
  // the throw is deliberately raised outside the signal helpers' `catch`, which
  // exists for a vault refusing a hint and not for a bug of ours.
  if (!/^[0-9a-f]{32}$/i.test(hex)) {
    throw new TypeError(`not a UUID, so no credential could match it: ${uuid}`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return toBase64Url(bytes.buffer);
}

/**
 * The three static methods this console signals with.
 *
 * Declared here rather than taken from `lib.dom.d.ts`, which does not have them
 * yet, and read off `globalThis` rather than `window` so they are testable
 * without a DOM. Optional one at a time on purpose: they landed together in one
 * browser and will land separately in the next, so detection is per method and
 * never per interface — and never per browser.
 */
type SignalMethods = {
  signalCurrentUserDetails?: (options: {
    rpId: string;
    userId: string;
    name: string;
    displayName: string;
  }) => Promise<void>;
  signalAllAcceptedCredentials?: (options: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: string[];
  }) => Promise<void>;
  signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
};

function signals(): SignalMethods | undefined {
  return (globalThis as unknown as { PublicKeyCredential?: SignalMethods }).PublicKeyCredential;
}

let resolvedRpId: Promise<string | null> | null = null;

/**
 * The relying-party id, from the server, fetched once and kept.
 *
 * **Never `location.hostname`.** An rp_id may be a registrable *parent* of the
 * origin, so a guess is wrong on exactly the deployments where the two differ —
 * and a signal naming the wrong rp is discarded without an error. Nothing
 * happens and nobody finds out, which is worse than not signalling at all.
 *
 * The same shape as the connect page reading the MCP endpoint out of the
 * discovery document: nothing about a deployment is baked into this bundle. The
 * promise is cached rather than the value, so concurrent callers share one
 * request — but only a *successful* one is kept; see the retry in the body.
 */
function rpId(): Promise<string | null> {
  // The *value* is cached; the failure is not. This module lives as long as the
  // tab does — `adapter-static` means a navigation is not a reload — so caching
  // a rejection would let one 502 during a rolling deploy disable every signal
  // for the rest of the session, including a passkey deletion half an hour
  // later that is exactly when a stale credential gets stranded in a vault.
  // Retrying costs one GET to a public, sessionless endpoint.
  resolvedRpId ??= api
    .webauthnConfig()
    .then((config) => config.rpId)
    .catch(() => {
      resolvedRpId = null;
      return null;
    });
  return resolvedRpId;
}

/**
 * Repair the name a credential vault shows for this account's passkeys.
 *
 * Registering again cannot do this — the label is baked in at creation — so
 * this is the only way an account that had no address when it made its key ever
 * stops being a blank row in somebody's picker.
 *
 * **The pair is forwarded exactly as `/api/me` gave it**, and nothing here
 * composes, prefixes, or falls back to `email` or `label`. `credential_names`
 * on the server is the one place that rule lives; a second copy here would
 * drift, and the signal would keep being accepted while writing something a
 * fresh registration would not have written.
 */
export async function signalAccount(me: Me): Promise<void> {
  const pkc = signals();
  if (!pkc?.signalCurrentUserDetails) return;
  const rp = await rpId();
  if (!rp) return;

  // Built before the `try`, deliberately. `userHandle` throws on an id that is
  // not a UUID, and that is our bug, not a vault refusing a hint — inside the
  // block below it would be swallowed as though the password manager had said
  // no, which is the one thing the swallow must not be allowed to cover.
  const details = {
    rpId: rp,
    userId: userHandle(me.user.id),
    name: me.credentialName,
    displayName: me.credentialDisplayName
  };

  try {
    await pkc.signalCurrentUserDetails(details);
  } catch {
    // Swallowed deliberately, and this is the one place in this console where
    // that is right: a signal is a hint to a password manager, attached to a
    // flow that has already succeeded. Nobody should fail to sign in, or lose
    // a profile edit, because a vault refused a hint.
  }
}

/**
 * Tell the vault which credentials this server still has.
 *
 * Anything it holds for this account and rp that is not in the list is stale —
 * a passkey deleted here, or one cleared by an admin reset — and a vault that
 * was never told keeps offering it in the picker forever. An empty list is
 * legal and meaningful: it says this account has no accepted credentials.
 *
 * The ids go through **un-re-encoded**. `/api/me/passkeys` already speaks the
 * ceremony's base64url, "so the console can compare without re-encoding"; a
 * second encoding here would match nothing.
 */
export async function signalAcceptedCredentials(me: Me, keys: Passkey[]): Promise<void> {
  const pkc = signals();
  if (!pkc?.signalAllAcceptedCredentials) return;
  const rp = await rpId();
  if (!rp) return;

  // Outside the `try` for the same reason as in `signalAccount`.
  const accepted = {
    rpId: rp,
    userId: userHandle(me.user.id),
    allAcceptedCredentialIds: keys.map((key) => key.credentialId)
  };

  try {
    await pkc.signalAllAcceptedCredentials(accepted);
  } catch {
    // Swallowed for the same reason as in `signalAccount`: the delete this is
    // attached to already succeeded on the server, and a vault that refuses
    // the hint must not turn that into a failed page.
  }
}

/**
 * Tell the vault about a credential this server has never heard of.
 *
 * The post-reset case: an account whose passkeys an admin cleared is offered
 * the dead key first, because it is the oldest in the vault, and someone
 * already locked out gets a refusal they cannot act on. This is the only signal
 * that names no account — the browser is not signed into one — which is exactly
 * why it says nothing beyond "not this credential".
 */
export async function signalUnknownCredential(credentialId: string): Promise<void> {
  const pkc = signals();
  if (!pkc?.signalUnknownCredential) return;
  const rp = await rpId();
  if (!rp) return;

  try {
    await pkc.signalUnknownCredential({ rpId: rp, credentialId });
  } catch {
    // Swallowed: this runs on a sign-in that has already failed, and the error
    // the person needs to see is that one — not a second one about a hint.
  }
}
