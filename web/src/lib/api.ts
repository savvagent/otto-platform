/**
 * The one place the console talks to `otto-web`.
 *
 * Three things hold here, and each of them is a rule the server also keeps.
 *
 * **No credential is ever spent on a GET.** An invitation link points at a
 * *page* in this app; the page renders a button and
 * the button calls one of the `post` helpers below. A mail scanner that follows
 * the link loads a page and burns nothing. `otto-web`'s
 * `every_single_use_redemption_is_a_post` asserts the other half.
 *
 * **The session is never touched by script.** It is an `HttpOnly`,
 * `__Host-`-prefixed cookie, so there is no token to attach and nothing to
 * store. Requests are same-origin and the browser sends it; `credentials` is
 * left at its default for exactly that reason, and a change to `'include'`
 * would be a sign someone has moved the API to another origin, where the
 * `__Host-` prefix means the cookie could not follow anyway.
 *
 * **An error has a code before it has a message.** `ApiError.code` is the
 * stable branch point — `not_found`, `invalid_credentials`, `rate_limited` —
 * and `message` is written by the server to be shown to a person. Pages branch
 * on the code and render the message; they never parse the message.
 */

import type {
  AuditEvent,
  BrowserSession,
  ClaimedDomain,
  IdpConnection,
  Passkey,
  User,
  RegistrationChallenge,
  AuthenticationChallenge,
  ClaimCode,
  Invite,
  CreatedInvite,
  Joined,
  Me,
  Membership,
  Org,
  OrgMember,
  Role,
  SessionOpened,
  SsoStartResponse,
  Team,
  TeamMember,
  UsageStatus,
  WebauthnConfig
} from './types';

/**
 * A failure the server described. Carries the HTTP status too, because a few
 * callers need to tell "no such thing" (`404`) from "not allowed" (`403`) even
 * though the console's own rule is that an org you are not in answers `404`.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  /** No session, or one the server no longer honours. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

interface ErrorBody {
  error?: { code?: string; message?: string };
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch {
    // A network failure is not a server answer, and telling a user their
    // credentials were wrong when the wifi dropped sends them to reset
    // something that was never broken.
    throw new ApiError(0, 'network', 'Could not reach the server. Check your connection.');
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const parsed: unknown = text.length > 0 ? safeJson(text) : undefined;

  if (!response.ok) {
    const described = parsed as ErrorBody | undefined;
    throw new ApiError(
      response.status,
      described?.error?.code ?? 'unknown',
      described?.error?.message ?? `The server answered ${response.status}.`
    );
  }

  return parsed as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * Build a query string, dropping anything absent.
 *
 * Absent, not empty: a filter nobody set must not narrow anything.
 */
function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered.length > 0 ? `?${rendered}` : '';
}

const get = <T>(path: string) => request<T>('GET', path);
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
const patch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body);
const put = <T>(path: string, body?: unknown) => request<T>('PUT', path, body);
const del = <T>(path: string) => request<T>('DELETE', path);

/** Percent-encode one path segment. A slug is user-chosen; one containing `/` must not become two segments. */
const seg = (value: string) => encodeURIComponent(value);

export const api = {
  // ----------------------------------------------------------------- auth
  /**
   * Create an account and get a passkey challenge.
   *
   * Takes no arguments, deliberately: there is no identifier to give, which is
   * why nothing here can reveal whether an account already exists. The address
   * is set afterwards with `setProfile`.
   */
  signupStart: () => post<RegistrationChallenge>('/api/auth/signup/start'),
  signupFinish: (ceremonyId: string, credential: unknown, nickname?: string) =>
    post<SessionOpened>('/api/auth/signup/finish', { ceremonyId, credential, nickname }),

  /** Sign in. No identifier — the passkey says who you are. */
  loginStart: () => post<AuthenticationChallenge>('/api/auth/login/start'),
  loginFinish: (ceremonyId: string, credential: unknown) =>
    post<SessionOpened>('/api/auth/login/finish', { ceremonyId, credential }),

  /** Re-register after an admin cleared this account's passkeys. */
  claimStart: (code: string) => post<RegistrationChallenge>('/api/auth/claim/start', { code }),
  claimFinish: (ceremonyId: string, code: string, credential: unknown, nickname?: string) =>
    post<SessionOpened>('/api/auth/claim/finish', { ceremonyId, code, credential, nickname }),

  logout: () => post<void>('/api/auth/logout'),

  /**
   * The anonymous "sign in with SSO" entry point. Resolves the identity
   * provider purely from the email's domain — no account is looked up, so it
   * works from a signed-out browser.
   */
  /**
   * `next` is stored with the ceremony and followed by the callback, so an SSO
   * sign-in started from `/login?next=/oauth/authorize?…` returns to the
   * authorization request. The server re-validates it.
   */
  ssoStart: (email: string, next?: string) =>
    post<SsoStartResponse>('/api/auth/sso/start', next ? { email, next } : { email }),

  /**
   * The rp_id every passkey on this deployment is bound to.
   *
   * Public, and it discloses nothing: the same value is in every challenge this
   * server hands an unauthenticated caller. `$lib/webauthn` reads it once and
   * caches it — see `rpId()` there for why guessing is not an option.
   */
  webauthnConfig: () => get<WebauthnConfig>('/api/auth/webauthn'),

  // ------------------------------------------------------------------- me
  me: () => get<Me>('/api/me'),
  sessions: () => get<BrowserSession[]>('/api/me/sessions'),
  signOutEverywhere: () => del<{ revoked: number }>('/api/me/sessions'),
  /**
   * This account's own security activity: the audit rows written outside any
   * org that it is the actor of. Not an org's trail — that is `audit` below,
   * and admin-only.
   */
  myAudit: (limit = 100, actionPrefix?: string) =>
    get<AuditEvent[]>(`/api/me/audit${query({ limit, actionPrefix })}`),

  /** Add another authenticator. One passkey is one device. */
  addPasskeyStart: () => post<RegistrationChallenge>('/api/me/passkeys/start'),
  addPasskeyFinish: (ceremonyId: string, credential: unknown, nickname?: string) =>
    post<void>('/api/me/passkeys/finish', { ceremonyId, credential, nickname }),
  passkeys: () => get<Passkey[]>('/api/me/passkeys'),
  removePasskey: (id: string) => del<void>(`/api/me/passkeys/${seg(id)}`),
  renamePasskey: (id: string, nickname: string) =>
    patch<void>(`/api/me/passkeys/${seg(id)}`, { nickname }),

  /**
   * Set the address and display name.
   *
   * The one call that will say an address is already in use — which is safe
   * here precisely because it needs a session.
   */
  /**
   * `locale` has three states, not two: omit it to leave the console language
   * alone, pass a supported locale to set it, or pass an explicit `null` to
   * clear it and go back to following the browser. `undefined` and `null` mean
   * different things here, which is unusual enough to be worth saying — the
   * server distinguishes them deliberately.
   */
  setProfile: (profile: { email?: string; name?: string; locale?: string | null }) =>
    patch<User>('/api/me', profile),

  /**
   * The authenticated counterpart to `ssoStart`. Links the signed-in
   * account to whatever identity the resulting ceremony resolves to — the
   * only self-service way a passkey-only account gains a federated identity.
   */
  ssoLinkStart: () => post<SsoStartResponse>('/api/me/sso/link/start'),

  // ----------------------------------------------------------------- orgs
  orgs: () => get<Membership[]>('/api/orgs'),
  createOrg: (slug: string, name: string) => post<Org>('/api/orgs', { slug, name }),
  org: (org: string) => get<Joined>(`/api/orgs/${seg(org)}`),

  members: (org: string) => get<OrgMember[]>(`/api/orgs/${seg(org)}/members`),
  setMemberRole: (org: string, user: string, role: Role) =>
    patch<void>(`/api/orgs/${seg(org)}/members/${seg(user)}`, { role }),
  removeMember: (org: string, user: string) =>
    del<void>(`/api/orgs/${seg(org)}/members/${seg(user)}`),
  forceLogout: (org: string, user: string) =>
    post<void>(`/api/orgs/${seg(org)}/members/${seg(user)}/logout`),

  invites: (org: string) => get<Invite[]>(`/api/orgs/${seg(org)}/invites`),
  /** Returns the one-time code, shown once — the admin delivers it themselves. */
  invite: (org: string, email: string, role: Role) =>
    post<CreatedInvite>(`/api/orgs/${seg(org)}/invites`, { email, role }),
  /** Clear a member's passkeys and get the one-time code they need to re-register. */
  resetMemberPasskeys: (org: string, user: string) =>
    post<ClaimCode>(`/api/orgs/${seg(org)}/members/${seg(user)}/reset-passkeys`),
  revokeInvite: (org: string, id: string) => del<void>(`/api/orgs/${seg(org)}/invites/${seg(id)}`),
  acceptInvite: (org: string, token: string) =>
    post<Joined>(`/api/orgs/${seg(org)}/invites/accept`, { token }),

  // ---------------------------------------------------------------- teams
  teams: (org: string) => get<Team[]>(`/api/orgs/${seg(org)}/teams`),
  createTeam: (org: string, slug: string, name?: string) =>
    post<Team>(`/api/orgs/${seg(org)}/teams`, { slug, name: name || null }),
  renameTeam: (org: string, team: string, name: string) =>
    patch<Team>(`/api/orgs/${seg(org)}/teams/${seg(team)}`, { name }),
  deleteTeam: (org: string, team: string) => del<void>(`/api/orgs/${seg(org)}/teams/${seg(team)}`),
  teamMembers: (org: string, team: string) =>
    get<TeamMember[]>(`/api/orgs/${seg(org)}/teams/${seg(team)}/members`),
  addTeamMember: (org: string, team: string, user: string) =>
    put<void>(`/api/orgs/${seg(org)}/teams/${seg(team)}/members/${seg(user)}`),
  removeTeamMember: (org: string, team: string, user: string) =>
    del<void>(`/api/orgs/${seg(org)}/teams/${seg(team)}/members/${seg(user)}`),

  // ------------------------------------------------------------------ sso
  /**
   * This org's bound identity provider, if any — issuer and client id,
   * never the secret (the server has no read path for it at all). A `204`
   * (nothing bound) resolves to `undefined`, same as `request()`'s general
   * "no content" handling.
   */
  getSsoConnection: (org: string) =>
    get<IdpConnection | undefined>(`/api/orgs/${seg(org)}/sso/connection`),
  /** Bind (or replace) this org's identity provider. */
  upsertSsoConnection: (
    org: string,
    body: { issuer: string; clientId: string; clientSecret: string }
  ) => put<IdpConnection>(`/api/orgs/${seg(org)}/sso/connection`, body),
  /** Refused with `sso_lockout` while `enforceSso` is on. */
  deleteSsoConnection: (org: string) => del<void>(`/api/orgs/${seg(org)}/sso/connection`),

  ssoDomains: (org: string) => get<ClaimedDomain[]>(`/api/orgs/${seg(org)}/sso/domains`),
  /** Returns the exact TXT record name/value to publish. */
  claimSsoDomain: (org: string, domain: string) =>
    post<ClaimedDomain>(`/api/orgs/${seg(org)}/sso/domains`, { domain }),
  /** A synchronous DNS lookup. `{verified: false}` is not an error. */
  verifySsoDomain: (org: string, domain: string) =>
    post<{ verified: boolean }>(`/api/orgs/${seg(org)}/sso/domains/${seg(domain)}/verify`),
  /** Refused with `sso_lockout` while it's the org's only verified domain and `enforceSso` is on. */
  deleteSsoDomain: (org: string, domain: string) =>
    del<void>(`/api/orgs/${seg(org)}/sso/domains/${seg(domain)}`),

  /** Refused with `sso_lockout` when turning this on with no working SSO path yet. */
  setEnforceSso: (org: string, enforceSso: boolean) =>
    put<Org>(`/api/orgs/${seg(org)}/sso/enforce`, { enforceSso }),

  // ---------------------------------------------------------- usage & audit
  usage: (org: string) => get<UsageStatus>(`/api/orgs/${seg(org)}/usage`),
  audit: (org: string, limit = 100) =>
    get<AuditEvent[]>(`/api/orgs/${seg(org)}/audit${query({ limit })}`)
};
