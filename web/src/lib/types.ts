/**
 * The console API's wire types.
 *
 * Hand-written, and mirroring `crates/otto-web/src/openapi.rs` rather than
 * generated from it. Generation would be the reflex; it is the wrong trade at
 * this size. A generator has to run in CI to be worth anything, and until
 * the server binds a port there is no document to fetch — so the "generated"
 * file would in practice be a checked-in artifact nobody regenerates, which is
 * the same hand-written file with a comment claiming otherwise.
 * `GET /api/openapi.json` is the authority either way; this is a transcription
 * of it, and `npm run check` fails when a page reads a field not declared here.
 *
 * Every name is camelCase because every response body is: `otto-web`'s structs
 * carry `#[serde(rename_all = "camelCase")]`.
 */

export type Role = 'owner' | 'admin' | 'member';

export interface User {
  id: string;
  /** Absent until the account sets one — a passkey creates the account. */
  email: string | null;
  name: string | null;
  /**
   * Generated words — `brisk-harbor-42` — that name this account in a
   * credential vault's picker. Never an identifier and never unique; it exists
   * so a key belonging to an account with no address is still nameable.
   */
  label: string;
  /**
   * The console language this account chose, or `null` for "never chose".
   *
   * `null` is not English — it is the state where the browser's own preference
   * is still in charge. See `$lib/locale`.
   */
  locale: string | null;
  createdAt: string;
  disabledAt: string | null;
}

export interface Org {
  id: string;
  slug: string;
  name: string;
  plan: string;
  enforceSso: boolean;
  createdAt: string;
}

/** One org this account belongs to, and the role it holds there. */
export interface Membership {
  orgId: string;
  userId: string;
  role: Role;
  orgSlug: string;
  orgName: string;
  plan: string;
}

export interface Me {
  user: User;
  orgs: Membership[];
  shouldAddPasskey: boolean;
  passkeyCount: number;
  /**
   * What a fresh registration would file this account's credential under, as
   * `otto_auth::passkeys::credential_names` composed it.
   *
   * Handed over rather than derived here, and forwarded to
   * `signalCurrentUserDetails` **verbatim**. A second copy of the
   * email-then-name-then-label precedence in TypeScript would drift from the
   * server's, and the drift would be silent: the signal is accepted either way
   * and writes words subtly unlike what registering again writes, so "repair a
   * stale label by signing in once" would half-work and look like it worked.
   */
  credentialName: string;
  /** The row a human reads in a vault's picker. Same rule: never composed here. */
  credentialDisplayName: string;
}

export interface Joined {
  org: Org;
  role: Role;
}

export interface SessionOpened {
  user: User;
  shouldAddPasskey: boolean;
}

export interface OrgMember {
  id: string;
  email: string | null;
  name: string | null;
  /** See `User.label` — what to render where an address is missing. */
  label: string;
  role: Role;
  joinedAt: string;
  disabledAt: string | null;
}

export interface Invite {
  id: string;
  orgId: string;
  email: string;
  role: Role;
  invitedBy: string | null;
  expiresAt: string;
  acceptedAt: string | null;
  createdAt: string;
}

/**
 * The response from minting an invitation: the invite, plus the one-time code.
 *
 * `code` and `link` are the same secret twice and are returned **only** here —
 * nothing is emailed, and only the hash is stored, so an admin who loses the
 * code re-invites rather than looking it up.
 */
export interface CreatedInvite extends Invite {
  code: string;
  link: string;
}

/** A registered authenticator, as the console lists it. */
export interface Passkey {
  id: string;
  /**
   * The credential's own id, base64url without padding — the same encoding the
   * ceremony speaks, so it can be compared with what an authenticator reports
   * without re-encoding either side.
   *
   * **A public handle, not a secret.** The authenticator hands it to any origin
   * it is asked to sign for; withholding it protects nothing. It is here
   * because `signalAllAcceptedCredentials` matches the surviving credentials by
   * it, and a list that omitted it would leave a deleted passkey in the
   * picker forever.
   */
  credentialId: string;
  nickname: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

/** A WebAuthn challenge plus the id that lets the server find its own state. */
export interface RegistrationChallenge {
  ceremonyId: string;
  challenge: unknown;
}

export interface AuthenticationChallenge {
  ceremonyId: string;
  challenge: unknown;
}

/**
 * A one-time code letting an account register a passkey again, returned once
 * to the admin who cleared them. Nothing is emailed.
 */
export interface ClaimCode {
  code: string;
  link: string;
}

export interface Team {
  id: string;
  orgId: string;
  slug: string;
  name: string;
  createdAt: string;
}

export interface TeamMember {
  userId: string;
  email: string | null;
  name: string | null;
  /** See `User.label` — what to render where an address is missing. */
  label: string;
  joinedAt: string;
}

export interface UsageStatus {
  plan: string;
  includedOps: number;
  billableUsed: number;
  remaining: number;
  totalCalls: number;
  periodStart: string;
  warning: boolean;
  hardStop: boolean;
  /** Whether the server is currently refusing billable calls over the bucket. */
  enforced: boolean;
}

export interface BrowserSession {
  id: string;
  userId: string;
  expiresAt: string;
  createdAt: string;
}

export interface AuditEvent {
  id: number;
  orgId: string | null;
  actorUserId: string | null;
  actorLabel: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  detail: Record<string, unknown>;
  createdAt: string;
}

/**
 * The relying party every passkey on this deployment is bound to.
 *
 * Read from the server rather than taken from `location.hostname`: an rp_id may
 * be a registrable *parent* of the origin, and a browser discards a signal that
 * names the wrong one without an error — so a guess no-ops on exactly the
 * deployments where it differs, and nobody finds out.
 */
export interface WebauthnConfig {
  rpId: string;
}

/**
 * An org's bound identity provider, minus its secret.
 *
 * Returned by both `GET` and `PUT .../sso/connection`. `clientSecret` is
 * never a field here at all: it is sealed at rest and no endpoint ever
 * returns it, matching `TrackerConnection`'s `hasCredentials`-not-the-secret
 * convention one step further.
 */
export interface IdpConnection {
  id: string;
  orgId: string;
  issuer: string;
  clientId: string;
  /** The provider's discovery document. Not rendered; kept for shape fidelity. */
  discovery: unknown;
  createdAt: string;
}

/**
 * A domain this org has claimed, verified or not — with the exact DNS TXT
 * record the console tells an admin to publish to prove control of it.
 */
export interface ClaimedDomain {
  orgId: string;
  domain: string;
  verificationToken: string;
  verifiedAt: string | null;
  createdAt: string;
  txtRecordName: string;
  txtRecordValue: string;
}

/** `POST /api/auth/sso/start` and `POST /api/me/sso/link/start` both answer this. */
export interface SsoStartResponse {
  redirectUrl: string;
}
