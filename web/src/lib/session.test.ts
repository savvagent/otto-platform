import { afterEach, describe, expect, it } from 'vitest';

import { consoleEntry, session } from './session.svelte';
import type { Me, Membership } from './types';

/**
 * Where a "way into the console" link goes. One rule, used by the marketing
 * header, the landing page and the product pages, so a visitor never sees
 * two of them disagree about whether they are signed in.
 */

function membership(orgSlug: string): Membership {
  return { orgId: orgSlug, userId: 'u1', role: 'owner', orgSlug, orgName: orgSlug, plan: 'free' };
}

afterEach(() => session.clear());

describe('consoleEntry', () => {
  it('sends a signed-out visitor to sign up', () => {
    expect(consoleEntry({ signedIn: false, homeOrg: undefined })).toEqual({
      kind: 'signup',
      href: '/signup'
    });
  });

  it('sends a member to their home org', () => {
    expect(consoleEntry({ signedIn: true, homeOrg: 'acme' })).toEqual({
      kind: 'console',
      href: '/o/acme'
    });
  });

  it('sends a signed-in account with no org to create one', () => {
    expect(consoleEntry({ signedIn: true, homeOrg: undefined })).toEqual({
      kind: 'console',
      href: '/orgs/new'
    });
  });

  it('never names an org for a signed-out visitor, whatever homeOrg says', () => {
    expect(consoleEntry({ signedIn: false, homeOrg: 'acme' }).href).toBe('/signup');
  });

  it('reads the live session', () => {
    expect(consoleEntry(session).href).toBe('/signup');
    session.me = { orgs: [membership('acme')] } as unknown as Me;
    expect(consoleEntry(session).href).toBe('/o/acme');
    session.me = { orgs: [] } as unknown as Me;
    expect(consoleEntry(session).href).toBe('/orgs/new');
  });
});
