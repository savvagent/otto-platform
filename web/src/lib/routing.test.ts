import { describe, expect, it } from 'vitest';

import { guard, type GuardState } from './routing';

const signedOut: GuardState = {
  signedIn: false,
  needsProfile: false,
  isPublic: false,
  path: '/home',
  next: null
};
const signedIn: GuardState = { ...signedOut, signedIn: true };

describe('the console routing guard, signed out', () => {
  it('sends a visit to the console home to /login with no next', () => {
    expect(guard({ ...signedOut, path: '/home' })).toEqual({ kind: 'goto', to: '/login' });
    expect(guard({ ...signedOut, path: '/' })).toEqual({ kind: 'goto', to: '/login' });
  });

  it('carries any other page through as next', () => {
    expect(guard({ ...signedOut, path: '/o/acme/members?x=1' })).toEqual({
      kind: 'goto',
      to: '/login?next=%2Fo%2Facme%2Fmembers%3Fx%3D1'
    });
  });

  it('leaves the doors alone', () => {
    expect(guard({ ...signedOut, isPublic: true, path: '/login' })).toBeNull();
  });
});

describe('the console routing guard, signed in', () => {
  it('sends /login with no next to the console home', () => {
    expect(guard({ ...signedIn, isPublic: true, path: '/login' })).toEqual({
      kind: 'goto',
      to: '/home'
    });
  });

  it('reads next=/ as the console home', () => {
    expect(guard({ ...signedIn, isPublic: true, path: '/login?next=%2F', next: '/' })).toEqual({
      kind: 'goto',
      to: '/home'
    });
  });

  it('follows a safe next, and a server route with a full navigation', () => {
    expect(guard({ ...signedIn, isPublic: true, next: '/o/acme' })).toEqual({
      kind: 'goto',
      to: '/o/acme'
    });
    expect(guard({ ...signedIn, isPublic: true, next: '/oauth/authorize?x=1' })).toEqual({
      kind: 'assign',
      to: '/oauth/authorize?x=1'
    });
  });

  it('ignores an unsafe next', () => {
    expect(guard({ ...signedIn, isPublic: true, next: '//evil.test' })).toEqual({
      kind: 'goto',
      to: '/home'
    });
  });

  it('keeps an account that still owes its address on /signup', () => {
    expect(guard({ ...signedIn, isPublic: true, needsProfile: true, path: '/signup' })).toBeNull();
  });

  it('leaves console pages alone', () => {
    expect(guard({ ...signedIn, path: '/o/acme' })).toBeNull();
  });
});
