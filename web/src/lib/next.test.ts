import { describe, expect, it } from 'vitest';

import { consoleNext, safeNext } from './next';

describe('safeNext', () => {
  it.each([
    null,
    '',
    'dashboard',
    'https://evil.test/',
    '//evil.test',
    '/\\evil.test',
    '/\t/evil.test',
    '/\n/evil.test',
    '/a\\b'
  ])('refuses %j', (raw) => {
    expect(safeNext(raw)).toBeUndefined();
  });

  it('keeps a same-origin path, `/` included', () => {
    expect(safeNext('/o/acme?tab=1')).toBe('/o/acme?tab=1');
    expect(safeNext('/')).toBe('/');
  });
});

describe('consoleNext', () => {
  // `/` is the marketing page; inside the console it means the console home.
  it('reads a bare `/` as the console home', () => {
    expect(consoleNext('/')).toBe('/home');
  });

  it('leaves every other safe path alone', () => {
    expect(consoleNext('/home')).toBe('/home');
    expect(consoleNext('/o/acme')).toBe('/o/acme');
    expect(consoleNext('/?a=1')).toBe('/?a=1');
    expect(consoleNext('/oauth/authorize?client_id=c')).toBe('/oauth/authorize?client_id=c');
  });

  it.each([null, '', '//evil.test', '/\\evil.test', 'https://evil.test/'])(
    'still refuses %j',
    (raw) => {
      expect(consoleNext(raw)).toBeUndefined();
    }
  );
});
