import { describe, expect, it } from 'vitest';
import pkg from '../../package.json';
import { APP_VERSION } from './version';

describe('APP_VERSION', () => {
  it('matches package.json', () => {
    expect(APP_VERSION).toBe(pkg.version);
  });

  it('looks like a SemVer version', () => {
    expect(APP_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
