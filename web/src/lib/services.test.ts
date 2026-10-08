import { describe, expect, it } from 'vitest';

import { SERVICES, servicesIn } from './services';

describe('the services list', () => {
  it('ships Otto Factory, over https', () => {
    expect(SERVICES.map((s) => s.name)).toContain('Otto Factory');
    for (const service of SERVICES) {
      expect(service.url.startsWith('https://')).toBe(true);
    }
  });

  it('drops anything that is not an https link', () => {
    const kept = servicesIn([
      { name: 'Good', url: 'https://good.example' },
      { name: 'Plain', url: 'http://plain.example' },
      { name: 'Script', url: 'javascript:alert(1)' },
      { name: 'Garbage', url: 'not a url' },
      { name: '  ', url: 'https://nameless.example' }
    ]);
    expect(kept).toEqual([{ name: 'Good', url: 'https://good.example' }]);
  });
});
