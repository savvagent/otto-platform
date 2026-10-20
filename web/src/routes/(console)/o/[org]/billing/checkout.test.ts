// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';

import { leaveForCheckout } from './checkout';

describe('leaveForCheckout', () => {
  const assign = vi.fn();

  afterEach(() => {
    vi.unstubAllGlobals();
    assign.mockReset();
  });

  function stubLocation() {
    vi.stubGlobal('window', { location: { assign } });
  }

  it('follows an https Checkout URL', () => {
    stubLocation();
    expect(leaveForCheckout('https://checkout.stripe.com/c/pay/cs_test_1')).toBe(true);
    expect(assign).toHaveBeenCalledWith('https://checkout.stripe.com/c/pay/cs_test_1');
  });

  it.each(['javascript:alert(1)', 'http://checkout.stripe.com/x', '/o/acme/billing', 'not a url'])(
    'refuses %j',
    (url) => {
      stubLocation();
      expect(leaveForCheckout(url)).toBe(false);
      expect(assign).not.toHaveBeenCalled();
    }
  );
});
