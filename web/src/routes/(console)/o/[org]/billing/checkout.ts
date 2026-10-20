/**
 * Leave the console for Stripe Checkout.
 *
 * A module of its own so render tests can replace it: jsdom cannot navigate,
 * and `window.location.assign` cannot be spied on there.
 *
 * Only an `https:` URL is followed. The server builds it from Stripe's
 * answer, so anything else is a fault upstream, and following a
 * `javascript:` or plaintext URL out of a billing page is the one way that
 * fault could hurt someone.
 */
export function leaveForCheckout(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  window.location.assign(parsed.href);
  return true;
}
