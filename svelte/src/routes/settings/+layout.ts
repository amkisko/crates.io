import { error } from '@sveltejs/kit';

export async function load({ parent, url }) {
  let { userPromise } = await parent();
  let user = await userPromise;

  // CLI link-login approve must be reachable before sign-in.
  // Legacy MFA verify paths redirect to /mfa/verify/{id} without a cookie.
  let isCliLogin = url.pathname.startsWith('/settings/tokens/cli/');
  let isLegacyMfaVerify =
    url.pathname.startsWith('/settings/api-mfa/verify/') || url.pathname.startsWith('/settings/mfa/verify/');

  if (!user && !isCliLogin && !isLegacyMfaVerify) {
    error(401, { message: 'This page requires authentication', loginNeeded: true });
  }
}
