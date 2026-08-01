import { error } from '@sveltejs/kit';

export async function load({ parent, url }) {
  let { userPromise } = await parent();
  let user = await userPromise;

  // CLI link-login approve must be reachable before sign-in.
  let isCliLogin = url.pathname.startsWith('/settings/tokens/cli/');

  if (!user && !isCliLogin) {
    error(401, { message: 'This page requires authentication', loginNeeded: true });
  }
}
