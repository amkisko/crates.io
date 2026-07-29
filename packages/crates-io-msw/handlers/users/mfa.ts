import { http, HttpResponse } from 'msw';

import { getSession } from '../../utils/session.js';

export default http.get('/api/v1/me/mfa', () => {
  let { user } = getSession();
  if (!user) {
    return HttpResponse.json({ errors: [{ detail: 'must be logged in to perform that action' }] }, { status: 403 });
  }

  return HttpResponse.json({
    enabled: Boolean(user.apiMfaEnabled),
    credentials: [],
    grant_expires_at: null,
    has_verified_email: Boolean(user.email),
  });
});
