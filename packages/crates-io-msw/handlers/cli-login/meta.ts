import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';
import { getSession } from '../../utils/session.js';

export default http.get('/api/v1/cli_login/:id/meta', ({ params }) => {
  let { user } = getSession();
  if (!user) {
    return HttpResponse.json({ errors: [{ detail: 'must be logged in to perform that action' }] }, { status: 403 });
  }

  let session = db.cliLoginSession.findFirst(q => q.where({ id: params.id as string }));
  if (!session) {
    return HttpResponse.json({ errors: [{ detail: 'Not Found' }] }, { status: 404 });
  }

  let mfaRequired = Boolean(user.apiMfaEnabled);
  return HttpResponse.json({
    login_id: session.id,
    status: session.status,
    expires_at: session.expiresAt,
    localhost_port: session.localhostPort,
    client_ip: session.clientIp ?? undefined,
    mfa_required: mfaRequired,
    // MSW has no passkey store; recovery path is unused in e2e unless set explicitly.
    mfa_email_otp_allowed: false,
  });
});
