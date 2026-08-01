import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';

export default http.post('/api/v1/cli_login', async () => {
  let session = await db.cliLoginSession.create({
    status: 'pending',
  });

  let loginId = session.id;
  return HttpResponse.json({
    login_id: loginId,
    login_url: `http://localhost:4200/settings/tokens/cli/${loginId}`,
    poll_url: `http://localhost:4200/api/v1/cli_login/${loginId}`,
    confirmation_code: session.confirmationCode,
    poll_secret: session.pollSecret,
    expires_at: session.expiresAt,
    recommended_poll_interval_secs: 2,
  });
});
