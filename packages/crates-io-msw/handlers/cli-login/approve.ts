import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';
import { getSession } from '../../utils/session.js';

export default http.post('/api/v1/cli_login/:id/approve', async ({ params, request }) => {
  let { user } = getSession();
  if (!user) {
    return HttpResponse.json({ errors: [{ detail: 'must be logged in to perform that action' }] }, { status: 403 });
  }

  let session = db.cliLoginSession.findFirst(q => q.where({ id: params.id as string }));
  if (!session) {
    return HttpResponse.json({ errors: [{ detail: 'Not Found' }] }, { status: 404 });
  }
  if (session.status !== 'pending') {
    return HttpResponse.json({ errors: [{ detail: 'this CLI login session is no longer pending' }] }, { status: 400 });
  }

  let body = (await request.json()) as {
    name: string;
    endpoint_scopes?: string[] | null;
    crate_scopes?: string[] | null;
    expired_at?: string | null;
    confirmation_code?: string;
    credential?: unknown;
  };

  let normalized = (body.confirmation_code ?? '').replaceAll(/[^A-Za-z0-9]/g, '').toUpperCase();
  let expected = session.confirmationCode.replaceAll(/[^A-Za-z0-9]/g, '').toUpperCase();
  if (!normalized || normalized !== expected) {
    return HttpResponse.json(
      {
        errors: [
          {
            detail: 'confirmation code does not match; enter the code shown in your terminal after cargo login',
          },
        ],
      },
      { status: 400 },
    );
  }

  if (user.apiMfaEnabled && !body.credential) {
    return HttpResponse.json(
      { errors: [{ detail: 'passkey verification required to approve CLI login while API MFA is enabled' }] },
      { status: 400 },
    );
  }

  let token = await db.apiToken.create({
    user,
    name: body.name,
    endpointScopes: body.endpoint_scopes ?? null,
    crateScopes: body.crate_scopes ?? null,
    expiredAt: body.expired_at ?? null,
    createdAt: new Date().toISOString(),
  });

  // Opaque placeholder for poll redeem; never returned to the browser approve response.
  let plaintext = `cio_${token.id}_cli_login_secret`;

  db.cliLoginSession.update(q => q.where({ id: session.id }), {
    data(row) {
      row.status = 'ready';
      row.plaintextToken = plaintext;
      row.apiTokenId = token.id;
      row.userId = user.id;
    },
  });

  return HttpResponse.json({
    status: 'ready',
    token_name: body.name,
    api_token_id: token.id,
    localhost_port: session.localhostPort ?? undefined,
  });
});
