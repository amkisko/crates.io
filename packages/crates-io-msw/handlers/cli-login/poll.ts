import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';

export default http.get('/api/v1/cli_login/:id', ({ params, request }) => {
  let secret = request.headers.get('Crates-Cli-Login-Secret')?.trim();
  if (!secret) {
    return HttpResponse.json(
      {
        errors: [
          {
            detail: 'Crates-Cli-Login-Secret header required; use the poll_secret from POST /api/v1/cli_login',
          },
        ],
      },
      { status: 400 },
    );
  }

  let session = db.cliLoginSession.findFirst(q => q.where({ id: params.id as string }));
  if (!session) {
    return HttpResponse.json({ errors: [{ detail: 'Not Found' }] }, { status: 404 });
  }

  if (session.pollSecret !== secret) {
    return HttpResponse.json({ errors: [{ detail: 'invalid CLI login poll secret' }] }, { status: 403 });
  }

  if (session.status === 'ready' && session.plaintextToken) {
    let token = session.plaintextToken;
    db.cliLoginSession.update(q => q.where({ id: session.id }), {
      data(row) {
        row.status = 'consumed';
        row.plaintextToken = null;
      },
    });
    return HttpResponse.json({
      status: 'ready',
      token,
    });
  }

  return HttpResponse.json({ status: session.status });
});
