import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';

export default http.get('/api/v1/cli_login/:id', ({ params }) => {
  let session = db.cliLoginSession.findFirst(q => q.where({ id: params.id as string }));
  if (!session) {
    return HttpResponse.json({ errors: [{ detail: 'Not Found' }] }, { status: 404 });
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
