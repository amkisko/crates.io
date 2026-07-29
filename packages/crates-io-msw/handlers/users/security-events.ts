import { http, HttpResponse } from 'msw';

import { db } from '../../index.js';
import { getSession } from '../../utils/session.js';

export default http.get('/api/v1/me/security_events', ({ request }) => {
  let { user } = getSession();
  if (!user) {
    return HttpResponse.json({ errors: [{ detail: 'must be logged in to perform that action' }] }, { status: 403 });
  }

  let url = new URL(request.url);
  let perPage = Number(url.searchParams.get('per_page') ?? '10');
  if (!Number.isFinite(perPage) || perPage < 1) {
    perPage = 10;
  }
  perPage = Math.min(perPage, 100);

  let events = db.securityEvent
    .findMany(q => q.where(event => event.user.id === user.id), { orderBy: { id: 'desc' } })
    .map(event => ({
      id: event.id,
      event_type: event.eventType,
      api_token_id: event.apiTokenId,
      ip: event.ip,
      metadata: event.metadata,
      created_at: event.createdAt,
    }));

  let page = events.slice(0, perPage);
  let nextPage =
    events.length > perPage
      ? `?per_page=${perPage}&seek=${btoa(JSON.stringify(page.at(-1)!.id))
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replace(/=+$/, '')}`
      : undefined;

  return HttpResponse.json({
    security_events: page,
    meta: {
      total: events.length,
      ...(nextPage ? { next_page: nextPage } : {}),
    },
  });
});
