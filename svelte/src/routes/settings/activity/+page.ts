import { createClient } from '@crates-io/api-client';
import { error } from '@sveltejs/kit';

export async function load({ fetch }) {
  let client = createClient({ fetch });
  let response;
  try {
    response = await client.GET('/api/v1/me/security_events', {
      params: { query: { per_page: 50 } },
    });
  } catch {
    loadError(504);
  }

  if (!response.data) {
    loadError(response.response.status);
  }

  return {
    securityEvents: response.data.security_events.map(event => ({
      ...event,
      api_token_id: event.api_token_id ?? null,
      ip: event.ip ?? null,
      metadata: event.metadata as Record<string, string | null>,
    })),
    meta: response.data.meta,
  };
}

function loadError(status: number): never {
  error(status, { message: 'Failed to load security activity', tryAgain: true });
}
