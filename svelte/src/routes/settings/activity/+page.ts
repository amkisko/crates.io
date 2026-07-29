import { error } from '@sveltejs/kit';

export async function load({ fetch }) {
  let response;
  try {
    response = await fetch('/api/v1/me/security_events?per_page=50');
  } catch {
    loadError(504);
  }

  if (!response.ok) {
    loadError(response.status);
  }

  let body = await response.json();
  return {
    securityEvents: body.security_events ?? [],
    meta: body.meta ?? { total: 0 },
  };
}

function loadError(status: number): never {
  error(status, { message: 'Failed to load security activity', tryAgain: true });
}
