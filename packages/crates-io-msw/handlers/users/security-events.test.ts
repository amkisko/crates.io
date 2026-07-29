import { expect, test } from 'vitest';

import { db } from '../../index.js';

test('requires login', async function () {
  let response = await fetch('/api/v1/me/security_events');
  expect(response.status).toBe(403);
});

test('lists events for the session user', async function () {
  let user = await db.user.create({});
  await db.mswSession.create({ user });
  await db.securityEvent.create({
    user,
    eventType: 'token_created',
    metadata: { token_name: 'ci' },
    ip: '203.0.113.0/24',
  });

  let response = await fetch('/api/v1/me/security_events');
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchInlineSnapshot(`
    {
      "meta": {
        "total": 1,
      },
      "security_events": [
        {
          "api_token_id": null,
          "created_at": "2026-07-29T12:00:00Z",
          "event_type": "token_created",
          "id": 1,
          "ip": "203.0.113.0/24",
          "metadata": {
            "token_name": "ci",
          },
        },
      ],
    }
  `);
});
