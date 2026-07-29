import { Collection } from '@msw/data';
import * as v from 'valibot';

import * as counters from '../utils/counters.js';

const schema = v.pipe(
  v.object({
    id: v.optional(v.string()),
    status: v.optional(v.picklist(['pending', 'ready', 'consumed']), 'pending'),
    localhostPort: v.optional(v.nullable(v.number()), null),
    clientIp: v.optional(v.nullable(v.string()), null),
    /** Plaintext for MSW only; real API stores a hash and returns the code once from start. */
    confirmationCode: v.optional(v.string()),
    plaintextToken: v.optional(v.nullable(v.string()), null),
    apiTokenId: v.optional(v.nullable(v.number()), null),
    userId: v.optional(v.nullable(v.number()), null),
    expiresAt: v.optional(v.string()),
    createdAt: v.optional(v.string()),
  }),
  v.transform(function (input) {
    let counter = counters.increment('cliLoginSession');
    let id = input.id ?? `login_${counter.toString(36).padStart(8, '0')}`;
    let now = new Date().toISOString();
    let expiresAt = input.expiresAt ?? new Date(Date.now() + 10 * 60 * 1000).toISOString();
    let createdAt = input.createdAt ?? now;
    let confirmationCode = input.confirmationCode ?? `TEST-${counter.toString(36).toUpperCase().padStart(4, '0')}`;
    return { ...input, id, expiresAt, createdAt, confirmationCode };
  }),
);

const collection = new Collection({ schema });

export default collection;
