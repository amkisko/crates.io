import { Collection } from '@msw/data';
import * as v from 'valibot';

import * as counters from '../utils/counters.js';

const schema = v.pipe(
  v.object({
    id: v.optional(v.number()),
    eventType: v.optional(v.string(), 'token_created'),
    apiTokenId: v.optional(v.nullable(v.number()), null),
    ip: v.optional(v.nullable(v.string()), null),
    metadata: v.optional(v.record(v.string(), v.nullable(v.string())), {}),
    createdAt: v.optional(v.string(), '2026-07-29T12:00:00Z'),
    user: v.any(),
  }),
  v.transform(function (input) {
    let counter = counters.increment('securityEvent');
    let id = input.id ?? counter;
    return { ...input, id };
  }),
);

const collection = new Collection({ schema });

export default collection;
