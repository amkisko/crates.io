import { describe, expect, it } from 'vitest';

import { decodeBase64Url, encodeBase64Url, revivePublicKeyCreation, revivePublicKeyRequest } from './webauthn';

describe('WebAuthn utilities', () => {
  it('round-trips unpadded base64url values', () => {
    let bytes = Uint8Array.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);

    let encoded = encodeBase64Url(bytes.buffer);

    expect(encoded).toBe('AAEC-vv8_f7_');
    expect(new Uint8Array(decodeBase64Url(encoded))).toEqual(bytes);
  });

  it('revives request challenge and credential identifiers', () => {
    let options = revivePublicKeyRequest({
      challenge: 'AQI',
      allowCredentials: [{ id: 'AwQ', type: 'public-key' }],
      timeout: 60_000,
    });

    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(Uint8Array.from([1, 2]));
    expect(new Uint8Array(options.allowCredentials![0].id as ArrayBuffer)).toEqual(Uint8Array.from([3, 4]));
    expect(options.timeout).toBe(60_000);
  });

  it('revives creation challenge, user id, and excluded credentials', () => {
    let options = revivePublicKeyCreation({
      challenge: 'AQI',
      rp: { name: 'crates.io' },
      user: { id: 'AwQ', name: 'ferris', displayName: 'Ferris' },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      excludeCredentials: [{ id: 'BQY', type: 'public-key' }],
    });

    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(Uint8Array.from([1, 2]));
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(Uint8Array.from([3, 4]));
    expect(new Uint8Array(options.excludeCredentials![0].id as ArrayBuffer)).toEqual(Uint8Array.from([5, 6]));
  });
});
