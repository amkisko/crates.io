import { describe, expect, it } from 'vitest';

import { isValidCratePattern, TokenFormState } from './token-form.svelte';

describe('isValidCratePattern', () => {
  it.each(['serde', 'serde-json', 'serde_json', 'serde*', '*'])('accepts %s', pattern => {
    expect(isValidCratePattern(pattern)).toBe(true);
  });

  it.each(['', '-serde', '_serde', 'serde**', 'serde.json'])('rejects %s', pattern => {
    expect(isValidCratePattern(pattern)).toBe(false);
  });
});

describe('TokenFormState', () => {
  it('validates the shared token fields', () => {
    let state = new TokenFormState();

    expect(state.validate()).toBe(false);
    expect(state.nameInvalid).toBe(true);
    expect(state.scopesInvalid).toBe(true);

    state.name = 'cargo login';
    state.toggleScope('publish-new');
    state.addCratePattern();
    state.crateScopes[0].pattern = 'serde*';

    expect(state.validate()).toBe(true);
  });

  it('marks invalid crate patterns', () => {
    let state = new TokenFormState({
      name: 'release token',
      endpointScopes: ['publish-new'],
      crateScopes: ['-invalid'],
    });

    expect(state.validate()).toBe(false);
    expect(state.crateScopes[0].showAsInvalid).toBe(true);
  });
});
