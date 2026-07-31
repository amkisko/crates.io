/** Decodes an unpadded base64url value into the binary format WebAuthn expects. */
export function decodeBase64Url(value: string): ArrayBuffer {
  let padded = value.replaceAll('-', '+').replaceAll('_', '/');
  while (padded.length % 4) padded += '=';

  let binary = atob(padded);
  let bytes = Uint8Array.from(binary, character => character.codePointAt(0)!);
  return bytes.buffer;
}

/** Encodes WebAuthn binary data as unpadded base64url for the JSON API. */
export function encodeBase64Url(buffer: ArrayBuffer): string {
  let binary = Array.from(new Uint8Array(buffer), byte => String.fromCodePoint(byte)).join('');
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll(/=+$/g, '');
}

/** Converts JSON creation options into browser WebAuthn creation options. */
export function revivePublicKeyCreation(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  let user = options.user as Record<string, unknown>;
  return {
    ...(options as unknown as PublicKeyCredentialCreationOptions),
    challenge: decodeBase64Url(options.challenge as string),
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: decodeBase64Url(user.id as string),
    },
    excludeCredentials: ((options.excludeCredentials as Array<Record<string, unknown>>) ?? []).map(credential => ({
      ...(credential as unknown as PublicKeyCredentialDescriptor),
      id: decodeBase64Url(credential.id as string),
    })),
  };
}

/** Converts JSON request options into browser WebAuthn request options. */
export function revivePublicKeyRequest(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  return {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: decodeBase64Url(options.challenge as string),
    allowCredentials: ((options.allowCredentials as Array<Record<string, unknown>>) ?? []).map(credential => ({
      ...(credential as unknown as PublicKeyCredentialDescriptor),
      id: decodeBase64Url(credential.id as string),
    })),
  };
}

/** Serializes a browser passkey registration response for the JSON API. */
export function serializeAttestation(credential: PublicKeyCredential) {
  let response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      attestationObject: encodeBase64Url(response.attestationObject),
    },
  };
}

/** Serializes a browser passkey authentication response for the JSON API. */
export function serializeAssertion(credential: PublicKeyCredential) {
  let response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      authenticatorData: encodeBase64Url(response.authenticatorData),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
    },
  };
}
