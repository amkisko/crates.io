const MIN_CALLBACK_PORT = 1024;
const MAX_CALLBACK_PORT = 65_535;

type ImageFactory = () => Pick<HTMLImageElement, 'addEventListener' | 'src'>;
type Fetch = typeof globalThis.fetch;

/** Recovers a verified callback after a reload without exposing the secret in a URL. */
export async function recoverLocalhostCallbackUrl(
  challengeId: string,
  callbackSecret: string,
  fetchImpl: Fetch = globalThis.fetch,
): Promise<string | null> {
  let response = await fetchImpl(`/api/v1/mfa/challenges/${challengeId}/recover`, {
    method: 'POST',
    headers: { 'Crates-MFA-Callback-Secret': callbackSecret },
  });
  // The OTP was already consumed, so the original Cargo mutation completed.
  if (response.status === 400) return null;
  if (!response.ok) {
    let body = (await response.json().catch(() => null)) as { errors?: Array<{ detail?: string }> } | null;
    throw new Error(body?.errors?.[0]?.detail ?? 'Failed to recover Cargo callback');
  }
  let body = (await response.json()) as { localhost_callback_url: string };
  return body.localhost_callback_url;
}

/** Delivers an MFA OTP only to the loopback callback shape emitted by crates.io. */
export async function deliverLocalhostCallback(
  callbackUrl: string,
  imageFactory: ImageFactory = () => new Image(),
): Promise<void> {
  let url = new URL(callbackUrl);
  let port = Number(url.port);
  let valid =
    url.protocol === 'http:' &&
    url.hostname === '127.0.0.1' &&
    Number.isInteger(port) &&
    port >= MIN_CALLBACK_PORT &&
    port <= MAX_CALLBACK_PORT &&
    url.pathname === '/' &&
    Boolean(url.searchParams.get('code'));

  if (!valid) {
    throw new Error('Invalid Cargo callback URL');
  }

  // Cargo returns a valid image response. Unlike an opaque `no-cors` fetch,
  // image load/error gives the page a verifiable delivery result.
  await new Promise<void>((resolve, reject) => {
    let image = imageFactory();
    image.addEventListener('load', () => resolve(), { once: true });
    image.addEventListener('error', () => reject(new Error('Cargo callback failed')), { once: true });
    image.src = url.href;
  });
}
