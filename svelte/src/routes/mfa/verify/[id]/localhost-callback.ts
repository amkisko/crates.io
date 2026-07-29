const MIN_CALLBACK_PORT = 1024;
const MAX_CALLBACK_PORT = 65_535;

type ImageFactory = () => Pick<HTMLImageElement, 'onload' | 'onerror' | 'src'>;

/** Delivers an MFA OTP only to the loopback callback shape emitted by crates.io. */
export async function deliverLocalhostCallback(
  callbackUrl: string,
  fetcher: typeof fetch = globalThis.fetch,
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

  try {
    await fetcher(url, { mode: 'no-cors' });
  } catch {
    // Content Security Policy can block `connect-src` to loopback. Cargo returns
    // a valid image response so this fallback can distinguish delivery from a
    // connection failure.
    await new Promise<void>((resolve, reject) => {
      let image = imageFactory();
      image.onload = () => resolve();
      image.onerror = () => reject(new Error('Cargo callback failed'));
      image.src = url.href;
    });
  }
}
