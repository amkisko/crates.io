const MIN_CALLBACK_PORT = 1024;
const MAX_CALLBACK_PORT = 65_535;
const MIN_STATE_LENGTH = 22;
const MAX_STATE_LENGTH = 128;
const STATE_PATTERN = /^[A-Za-z0-9_-]+$/;

type ImageFactory = () => Pick<HTMLImageElement, 'addEventListener' | 'src'>;

/** Delivers the registry-stored wake-up URL without modifying it. */
export async function deliverLocalhostCallback(
  callbackUrl: string,
  imageFactory: ImageFactory = () => new Image(),
): Promise<void> {
  let url = new URL(callbackUrl);
  let port = Number(url.port);
  let states = url.searchParams.getAll('state');
  let state = states[0] ?? '';
  let valid =
    url.protocol === 'http:' &&
    url.hostname === '127.0.0.1' &&
    !url.username &&
    !url.password &&
    !url.hash &&
    Number.isInteger(port) &&
    port >= MIN_CALLBACK_PORT &&
    port <= MAX_CALLBACK_PORT &&
    url.pathname === '/cargo/registry-authorization' &&
    [...url.searchParams.keys()].every(key => key === 'state') &&
    states.length === 1 &&
    state.length >= MIN_STATE_LENGTH &&
    state.length <= MAX_STATE_LENGTH &&
    STATE_PATTERN.test(state);

  if (!valid) {
    throw new Error('Invalid Cargo callback URL');
  }

  await new Promise<void>((resolve, reject) => {
    let image = imageFactory();
    image.addEventListener('load', () => resolve(), { once: true });
    image.addEventListener('error', () => reject(new Error('Cargo callback failed')), { once: true });
    image.src = callbackUrl;
  });
}
