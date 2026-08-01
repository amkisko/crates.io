import type { SetupWorker } from 'msw/browser';

import { http, HttpResponse } from 'msw';
import { afterEach, beforeEach, describe, expect, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { page } from 'vitest/browser';

import { test } from '../../../test/msw';
import PageTestWrapper from './PageTestWrapper.svelte';

const callback = vi.hoisted(() => vi.fn());

vi.mock('$app/state', () => ({
  page: {
    params: { id: 'mut_test' },
    url: new URL('https://crates.io/verify/mut_test'),
  },
}));

vi.mock('./localhost-callback', async importOriginal => ({
  ...(await importOriginal<typeof import('./localhost-callback')>()),
  deliverLocalhostCallback: callback,
}));

const callbackUrl = 'http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef';
const archiveSha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function installApiHandlers(worker: SetupWorker) {
  worker.use(
    http.get('/api/v1/auth/challenges/mut_test', () =>
      HttpResponse.json({
        status: 'pending',
        operation: 'publish',
        operation_summary: 'Publish example 1.0.0',
        crate_name: 'example',
        archive_sha256: archiveSha256,
        expires_at: '2099-01-01T00:00:00Z',
      }),
    ),
    http.post('/api/v1/auth/challenges/mut_test/start', () =>
      HttpResponse.json({
        public_key: {
          challenge: 'AQ',
          allowCredentials: [],
        },
      }),
    ),
    http.post('/api/v1/auth/challenges/mut_test/finish', () =>
      HttpResponse.json({
        callback_url: callbackUrl,
      }),
    ),
    http.post('/api/v1/auth/challenges/mut_test/deny', () =>
      HttpResponse.json({
        status: 'denied',
      }),
    ),
  );
}

function mockPasskey() {
  let byte = new Uint8Array([1]).buffer;
  let credential = {
    id: 'credential',
    rawId: byte,
    type: 'public-key',
    response: {
      clientDataJSON: byte,
      authenticatorData: byte,
      signature: byte,
      userHandle: null,
    },
  } as unknown as PublicKeyCredential;

  return vi.spyOn(navigator.credentials, 'get').mockResolvedValue(credential);
}

describe('/verify/[id]', () => {
  beforeEach(() => {
    callback.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('reports callback success only after Cargo receives the wake-up', async ({ worker }) => {
    installApiHandlers(worker);
    callback.mockImplementation(async () => {});
    mockPasskey();

    await render(PageTestWrapper);
    await expect.element(page.getByRole('heading', { name: 'Authorize publishing example' })).toBeInTheDocument();
    await expect.element(page.getByCSS('[data-test-archive-digest]')).toHaveTextContent(archiveSha256);
    await page.getByCSS('[data-test-verify-passkey]').click();

    await expect
      .element(page.getByCSS('[data-test-verify-success]'))
      .toHaveTextContent('This operation is authorized. Cargo must still send it to the registry.');
    expect(callback).toHaveBeenCalledWith(callbackUrl);
  });

  test('shows callback failure and lets the user retry', async ({ worker }) => {
    installApiHandlers(worker);
    callback.mockRejectedValueOnce(new Error('connection refused')).mockImplementationOnce(async () => {});
    mockPasskey();

    await render(PageTestWrapper);
    await page.getByCSS('[data-test-verify-passkey]').click();

    await expect.element(page.getByCSS('[data-test-callback-error]')).toBeInTheDocument();
    await page.getByCSS('[data-test-retry-callback]').click();

    await expect.element(page.getByCSS('[data-test-verify-success]')).toBeInTheDocument();
    expect(callback).toHaveBeenCalledTimes(2);
  });

  test('denies a pending mutation without starting passkey verification', async ({ worker }) => {
    installApiHandlers(worker);
    let passkey = mockPasskey();

    await render(PageTestWrapper);
    await page.getByCSS('[data-test-deny-authorization]').click();

    await expect.element(page.getByCSS('[data-test-verify-denied]')).toBeInTheDocument();
    expect(passkey).not.toHaveBeenCalled();
    expect(callback).not.toHaveBeenCalled();
  });
});
