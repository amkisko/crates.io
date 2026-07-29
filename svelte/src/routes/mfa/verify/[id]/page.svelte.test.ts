import type { SetupWorker } from 'msw/browser';

import { http, HttpResponse } from 'msw';
import { afterEach, beforeEach, describe, expect, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { page } from 'vitest/browser';

import { test } from '../../../../test/msw';
import PageTestWrapper from './PageTestWrapper.svelte';

const callback = vi.hoisted(() => vi.fn());

vi.mock('$app/state', () => ({
  page: { params: { id: 'mfa_test' } },
}));

vi.mock('./localhost-callback', () => ({
  deliverLocalhostCallback: callback,
}));

const callbackUrl = 'http://127.0.0.1:34567/?code=TestOtp1';

function installApiHandlers(worker: SetupWorker) {
  worker.use(
    http.get('/api/v1/mfa/challenges/mfa_test', () =>
      HttpResponse.json({
        operation_id: 'mfa_test',
        status: 'pending',
        acknowledged: false,
        operation: 'publish',
        crate_name: 'example',
        expires_at: '2099-01-01T00:00:00Z',
      }),
    ),
    http.post('/api/v1/mfa/challenges/mfa_test/start', () =>
      HttpResponse.json({
        public_key: {
          challenge: 'AQ',
          allowCredentials: [],
        },
      }),
    ),
    http.post('/api/v1/mfa/challenges/mfa_test/finish', () =>
      HttpResponse.json({
        otp: 'TestOtp1',
        localhost_callback_url: callbackUrl,
        grant_expires_at: null,
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

describe('/mfa/verify/[id]', () => {
  beforeEach(() => {
    callback.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('reports callback success only after Cargo receives the OTP', async ({ worker }) => {
    installApiHandlers(worker);
    callback.mockResolvedValue(undefined);
    mockPasskey();

    await render(PageTestWrapper);
    await page.getByCSS('[data-test-verify-passkey]').click();

    await expect.element(page.getByCSS('[data-test-verify-success]')).toBeInTheDocument();
    expect(callback).toHaveBeenCalledWith(callbackUrl);
  });

  test('shows callback failure and lets the user retry', async ({ worker }) => {
    installApiHandlers(worker);
    callback.mockRejectedValueOnce(new Error('connection refused')).mockResolvedValueOnce(undefined);
    mockPasskey();

    await render(PageTestWrapper);
    await page.getByCSS('[data-test-verify-passkey]').click();

    await expect.element(page.getByCSS('[data-test-callback-error]')).toBeInTheDocument();
    await page.getByCSS('[data-test-retry-callback]').click();

    await expect.element(page.getByCSS('[data-test-verify-success]')).toBeInTheDocument();
    expect(callback).toHaveBeenCalledTimes(2);
  });
});
