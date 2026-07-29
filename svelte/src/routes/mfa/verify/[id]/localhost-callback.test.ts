import { describe, expect, it, vi } from 'vitest';

import { deliverLocalhostCallback, recoverLocalhostCallbackUrl } from './localhost-callback';

describe('recoverLocalhostCallbackUrl', () => {
  it('recovers a lost finish response with the fragment-held secret', async () => {
    let fetchMock = vi.fn().mockResolvedValue(
      Response.json(
        { localhost_callback_url: 'http://127.0.0.1:34567/?code=TestOtp1' },
        {
          status: 200,
        },
      ),
    );

    await expect(recoverLocalhostCallbackUrl('mfa_test', 'callback-secret', fetchMock)).resolves.toBe(
      'http://127.0.0.1:34567/?code=TestOtp1',
    );
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/mfa/challenges/mfa_test/recover', {
      method: 'POST',
      headers: { 'Crates-MFA-Callback-Secret': 'callback-secret' },
    });
  });

  it('treats an already-consumed OTP as completed', async () => {
    let fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 400 }));
    await expect(recoverLocalhostCallbackUrl('mfa_test', 'callback-secret', fetchMock)).resolves.toBeNull();
  });

  it('reports recovery errors from the server', async () => {
    let fetchMock = vi.fn().mockResolvedValue(
      Response.json(
        { errors: [{ detail: 'Challenge not found or expired' }] },
        {
          status: 404,
        },
      ),
    );
    await expect(recoverLocalhostCallbackUrl('mfa_test', 'wrong-secret', fetchMock)).rejects.toThrow(
      'Challenge not found or expired',
    );
  });
});

describe('deliverLocalhostCallback', () => {
  it('delivers the OTP to an IPv4 loopback callback', async () => {
    let listeners = new Map<string, EventListener>();
    let image = {
      addEventListener: (type: string, listener: EventListenerOrEventListenerObject) =>
        listeners.set(type, listener as EventListener),
      src: '',
    } as Pick<HTMLImageElement, 'addEventListener' | 'src'>;

    let delivery = deliverLocalhostCallback('http://127.0.0.1:34567/?code=TestOtp1', () => image);
    await vi.waitFor(() => expect(listeners.get('load')).toBeTypeOf('function'));
    listeners.get('load')!(new Event('load'));

    await expect(delivery).resolves.toBeUndefined();
    expect(image.src).toBe('http://127.0.0.1:34567/?code=TestOtp1');
  });

  it.each([
    'https://127.0.0.1:34567/?code=TestOtp1',
    'http://localhost:34567/?code=TestOtp1',
    'http://127.0.0.1:80/?code=TestOtp1',
    'http://127.0.0.1:34567/other?code=TestOtp1',
    'http://127.0.0.1:34567/',
  ])('rejects an unsafe callback URL: %s', async callbackUrl => {
    let imageFactory = vi.fn();
    await expect(deliverLocalhostCallback(callbackUrl, imageFactory)).rejects.toThrow('Invalid Cargo callback URL');
    expect(imageFactory).not.toHaveBeenCalled();
  });

  it('reports callback delivery failures', async () => {
    let listeners = new Map<string, EventListener>();
    let image = {
      addEventListener: (type: string, listener: EventListenerOrEventListenerObject) =>
        listeners.set(type, listener as EventListener),
      src: '',
    } as Pick<HTMLImageElement, 'addEventListener' | 'src'>;

    let delivery = deliverLocalhostCallback('http://127.0.0.1:34567/?code=TestOtp1', () => image);
    await vi.waitFor(() => expect(listeners.get('error')).toBeTypeOf('function'));
    listeners.get('error')!(new Event('error'));

    await expect(delivery).rejects.toThrow('Cargo callback failed');
  });
});
