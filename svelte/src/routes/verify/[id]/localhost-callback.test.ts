import { describe, expect, it, vi } from 'vitest';

import { addLocalhostCallbackState, deliverLocalhostCallback, recoverLocalhostCallbackUrl } from './localhost-callback';

describe('addLocalhostCallbackState', () => {
  it('constructs callback state without a registry round trip', () => {
    expect(addLocalhostCallbackState('http://127.0.0.1:34567/?code=TestOtp1', 'callback-secret')).toBe(
      'http://127.0.0.1:34567/?code=TestOtp1&state=callback-secret',
    );
  });

  it('constructs the mutation-authorization wake-up URL', () => {
    expect(addLocalhostCallbackState('http://127.0.0.1:34567/cargo/registry-authorization', 'callback-state')).toBe(
      'http://127.0.0.1:34567/cargo/registry-authorization?state=callback-state',
    );
  });

  it.each([
    'https://127.0.0.1:34567/?code=TestOtp1',
    'http://localhost:34567/?code=TestOtp1',
    'http://127.0.0.1:80/?code=TestOtp1',
    'http://127.0.0.1:34567/other?code=TestOtp1',
    'http://127.0.0.1:34567/',
    'http://127.0.0.1:34567/?code=TestOtp1&state=server-state',
  ])('rejects an unsafe callback URL: %s', callbackUrl => {
    expect(() => addLocalhostCallbackState(callbackUrl, 'callback-secret')).toThrow('Invalid Cargo callback URL');
  });
});

describe('recoverLocalhostCallbackUrl', () => {
  it('recovers a lost finish response with the fragment-held secret', async () => {
    let fetchMock = vi.fn().mockResolvedValue(
      Response.json(
        {
          localhost_callback_url: 'http://127.0.0.1:34567/?code=TestOtp1',
        },
        {
          status: 200,
        },
      ),
    );

    await expect(recoverLocalhostCallbackUrl('stp_test', 'callback-secret', fetchMock)).resolves.toBe(
      'http://127.0.0.1:34567/?code=TestOtp1&state=callback-secret',
    );
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/challenges/stp_test/recover', {
      method: 'POST',
      headers: { 'Cargo-Step-Up-Callback-Secret': 'callback-secret' },
    });
  });

  it('treats an already-consumed OTP as completed', async () => {
    let fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 400 }));
    await expect(recoverLocalhostCallbackUrl('stp_test', 'callback-secret', fetchMock)).resolves.toBeNull();
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
    await expect(recoverLocalhostCallbackUrl('stp_test', 'wrong-secret', fetchMock)).rejects.toThrow(
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

    let delivery = deliverLocalhostCallback(
      'http://127.0.0.1:34567/?code=TestOtp1&state=0123456789abcdef0123456789abcdef',
      () => image,
    );
    await vi.waitFor(() => expect(listeners.get('load')).toBeTypeOf('function'));
    listeners.get('load')!(new Event('load'));

    await expect(delivery).resolves.toBeUndefined();
    expect(image.src).toBe('http://127.0.0.1:34567/?code=TestOtp1&state=0123456789abcdef0123456789abcdef');
  });

  it('delivers a mutation-authorization wake-up without an OTP', async () => {
    let listeners = new Map<string, EventListener>();
    let image = {
      addEventListener: (type: string, listener: EventListenerOrEventListenerObject) =>
        listeners.set(type, listener as EventListener),
      src: '',
    } as Pick<HTMLImageElement, 'addEventListener' | 'src'>;

    let callbackUrl = 'http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef';
    let delivery = deliverLocalhostCallback(callbackUrl, () => image);
    await vi.waitFor(() => expect(listeners.get('load')).toBeTypeOf('function'));
    listeners.get('load')!(new Event('load'));

    await expect(delivery).resolves.toBeUndefined();
    expect(image.src).toBe(callbackUrl);
  });

  it.each([
    'https://127.0.0.1:34567/?code=TestOtp1',
    'http://localhost:34567/?code=TestOtp1',
    'http://127.0.0.1:80/?code=TestOtp1',
    'http://127.0.0.1:34567/other?code=TestOtp1',
    'http://127.0.0.1:34567/',
    'http://127.0.0.1:34567/?code=TestOtp1',
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

    let delivery = deliverLocalhostCallback(
      'http://127.0.0.1:34567/?code=TestOtp1&state=0123456789abcdef0123456789abcdef',
      () => image,
    );
    await vi.waitFor(() => expect(listeners.get('error')).toBeTypeOf('function'));
    listeners.get('error')!(new Event('error'));

    await expect(delivery).rejects.toThrow('Cargo callback failed');
  });
});
