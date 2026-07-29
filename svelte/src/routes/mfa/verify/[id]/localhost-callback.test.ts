import { describe, expect, it, vi } from 'vitest';

import { deliverLocalhostCallback } from './localhost-callback';

describe('deliverLocalhostCallback', () => {
  it('delivers the OTP to an IPv4 loopback callback', async () => {
    let fetcher = vi.fn().mockResolvedValue(new Response());

    await deliverLocalhostCallback('http://127.0.0.1:34567/?code=TestOtp1', fetcher);

    expect(fetcher).toHaveBeenCalledWith(new URL('http://127.0.0.1:34567/?code=TestOtp1'), {
      mode: 'no-cors',
    });
  });

  it.each([
    'https://127.0.0.1:34567/?code=TestOtp1',
    'http://localhost:34567/?code=TestOtp1',
    'http://127.0.0.1:80/?code=TestOtp1',
    'http://127.0.0.1:34567/other?code=TestOtp1',
    'http://127.0.0.1:34567/',
  ])('rejects an unsafe callback URL: %s', async callbackUrl => {
    let fetcher = vi.fn();

    await expect(deliverLocalhostCallback(callbackUrl, fetcher)).rejects.toThrow('Invalid Cargo callback URL');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('falls back to a verifiable image beacon when fetch is blocked', async () => {
    let fetcher = vi.fn().mockRejectedValue(new TypeError('Blocked by CSP'));
    let image = { onload: null, onerror: null, src: '' } as Pick<HTMLImageElement, 'onload' | 'onerror' | 'src'>;

    let delivery = deliverLocalhostCallback('http://127.0.0.1:34567/?code=TestOtp1', fetcher, () => image);
    await vi.waitFor(() => expect(image.onload).toBeTypeOf('function'));
    image.onload!.call(image as unknown as GlobalEventHandlers, new Event('load'));

    await expect(delivery).resolves.toBeUndefined();
    expect(image.src).toBe('http://127.0.0.1:34567/?code=TestOtp1');
  });

  it('reports callback delivery failures', async () => {
    let fetcher = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    let image = { onload: null, onerror: null, src: '' } as Pick<HTMLImageElement, 'onload' | 'onerror' | 'src'>;

    let delivery = deliverLocalhostCallback('http://127.0.0.1:34567/?code=TestOtp1', fetcher, () => image);
    await vi.waitFor(() => expect(image.onerror).toBeTypeOf('function'));
    image.onerror!.call(image as unknown as GlobalEventHandlers, new Event('error'));

    await expect(delivery).rejects.toThrow('Cargo callback failed');
  });
});
