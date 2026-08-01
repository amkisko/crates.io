import { describe, expect, it, vi } from 'vitest';

import { deliverLocalhostCallback } from './localhost-callback';

const callbackUrl = 'http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef';

describe('deliverLocalhostCallback', () => {
  it('delivers the stored mutation-authorization wake-up URL unchanged', async () => {
    let listeners = new Map<string, EventListener>();
    let image = {
      addEventListener: (type: string, listener: EventListenerOrEventListenerObject) =>
        listeners.set(type, listener as EventListener),
      src: '',
    } as Pick<HTMLImageElement, 'addEventListener' | 'src'>;

    let delivery = deliverLocalhostCallback(callbackUrl, () => image);
    await vi.waitFor(() => expect(listeners.get('load')).toBeTypeOf('function'));
    listeners.get('load')!(new Event('load'));

    await expect(delivery).resolves.toBeUndefined();
    expect(image.src).toBe(callbackUrl);
  });

  it.each([
    'https://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef',
    'http://localhost:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef',
    'http://127.0.0.1:80/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef',
    'http://127.0.0.1:34567/other?state=0123456789abcdef0123456789abcdef',
    'http://127.0.0.1:34567/cargo/registry-authorization',
    'http://127.0.0.1:34567/cargo/registry-authorization?state=too-short',
    'http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef&extra=1',
    'http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef#fragment',
  ])('rejects an invalid callback URL: %s', async url => {
    let imageFactory = vi.fn();
    await expect(deliverLocalhostCallback(url, imageFactory)).rejects.toThrow('Invalid Cargo callback URL');
    expect(imageFactory).not.toHaveBeenCalled();
  });

  it('reports callback delivery failures', async () => {
    let listeners = new Map<string, EventListener>();
    let image = {
      addEventListener: (type: string, listener: EventListenerOrEventListenerObject) =>
        listeners.set(type, listener as EventListener),
      src: '',
    } as Pick<HTMLImageElement, 'addEventListener' | 'src'>;

    let delivery = deliverLocalhostCallback(callbackUrl, () => image);
    await vi.waitFor(() => expect(listeners.get('error')).toBeTypeOf('function'));
    listeners.get('error')!(new Event('error'));

    await expect(delivery).rejects.toThrow('Cargo callback failed');
  });
});
