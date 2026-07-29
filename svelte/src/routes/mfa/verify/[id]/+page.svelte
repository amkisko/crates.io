<script lang="ts">
  import { page } from '$app/state';

  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import { getNotifications } from '$lib/notifications.svelte';
  import { deliverLocalhostCallback } from './localhost-callback';

  interface ChallengeMeta {
    operation_id: string;
    status: string;
    acknowledged: boolean;
    operation: string;
    crate_name: string | null;
    expires_at: string;
  }

  let notifications = getNotifications();

  let busy = $state(false);
  let loading = $state(true);
  let done = $state(false);
  let localhostCallbackUrl = $state<string | null>(null);
  let callbackDeliveryBusy = $state(false);
  let callbackDeliveryFailed = $state(false);
  let meta = $state<ChallengeMeta | null>(null);
  let loadError = $state<string | null>(null);

  let challengeId = $derived(page.params.id);

  async function loadMeta() {
    loading = true;
    loadError = null;
    try {
      let response = await fetch(`/api/v1/mfa/challenges/${challengeId}`);
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Challenge not found or expired');
      }
      meta = await response.json();
      if (meta?.acknowledged) {
        done = true;
      }
    } catch (error) {
      loadError = error instanceof Error ? error.message : 'Failed to load challenge';
      notifications.error(loadError);
    } finally {
      loading = false;
    }
  }

  async function verify() {
    if (!globalThis.PublicKeyCredential) {
      notifications.error('This browser does not support passkeys.');
      return;
    }

    busy = true;
    try {
      let start = await fetch(`/api/v1/mfa/challenges/${challengeId}/start`, {
        method: 'POST',
      });
      if (!start.ok) {
        let body = await start.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to start verification');
      }
      let { public_key } = await start.json();
      let credential = (await navigator.credentials.get({
        publicKey: revivePublicKeyRequest(public_key),
      })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('Passkey verification was cancelled');
      }

      let finish = await fetch(`/api/v1/mfa/challenges/${challengeId}/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serializeAssertion(credential) }),
      });
      if (!finish.ok) {
        let body = await finish.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Verification failed');
      }

      let result = await finish.json();
      localhostCallbackUrl = result.localhost_callback_url ?? null;
      done = true;

      if (localhostCallbackUrl && !(await sendLocalhostCallback())) {
        return;
      }

      notifications.success('Acknowledged. You may return to the command line.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Verification failed.');
    } finally {
      busy = false;
    }
  }

  async function sendLocalhostCallback() {
    if (!localhostCallbackUrl) return true;

    callbackDeliveryBusy = true;
    callbackDeliveryFailed = false;
    try {
      await deliverLocalhostCallback(localhostCallbackUrl);
      return true;
    } catch {
      callbackDeliveryFailed = true;
      notifications.error('Cargo could not be reached. Keep the command running and try again.');
      return false;
    } finally {
      callbackDeliveryBusy = false;
    }
  }

  function b64urlToBuffer(value: string): ArrayBuffer {
    let padded = value.replaceAll('-', '+').replaceAll('_', '/');
    while (padded.length % 4) padded += '=';
    let binary = atob(padded);
    let bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i)!;
    return bytes.buffer;
  }

  function bufferToB64url(buffer: ArrayBuffer): string {
    let bytes = new Uint8Array(buffer);
    let binary = '';
    for (let byte of bytes) binary += String.fromCodePoint(byte);
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll(/=+$/g, '');
  }

  function revivePublicKeyRequest(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
    return {
      ...(options as unknown as PublicKeyCredentialRequestOptions),
      challenge: b64urlToBuffer(options.challenge as string),
      allowCredentials: ((options.allowCredentials as Array<Record<string, unknown>>) ?? []).map(cred => ({
        ...(cred as unknown as PublicKeyCredentialDescriptor),
        id: b64urlToBuffer(cred.id as string),
      })),
    };
  }

  function serializeAssertion(credential: PublicKeyCredential) {
    let assertion = credential.response as AuthenticatorAssertionResponse;
    return {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToB64url(assertion.clientDataJSON),
        authenticatorData: bufferToB64url(assertion.authenticatorData),
        signature: bufferToB64url(assertion.signature),
        userHandle: assertion.userHandle ? bufferToB64url(assertion.userHandle) : null,
      },
    };
  }

  function operationLabel(operation: string, crateName: string | null) {
    if (crateName) {
      return `${operation} for ${crateName}`;
    }
    return operation;
  }

  let pageHeading = $derived.by(() => {
    if (done) {
      return callbackDeliveryFailed ? 'Cargo was not reached' : 'Passkey verified';
    }
    if (meta) {
      return `Confirm ${operationLabel(meta.operation, meta.crate_name)}`;
    }
    if (loadError) {
      return 'Verification failed';
    }
    return 'Confirm action';
  });

  $effect(() => {
    if (challengeId) {
      loadMeta();
    }
  });
</script>

<PageTitle title={pageHeading} />

<div class="content" data-test-mfa-verify>
  <h1>
    {pageHeading}
    {#if loading}
      <LoadingSpinner />
    {/if}
  </h1>

  {#if !loading && loadError}
    <p data-test-verify-error>{loadError}</p>
  {:else if !loading && done}
    {#if callbackDeliveryFailed}
      <p data-test-callback-error>Passkey verified, but Cargo could not be reached.</p>
      <p>Keep the Cargo command running, then retry the connection.</p>
      <div class="actions">
        <button
          type="button"
          class="button"
          disabled={callbackDeliveryBusy}
          onclick={sendLocalhostCallback}
          data-test-retry-callback
        >
          Retry Cargo connection
          {#if callbackDeliveryBusy}
            <LoadingSpinner theme="light" class="spinner" />
          {/if}
        </button>
      </div>
    {:else}
      <p data-test-verify-success>You may close this window and return to the command line.</p>
    {/if}
  {:else if !loading && meta}
    <p>Expires {new Date(meta.expires_at).toLocaleString()}</p>
    <div class="actions">
      <button type="button" class="button" disabled={busy} onclick={verify} data-test-verify-passkey>
        Verify with passkey
        {#if busy}
          <LoadingSpinner theme="light" class="spinner" />
        {/if}
      </button>
    </div>
  {/if}
</div>

<style>
  .content {
    max-width: 600px;
    margin: var(--space-xl) auto;

    h1 {
      display: flex;
      align-items: baseline;
      gap: var(--space-2xs);
      margin-top: 0;
    }
  }

  .actions {
    display: flex;
    justify-content: center;
    margin-top: var(--space-m);
  }

  .actions :global(.spinner) {
    margin-left: var(--space-2xs);
  }
</style>
