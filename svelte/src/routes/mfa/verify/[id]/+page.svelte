<script lang="ts">
  import { page } from '$app/state';

  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import { getNotifications } from '$lib/notifications.svelte';

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
  let otp = $state<string | null>(null);
  let localhostCallbackUrl = $state<string | null>(null);
  let grantExpiresAt = $state<string | null>(null);
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
      otp = result.otp;
      localhostCallbackUrl = result.localhost_callback_url ?? null;
      grantExpiresAt = result.grant_expires_at ?? null;
      done = true;

      if (localhostCallbackUrl) {
        try {
          await fetch(localhostCallbackUrl, { mode: 'no-cors' });
        } catch {
          // Ignore; CLI can poll for acknowledgment instead.
        }
      }

      notifications.success('Acknowledged. You may return to the command line.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Verification failed.');
    } finally {
      busy = false;
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
      ...(options as PublicKeyCredentialRequestOptions),
      challenge: b64urlToBuffer(options.challenge as string),
      allowCredentials: ((options.allowCredentials as Array<Record<string, unknown>>) ?? []).map(cred => ({
        ...(cred as PublicKeyCredentialDescriptor),
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

  $effect(() => {
    if (challengeId) {
      loadMeta();
    }
  });
</script>

<PageTitle title="Authenticate with security device" />
<PageHeader title="Authenticate with security device" />

<main class="verify" data-test-mfa-verify>
  {#if loading}
    <LoadingSpinner />
  {:else if loadError}
    <p data-test-verify-error>{loadError}</p>
  {:else if done}
    <h2 data-test-verify-success>You are verified with a security device</h2>
    <p>You may close this window and return to the command line. The CLI can retry now.</p>
    {#if meta}
      <p>
        Operation <code data-test-operation-id>{meta.operation_id}</code>
        ({operationLabel(meta.operation, meta.crate_name)}).
      </p>
    {/if}
    {#if grantExpiresAt}
      <p>
        A scoped grant is active until {new Date(grantExpiresAt).toLocaleString()} for stock
        <code>cargo</code> retries.
      </p>
    {:else if otp}
      <p>
        One-time code for CLI clients (shown only when a localhost OTP callback was requested):
        <code data-test-otp>{otp}</code>
      </p>
    {/if}
  {:else if meta}
    <h2>Confirm {operationLabel(meta.operation, meta.crate_name)}</h2>
    <p>
      No crates.io sign-in is required. Use a registered passkey for this account. Your API token from
      <code>cargo login</code> already identified you.
    </p>
    <p class="meta">
      Operation id <code>{meta.operation_id}</code> · expires {new Date(meta.expires_at).toLocaleString()}
    </p>
    <button type="button" class="button" disabled={busy} onclick={verify} data-test-verify-passkey>
      {#if busy}
        <LoadingSpinner />
      {:else}
        Authenticate
      {/if}
    </button>
  {/if}
</main>

<style>
  .verify {
    max-width: 40rem;
    margin: 0 auto;
    padding: var(--space-m);
  }

  .meta {
    color: var(--grey600);
    font-size: 0.9rem;
  }
</style>
