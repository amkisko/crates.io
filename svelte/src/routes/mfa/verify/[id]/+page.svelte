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
    operation_summary: string;
    crate_name: string | null;
    expires_at: string;
    localhost_port: number | null;
  }

  let notifications = getNotifications();

  let busy = $state(false);
  let loading = $state(true);
  let done = $state(false);
  let localhostCallbackUrl = $state<string | null>(null);
  let callbackDeliveryBusy = $state(false);
  let callbackDeliveryFailed = $state(false);
  let missingCallbackSecret = $state(false);
  let meta = $state<ChallengeMeta | null>(null);
  let loadError = $state<string | null>(null);

  let challengeId = $derived(page.params.id);
  let callbackSecret = $derived(new URLSearchParams(page.url.hash.slice(1)).get('callback_secret'));

  async function loadMeta() {
    loading = true;
    loadError = null;
    missingCallbackSecret = false;
    try {
      let response = await fetch(`/api/v1/mfa/challenges/${challengeId}`);
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Challenge not found or expired');
      }
      meta = await response.json();
      if (meta?.acknowledged) {
        done = true;
        if (meta.localhost_port && callbackSecret) {
          try {
            await recoverLocalhostCallback();
          } catch (error) {
            callbackDeliveryFailed = true;
            notifications.error(error instanceof Error ? error.message : 'Failed to recover Cargo callback.');
          }
        } else if (meta.localhost_port && !callbackSecret) {
          missingCallbackSecret = true;
        }
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

      let headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (callbackSecret) headers['Crates-MFA-Callback-Secret'] = callbackSecret;
      let finish = await fetch(`/api/v1/mfa/challenges/${challengeId}/finish`, {
        method: 'POST',
        headers,
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

  async function recoverLocalhostCallback() {
    let recovery = await fetch(`/api/v1/mfa/challenges/${challengeId}/recover`, {
      method: 'POST',
      headers: { 'Crates-MFA-Callback-Secret': callbackSecret! },
    });
    if (!recovery.ok) {
      // A consumed OTP means Cargo already completed the original mutation.
      if (recovery.status === 400) return;
      let body = await recovery.json().catch(() => null);
      throw new Error(body?.errors?.[0]?.detail ?? 'Failed to recover Cargo callback');
    }
    let result = await recovery.json();
    localhostCallbackUrl = result.localhost_callback_url;
    await sendLocalhostCallback();
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

  function confirmHeading(challenge: ChallengeMeta): string {
    let crateName = challenge.crate_name;
    switch (challenge.operation) {
      case 'publish':
        return crateName ? `Confirm publish ${crateName}` : 'Confirm publish';
      case 'yank':
        return crateName ? `Confirm yank ${crateName}` : 'Confirm yank';
      case 'unyank':
        return crateName ? `Confirm unyank ${crateName}` : 'Confirm unyank';
      case 'change-owners':
        return crateName ? `Confirm owner change for ${crateName}` : 'Confirm owner change';
      case 'delete-crate':
        return crateName ? `Confirm delete ${crateName}` : 'Confirm delete';
      case 'change-trustpub-only':
      case 'change-trusted-publishing':
        return crateName ? `Confirm Trusted Publishing change for ${crateName}` : 'Confirm Trusted Publishing change';
      case 'accept-owner-invite':
        return crateName ? `Confirm owner invitation for ${crateName}` : 'Confirm owner invitation';
      case 'manual':
        return 'Confirm API MFA';
      default:
        return crateName ? `Confirm action for ${crateName}` : 'Confirm action';
    }
  }

  let pageHeading = $derived.by(() => {
    if (done) {
      return callbackDeliveryFailed ? 'Cargo was not reached' : 'Passkey verified';
    }
    if (loadError) {
      return 'Verification failed';
    }
    if (meta) {
      return confirmHeading(meta);
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

<div class="content" data-test-mfa-verify aria-busy={loading} aria-labelledby="mfa-verify-heading">
  <h1 id="mfa-verify-heading">{pageHeading}</h1>

  {#if loading}
    <LoadingSpinner />
  {:else if loadError}
    <p role="alert" data-test-verify-error>{loadError}</p>
  {:else if done}
    {#if meta}
      <p class="summary" data-test-operation-summary>
        Confirmed {meta.operation_summary[0].toLocaleLowerCase() + meta.operation_summary.slice(1)}
      </p>
    {/if}
    {#if callbackDeliveryFailed}
      <div role="alert" data-test-callback-error>
        <p>Passkey verified, but Cargo could not be reached.</p>
        <p>Keep the Cargo command running, then retry the connection.</p>
      </div>
      <div class="actions">
        <button
          type="button"
          class="button"
          disabled={callbackDeliveryBusy || !localhostCallbackUrl}
          aria-busy={callbackDeliveryBusy}
          onclick={sendLocalhostCallback}
          data-test-retry-callback
        >
          Retry Cargo connection
          {#if callbackDeliveryBusy}
            <LoadingSpinner theme="light" class="spinner" label={null} />
          {/if}
        </button>
      </div>
    {:else if missingCallbackSecret}
      <p role="status" data-test-missing-callback-secret>
        Reopen the verification link from your terminal to finish connecting to Cargo.
      </p>
    {:else}
      <p role="status" data-test-verify-success>You may close this window and return to the command line.</p>
    {/if}
  {:else if meta}
    <p class="summary" data-test-operation-summary>{meta.operation_summary}</p>
    <p class="expiry">
      Expires <time datetime={meta.expires_at}>{new Date(meta.expires_at).toLocaleString()}</time>
    </p>
    <div class="actions">
      <button type="button" class="button" disabled={busy} aria-busy={busy} onclick={verify} data-test-verify-passkey>
        Verify with passkey
        {#if busy}
          <LoadingSpinner theme="light" class="spinner" label={null} />
        {/if}
      </button>
    </div>
  {/if}
</div>

<style>
  .content {
    max-width: 600px;
    margin: var(--space-xl) auto;
    padding-inline: var(--space-s);
    box-sizing: border-box;
    overflow-wrap: anywhere;

    h1 {
      margin-top: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
  }

  .summary {
    margin: 0 0 var(--space-2xs);
    color: var(--grey600);
  }

  .expiry {
    margin: 0;
    color: var(--grey600);
    font-size: 0.9rem;
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
