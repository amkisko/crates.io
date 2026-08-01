<script lang="ts">
  import type { operations } from '@crates-io/api-client';

  import { page } from '$app/state';
  import { createClient } from '@crates-io/api-client';

  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import { getNotifications } from '$lib/notifications.svelte';
  import { revivePublicKeyRequest, serializeAssertion } from '$lib/utils/webauthn';
  import { deliverLocalhostCallback } from './localhost-callback';

  type ChallengeMeta = operations['get_api_mfa_challenge']['responses'][200]['content']['application/json'];

  let notifications = getNotifications();
  let client = createClient({ fetch });

  let busy = $state(false);
  let loading = $state(true);
  let done = $state(false);
  let denied = $state(false);
  let localhostCallbackUrl = $state<string | null>(null);
  let callbackDeliveryBusy = $state(false);
  let callbackDeliveryFailed = $state(false);
  let meta = $state<ChallengeMeta | null>(null);
  let loadError = $state<string | null>(null);

  let challengeId = $derived(page.params.id);
  async function loadMeta() {
    let id = challengeId;
    if (!id) return;

    loading = true;
    loadError = null;
    try {
      let response = await client.GET('/api/v1/auth/challenges/{id}', {
        params: { path: { id } },
      });
      if (!response.data) {
        throw new Error('Challenge not found or expired');
      }
      meta = response.data;
      if (meta?.status === 'denied') {
        denied = true;
      } else if (meta?.acknowledged) {
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
      let start = await fetch(`/api/v1/auth/challenges/${challengeId}/start`, {
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

      let finish = await fetch(`/api/v1/auth/challenges/${challengeId}/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serializeAssertion(credential) }),
      });
      if (!finish.ok) {
        let body = await finish.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Verification failed');
      }

      let result = await finish.json();
      localhostCallbackUrl = result.callback_url ?? null;
      done = true;

      if (localhostCallbackUrl && !(await sendLocalhostCallback())) {
        return;
      }

      notifications.success('Operation authorized. Cargo may continue.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Verification failed.');
    } finally {
      busy = false;
    }
  }

  async function deny() {
    busy = true;
    try {
      let response = await fetch(`/api/v1/auth/challenges/${challengeId}/deny`, {
        method: 'POST',
      });
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to deny authorization');
      }
      denied = true;
      notifications.success('Authorization denied. You may return to the command line.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to deny authorization.');
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

  function confirmHeading(challenge: ChallengeMeta): string {
    let crateName = challenge.crate_name;
    switch (challenge.operation) {
      case 'publish':
        return crateName ? `Authorize publishing ${crateName}` : 'Authorize publishing';
      case 'yank':
        return crateName ? `Authorize yanking ${crateName}` : 'Authorize yanking';
      case 'unyank':
        return crateName ? `Authorize unyanking ${crateName}` : 'Authorize unyanking';
      case 'owners':
        return crateName ? `Authorize owner change for ${crateName}` : 'Authorize owner change';
      default:
        return crateName ? `Authorize action for ${crateName}` : 'Authorize action';
    }
  }

  let pageHeading = $derived.by(() => {
    if (denied) {
      return 'Authorization denied';
    } else if (done) {
      return callbackDeliveryFailed ? 'Cargo was not reached' : 'Operation authorized';
    }
    if (loadError) {
      return 'Verification failed';
    }
    if (meta) {
      return confirmHeading(meta);
    }
    return 'Authorize action';
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
  {:else if denied}
    <p role="status" data-test-verify-denied>This operation will not be authorized. You may close this window.</p>
  {:else if done}
    {#if meta}
      <p class="summary" data-test-operation-summary>
        Authorized: {meta.operation_summary}
      </p>
      {#if meta.archive_sha256}
        <p class="archive-digest" data-test-archive-digest>
          Archive SHA-256: <code>{meta.archive_sha256}</code>
        </p>
      {/if}
    {/if}
    {#if callbackDeliveryFailed}
      <div role="alert" data-test-callback-error>
        <p>The operation is authorized, but Cargo could not be reached.</p>
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
    {:else}
      <p role="status" data-test-verify-success>
        This operation is authorized. Cargo must still send it to the registry. You may close this window.
      </p>
    {/if}
  {:else if meta}
    <p class="summary" data-test-operation-summary>{meta.operation_summary}</p>
    {#if meta.archive_sha256}
      <p class="archive-digest" data-test-archive-digest>
        Archive SHA-256: <code>{meta.archive_sha256}</code>
      </p>
    {/if}
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
      <button type="button" class="button button--red" disabled={busy} onclick={deny} data-test-deny-authorization>
        Deny
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

  .archive-digest {
    margin: 0 0 var(--space-2xs);

    code {
      overflow-wrap: anywhere;
    }
  }

  .expiry {
    margin: 0;
    color: var(--grey600);
    font-size: 0.9rem;
  }

  .actions {
    display: flex;
    gap: var(--space-s);
    justify-content: center;
    margin-top: var(--space-m);
  }

  .actions :global(.spinner) {
    margin-left: var(--space-2xs);
  }
</style>
