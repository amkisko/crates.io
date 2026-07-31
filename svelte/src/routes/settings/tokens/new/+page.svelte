<script lang="ts">
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { createClient } from '@crates-io/api-client';

  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import SettingsPage from '$lib/components/SettingsPage.svelte';
  import TokenDetailsFields from '$lib/components/TokenDetailsFields.svelte';
  import { getNotifications } from '$lib/notifications.svelte';
  import { getSession } from '$lib/utils/session.svelte';
  import { TokenFormState } from '$lib/utils/token-form.svelte';
  import { revivePublicKeyRequest, serializeAssertion } from '$lib/utils/webauthn';
  import { getTokenPageState } from '../+layout.svelte';

  let session = getSession();
  let notifications = getNotifications();
  let client = createClient({ fetch });
  let id = $props.id();
  let { data } = $props();
  let tokenPageState = getTokenPageState();
  let apiMfaEnabled = $derived(session.currentUser?.api_mfa_enabled ?? false);

  // svelte-ignore state_referenced_locally
  let existingToken = data.existingToken;

  let tokenForm = new TokenFormState({
    name: existingToken?.name,
    endpointScopes: existingToken?.endpoint_scopes ?? undefined,
    crateScopes: existingToken?.crate_scopes ?? undefined,
  });
  let isSaving = $state(false);

  async function assertPasskeyIfNeeded(): Promise<unknown | undefined> {
    if (!apiMfaEnabled) return undefined;

    if (!globalThis.PublicKeyCredential) {
      throw new Error('This browser does not support passkeys.');
    }

    let start = await fetch('/api/v1/me/mfa/authorize/start', { method: 'POST' });
    if (!start.ok) {
      let body = await start.json().catch(() => null);
      throw new Error(body?.errors?.[0]?.detail ?? 'Failed to start passkey verification');
    }
    let { public_key } = await start.json();
    let credential = (await navigator.credentials.get({
      publicKey: revivePublicKeyRequest(public_key),
    })) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error('Passkey verification was cancelled');
    }
    return serializeAssertion(credential);
  }

  async function handleSubmit(event: SubmitEvent): Promise<void> {
    event.preventDefault();

    if (!tokenForm.validate()) return;

    isSaving = true;

    let crateScopePatterns: string[] | null = tokenForm.crateScopes.map(it => it.pattern);
    if (crateScopePatterns.length === 0) {
      crateScopePatterns = null;
    }

    try {
      let credential = await assertPasskeyIfNeeded();

      let result = await client.PUT('/api/v1/me/tokens', {
        body: {
          api_token: {
            name: tokenForm.name,
            endpoint_scopes: tokenForm.scopes,
            crate_scopes: crateScopePatterns,
            expired_at: tokenForm.expiryDate?.toISOString() ?? null,
          },
          credential,
        } as never,
      });

      if (result.error) {
        throw new Error('Failed to create API token');
      }

      let apiToken = result.data.api_token;
      tokenPageState.pendingToken = { id: apiToken.id, token: apiToken.token };

      await goto(resolve('/settings/tokens'));
    } catch (error) {
      notifications.error(
        error instanceof Error
          ? error.message
          : 'An error has occurred while generating your API token. Please try again later!',
      );
    } finally {
      isSaving = false;
    }
  }
</script>

<PageTitle title="Settings" />

<PageHeader title="Account Settings" />

<SettingsPage>
  <h2>New API Token</h2>

  {#if apiMfaEnabled}
    <p class="explainer" data-test-new-token-mfa-note>
      API MFA is enabled. Creating this token will ask for a passkey confirmation.
    </p>
  {/if}

  <form class="form" onsubmit={handleSubmit}>
    <TokenDetailsFields {id} state={tokenForm} disabled={isSaving} autofocus />

    <div class="buttons">
      <button type="submit" class="generate-button button button--small" disabled={isSaving} data-test-generate>
        Generate Token

        {#if isSaving}
          <LoadingSpinner theme="light" class="spinner" />
        {/if}
      </button>

      <a href={resolve('/settings/tokens')} class="cancel-button button button--tan button--small" data-test-cancel>
        Cancel
      </a>
    </div>
  </form>
</SettingsPage>

<style>
  .buttons {
    position: relative;
    display: flex;
    gap: var(--space-2xs);
    flex-wrap: wrap;
    margin: var(--space-m) 0;
  }

  .explainer {
    margin: var(--space-s) 0;
    line-height: 1.5;
  }

  .generate-button,
  .cancel-button {
    border-radius: 4px;
  }

  .generate-button :global(.spinner) {
    margin-left: var(--space-2xs);
  }
</style>
