<script lang="ts">
  import type { operations } from '@crates-io/api-client';

  import { page } from '$app/state';
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

  type CliLoginMeta = operations['get_cli_login_meta']['responses'][200]['content']['application/json'];

  let session = getSession();
  let notifications = getNotifications();
  let client = createClient({ fetch });
  let id = $props.id();

  let loginId = $derived(page.params.id);

  let meta = $state<CliLoginMeta | null>(null);
  let loading = $state(true);
  let isSaving = $state(false);
  let done = $state(false);

  let tokenForm = new TokenFormState({
    name: 'cargo login',
    endpointScopes: ['publish-update', 'publish-new', 'yank'],
  });
  let confirmationCode = $state('');
  let confirmationCodeInvalid = $state(false);
  let emailOtp = $state('');
  let emailOtpHint = $state<string | null>(null);

  function validate(): boolean {
    let tokenFieldsValid = tokenForm.validate();
    confirmationCodeInvalid = confirmationCode.replaceAll(/[^A-Za-z0-9]/g, '').length < 8;
    return tokenFieldsValid && !confirmationCodeInvalid;
  }

  async function loadMeta() {
    let id = loginId;
    if (!id) return;

    loading = true;
    try {
      let response = await client.GET('/api/v1/cli_login/{id}/meta', {
        params: { path: { id } },
      });
      if (!response.data) {
        throw new Error('CLI login session not found or expired');
      }
      meta = response.data;
      if (meta?.status && meta.status !== 'pending') {
        done = true;
      }
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to load CLI login session');
    } finally {
      loading = false;
    }
  }

  async function sendEmailOtp() {
    let response = await fetch('/api/v1/me/mfa/email_codes', { method: 'POST' });
    if (!response.ok) {
      let body = await response.json().catch(() => null);
      throw new Error(body?.errors?.[0]?.detail ?? 'Failed to send email code');
    }
    let body = await response.json();
    emailOtpHint = body.sent_to_hint;
    notifications.success(`Verification code sent to ${body.sent_to_hint}.`);
  }

  async function assertPasskeyIfNeeded(): Promise<unknown | undefined> {
    if (!meta?.mfa_required || meta.mfa_email_otp_allowed) return undefined;

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

    if (!validate()) return;

    isSaving = true;
    try {
      let crateScopePatterns: string[] | null = tokenForm.crateScopes.map(it => it.pattern);
      if (crateScopePatterns.length === 0) {
        crateScopePatterns = null;
      }

      let credential = await assertPasskeyIfNeeded();
      let email_code = meta?.mfa_required && meta.mfa_email_otp_allowed ? emailOtp.trim() || undefined : undefined;
      if (meta?.mfa_required && meta.mfa_email_otp_allowed && !email_code) {
        throw new Error('Request an email verification code, then enter it to approve this login.');
      }

      let response = await fetch(`/api/v1/cli_login/${loginId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: tokenForm.name,
          endpoint_scopes: tokenForm.scopes,
          crate_scopes: crateScopePatterns,
          expired_at: tokenForm.expiryDate?.toISOString() ?? null,
          confirmation_code: confirmationCode,
          credential,
          email_code,
        }),
      });

      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to approve CLI login');
      }

      let result = await response.json();
      done = true;

      notifications.success('Token issued. Return to the terminal — the token is not shown here.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to approve CLI login');
    } finally {
      isSaving = false;
    }
  }

  $effect(() => {
    if (session.currentUser && loginId) {
      loadMeta();
    }
  });
</script>

<PageTitle title="Settings" />

<PageHeader title="Account Settings" />

<SettingsPage>
  <h2 data-test-cli-login-heading>Authorize cargo login</h2>

  {#if !session.currentUser}
    <p class="explainer" data-test-cli-login-signin>
      Sign in to approve this cargo login request and choose token scopes. The API token will be delivered to your
      terminal — it will not be shown on this page.
    </p>
    <button type="button" class="button" data-test-cli-login-signin-button onclick={() => session.login()}>
      Sign in with GitHub
    </button>
  {:else if loading}
    <LoadingSpinner />
  {:else if done}
    <p class="success" data-test-cli-login-success>
      Authorization complete. Return to the terminal to finish <code>cargo login</code>. The token was not shown in the
      browser and cannot be copied from this page.
    </p>
  {:else if meta}
    <p class="explainer" data-test-cli-login-warning>
      Only continue if you just ran <code>cargo login</code> yourself. Approving a link you did not start can give someone
      else an API token for your account.
    </p>

    <p class="explainer">
      Choose a name, expiration, and scopes for the API token that cargo will store locally. The plaintext token is
      never displayed here.
    </p>

    {#if meta.client_ip}
      <p class="explainer" data-test-cli-login-client-ip>
        This login was started from IP <code>{meta.client_ip}</code>. Decline if that is unexpected.
      </p>
    {/if}

    {#if meta.mfa_required && meta.mfa_email_otp_allowed}
      <p class="explainer" data-test-cli-login-mfa-note>
        API MFA is enabled and no passkeys are registered. Approving this login requires an email verification code
        (same recovery path as Settings → API MFA).
      </p>
    {:else if meta.mfa_required}
      <p class="explainer" data-test-cli-login-mfa-note>
        API MFA is enabled on your account. Approving this login will ask for a passkey confirmation.
      </p>
    {/if}

    <form class="form" onsubmit={handleSubmit} data-test-cli-login-form>
      {#if meta.mfa_required && meta.mfa_email_otp_allowed}
        <div class="form-group" data-test-cli-login-email-otp-group>
          <label for="{id}-email-otp" class="form-group-name">Email verification code</label>
          <p class="explainer">
            Request a code to your verified email, then enter it here.
            {#if emailOtpHint}
              Sent to <code>{emailOtpHint}</code>.
            {/if}
          </p>
          <div class="email-otp-row">
            <input
              id="{id}-email-otp"
              type="text"
              bind:value={emailOtp}
              disabled={isSaving}
              autocomplete="one-time-code"
              inputmode="numeric"
              spellcheck="false"
              class="name-input base-input"
              data-test-cli-login-email-otp
              placeholder="Email code"
            />
            <button
              type="button"
              class="button button--small"
              data-test-cli-login-send-email-otp
              disabled={isSaving}
              onclick={() => sendEmailOtp().catch(error => notifications.error(error.message))}
            >
              Send code
            </button>
          </div>
        </div>
      {/if}

      <div class="form-group" data-test-confirmation-code-group>
        <label for="{id}-confirmation-code" class="form-group-name">Confirmation code</label>
        <p class="explainer">
          Enter the code shown in your terminal after <code>cargo login</code>. It is not displayed on this page.
        </p>

        <input
          id="{id}-confirmation-code"
          type="text"
          bind:value={confirmationCode}
          disabled={isSaving}
          autocomplete="off"
          spellcheck="false"
          autocapitalize="characters"
          aria-required="true"
          aria-invalid={confirmationCodeInvalid}
          class="name-input base-input"
          data-test-confirmation-code
          placeholder="XXXX-XXXX"
          oninput={() => (confirmationCodeInvalid = false)}
        />

        {#if confirmationCodeInvalid}
          <div class="form-group-error" data-test-error>Please enter the confirmation code from your terminal.</div>
        {/if}
      </div>

      <TokenDetailsFields {id} state={tokenForm} disabled={isSaving} />

      <div class="buttons">
        <button type="submit" class="generate-button button button--small" disabled={isSaving} data-test-approve>
          Authorize and create token

          {#if isSaving}
            <LoadingSpinner theme="light" class="spinner" />
          {/if}
        </button>
      </div>
    </form>
  {/if}
</SettingsPage>

<style>
  .explainer,
  .success {
    margin: var(--space-s) 0;
    line-height: 1.5;
  }

  .success {
    padding: var(--space-s);
    border: 1px solid var(--gray-border);
    border-radius: var(--space-3xs);
    background: light-dark(#f4fff4, #0f1a0f);
  }

  .form-group,
  .buttons {
    position: relative;
    margin: var(--space-m) 0;
  }

  .email-otp-row,
  .buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2xs);
    align-items: center;
  }

  .name-input {
    max-width: 440px;
    width: 100%;
  }

  .generate-button {
    border-radius: 4px;
  }

  .generate-button :global(.spinner) {
    margin-left: var(--space-2xs);
  }
</style>
