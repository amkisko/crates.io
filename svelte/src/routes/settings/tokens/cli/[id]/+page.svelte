<script lang="ts">
  import { page } from '$app/state';

  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import PatternDescription from '$lib/components/PatternDescription.svelte';
  import SettingsPage from '$lib/components/SettingsPage.svelte';
  import { getNotifications } from '$lib/notifications.svelte';
  import { getSession } from '$lib/utils/session.svelte';
  import { scopeDescription } from '$lib/utils/token-scopes';

  const ENDPOINT_SCOPES = ['change-owners', 'publish-new', 'publish-update', 'trusted-publishing', 'yank'];

  interface CliLoginMeta {
    login_id: string;
    status: string;
    expires_at: string;
    localhost_port: number | null;
    client_ip?: string | null;
    mfa_required: boolean;
    mfa_email_otp_allowed: boolean;
  }

  let session = getSession();
  let notifications = getNotifications();
  let id = $props.id();

  let loginId = $derived(page.params.id);

  class CratePattern {
    pattern = $state('');
    showAsInvalid = $state(false);

    constructor(pattern: string) {
      this.pattern = pattern;
    }

    get isValid(): boolean {
      return isValidPattern(this.pattern);
    }
  }

  function isValidPattern(pattern: string): boolean {
    if (!pattern) return false;
    if (pattern === '*') return true;

    if (pattern.endsWith('*')) {
      pattern = pattern.slice(0, -1);
    }

    return isValidIdent(pattern);
  }

  function isValidIdent(pattern: string): boolean {
    return (
      [...pattern].every(c => isAsciiAlphanumeric(c) || c === '_' || c === '-') &&
      pattern[0] !== '_' &&
      pattern[0] !== '-'
    );
  }

  function isAsciiAlphanumeric(c: string): boolean {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  }

  let meta = $state<CliLoginMeta | null>(null);
  let loading = $state(true);
  let isSaving = $state(false);
  let done = $state(false);

  let name = $state('cargo login');
  let nameInvalid = $state(false);
  let confirmationCode = $state('');
  let confirmationCodeInvalid = $state(false);
  let emailOtp = $state('');
  let emailOtpHint = $state<string | null>(null);
  let expirySelection = $state('90');
  let expiryDateInput = $state('');
  let expiryDateInvalid = $state(false);
  let scopes = $state<string[]>(['publish-update', 'publish-new', 'yank']);
  let scopesInvalid = $state(false);
  let crateScopes = $state<CratePattern[]>([]);

  let today = $derived(new Date().toISOString().slice(0, 10));

  let expiryDate = $derived.by(() => {
    if (expirySelection === 'none') return null;

    let now = new Date();

    if (expirySelection === 'custom') {
      if (!expiryDateInput) return null;

      let timeSuffix = now.toISOString().slice(10);
      return new Date(expiryDateInput + timeSuffix);
    }

    return new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() + Number(expirySelection),
      now.getHours(),
      now.getMinutes(),
      now.getSeconds(),
    );
  });

  let expiryDescription = $derived(
    expirySelection === 'none'
      ? 'The token will never expire'
      : `The token will expire on ${expiryDate?.toLocaleDateString(undefined, { dateStyle: 'long' })}`,
  );

  function toggleScope(scope: string): void {
    scopes = scopes.includes(scope) ? scopes.filter(it => it !== scope) : [...scopes, scope];
    scopesInvalid = false;
  }

  function updateExpirySelection(event: Event): void {
    expiryDateInput = expiryDate?.toISOString().slice(0, 10) ?? '';
    expirySelection = (event.target as HTMLSelectElement).value;
  }

  function addCratePattern(): void {
    crateScopes = [...crateScopes, new CratePattern('')];
  }

  function removeCrateScope(index: number): void {
    crateScopes = crateScopes.filter((_, i) => i !== index);
  }

  function validate(): boolean {
    nameInvalid = !name;
    confirmationCodeInvalid = confirmationCode.replaceAll(/[^A-Za-z0-9]/g, '').length < 8;
    expiryDateInvalid = expirySelection === 'custom' && !expiryDateInput;
    scopesInvalid = scopes.length === 0;
    let crateScopesValid = crateScopes
      .map(pattern => {
        let valid = isValidPattern(pattern.pattern);
        pattern.showAsInvalid = !valid;
        return valid;
      })
      .every(Boolean);

    return !nameInvalid && !confirmationCodeInvalid && !expiryDateInvalid && !scopesInvalid && crateScopesValid;
  }

  async function loadMeta() {
    loading = true;
    try {
      let response = await fetch(`/api/v1/cli_login/${loginId}/meta`);
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'CLI login session not found or expired');
      }
      meta = await response.json();
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
      let crateScopePatterns: string[] | null = crateScopes.map(it => it.pattern);
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
          name,
          endpoint_scopes: scopes,
          crate_scopes: crateScopePatterns,
          expired_at: expiryDate?.toISOString() ?? null,
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

      // Wake a waiting localhost listener without sending the token (CLI polls for it).
      let port = result.localhost_port ?? meta?.localhost_port;
      if (typeof port === 'number' && port >= 1024 && port <= 65_535) {
        try {
          await fetch(`http://localhost:${port}/`, { mode: 'no-cors' });
        } catch {
          // Ignore; CLI can poll for the token instead.
        }
      }

      notifications.success('Token issued. Return to the terminal — the token is not shown here.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to approve CLI login');
    } finally {
      isSaving = false;
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

      <div class="form-group" data-test-name-group>
        <label for="{id}-name" class="form-group-name">Name</label>

        <input
          id="{id}-name"
          type="text"
          bind:value={name}
          disabled={isSaving}
          autocomplete="off"
          aria-required="true"
          aria-invalid={nameInvalid}
          class="name-input base-input"
          data-test-name
          oninput={() => (nameInvalid = false)}
        />

        {#if nameInvalid}
          <div class="form-group-error" data-test-error>Please enter a name for this token.</div>
        {/if}
      </div>

      <div class="form-group" data-test-expiry-group>
        <label for="{id}-expiry" class="form-group-name">Expiration</label>

        <div class="select-group">
          <select
            id="{id}-expiry"
            disabled={isSaving}
            class="expiry-select base-input"
            data-test-expiry
            onchange={updateExpirySelection}
          >
            <option value="none">No expiration</option>
            <option value="7">7 days</option>
            <option value="30">30 days</option>
            <option value="60">60 days</option>
            <option value="90" selected>90 days</option>
            <option value="365">365 days</option>
            <option value="custom">Custom...</option>
          </select>

          {#if expirySelection === 'custom'}
            <input
              type="date"
              bind:value={expiryDateInput}
              min={today}
              disabled={isSaving}
              aria-invalid={expiryDateInvalid}
              aria-label="Custom expiration date"
              class="expiry-date-input base-input"
              data-test-expiry-date
              oninput={() => (expiryDateInvalid = false)}
            />
          {:else}
            <span class="expiry-description" data-test-expiry-description>
              {expiryDescription}
            </span>
          {/if}
        </div>
      </div>

      <div class="form-group" data-test-scopes-group>
        <div class="form-group-name">
          Scopes

          <a
            href="https://rust-lang.github.io/rfcs/2947-crates-io-token-scopes.html"
            target="_blank"
            rel="noopener noreferrer"
            class="help-link"
          >
            <span class="sr-only">Help</span>
            <Icon class="i-mdi:help-circle-outline" />
          </a>
        </div>

        <ul role="list" class="scopes-list" class:invalid={scopesInvalid}>
          {#each ENDPOINT_SCOPES as scope (scope)}
            <li>
              <label data-test-scope={scope}>
                <input
                  type="checkbox"
                  checked={scopes.includes(scope)}
                  disabled={isSaving}
                  onchange={() => toggleScope(scope)}
                />

                <span class="scope-id">{scope}</span>
                <span class="scope-description">{scopeDescription(scope)}</span>
              </label>
            </li>
          {/each}
        </ul>

        {#if scopesInvalid}
          <div class="form-group-error" data-test-error>Please select at least one token scope.</div>
        {/if}
      </div>

      <div class="form-group" data-test-scopes-group>
        <div class="form-group-name">
          Crates

          <a
            href="https://rust-lang.github.io/rfcs/2947-crates-io-token-scopes.html"
            target="_blank"
            rel="noopener noreferrer"
            class="help-link"
          >
            <span class="sr-only">Help</span>
            <Icon class="i-mdi:help-circle-outline" />
          </a>
        </div>

        <ul role="list" class="crates-list">
          {#each crateScopes as pattern, index (pattern)}
            <li class="crates-scope" class:invalid={pattern.showAsInvalid} data-test-crate-pattern={index}>
              <div>
                <input
                  bind:value={pattern.pattern}
                  aria-label="Crate name pattern"
                  oninput={() => (pattern.showAsInvalid = false)}
                  onblur={() => {
                    let valid = pattern.isValid || pattern.pattern === '';
                    pattern.showAsInvalid = !valid;
                  }}
                />

                <span class="pattern-description" data-test-description>
                  {#if !pattern.pattern}
                    Please enter a crate name pattern
                  {:else if pattern.isValid}
                    <PatternDescription pattern={pattern.pattern} />
                  {:else}
                    Invalid crate name pattern
                  {/if}
                </span>
              </div>

              <button type="button" data-test-remove onclick={() => removeCrateScope(index)}>
                <span class="sr-only">Remove pattern</span>
                <Icon class="i-mdi:trash-can-outline" />
              </button>
            </li>
          {:else}
            <li class="crates-unrestricted" data-test-crates-unrestricted>
              <strong>Unrestricted</strong>
              – This token can be used for all of your crates.
            </li>
          {/each}

          <li class="crates-pattern-button">
            <button type="button" data-test-add-crate-pattern onclick={addCratePattern}> Add pattern </button>
          </li>
        </ul>
      </div>

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

  .email-otp-row {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2xs);
    align-items: center;
  }

  .select-group {
    display: flex;
    align-content: center;
    align-items: center;
  }

  .help-link {
    flex-shrink: 0;
    color: light-dark(var(--grey600), var(--grey700));
    padding: var(--space-3xs);
    margin: calc(-1 * var(--space-3xs));
    --icon-size: 1.25em;

    &:hover {
      color: light-dark(var(--grey700), var(--grey600));
    }

    :global(.icon) {
      margin: -0.125em;
    }
  }

  .buttons {
    display: flex;
    gap: var(--space-2xs);
    flex-wrap: wrap;
  }

  .name-input {
    max-width: 440px;
    width: 100%;
  }

  .expiry-select {
    --dropdown-icon-light: icon('i-mdi:menu-down', 'black');
    --dropdown-icon-dark: icon('i-mdi:menu-down', 'white');

    padding-right: var(--space-m);
    background-image: var(--dropdown-icon-light);
    background-repeat: no-repeat;
    background-position: calc(100% - var(--space-3xs)) center;
    background-size: 20px;
    appearance: none;

    :global([data-color-scheme='system']) & {
      @media (prefers-color-scheme: dark) {
        background-image: var(--dropdown-icon-dark);
      }
    }

    :global([data-color-scheme='dark']) & {
      background-image: var(--dropdown-icon-dark);
    }
  }

  .expiry-date-input {
    margin-left: var(--space-2xs);
  }

  .expiry-description {
    margin-left: var(--space-2xs);
    font-size: 0.9em;
  }

  .scopes-list {
    list-style: none;
    padding: 0;
    margin: 0;
    background-color: light-dark(white, #141413);
    border: 1px solid var(--gray-border);
    border-radius: var(--space-3xs);

    &.invalid {
      background: light-dark(#fff2f2, #170808);
      border-color: red;
    }

    > li + li {
      border-top: inherit;
    }

    label {
      padding: var(--space-xs) var(--space-s);
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-xs);
      font-size: 0.9em;
    }
  }

  .scope-id {
    display: inline-block;
    max-width: 170px;
    flex-grow: 1;
    font-weight: bold;
  }

  .scope-description {
    display: inline-block;
  }

  .crates-list {
    list-style: none;
    padding: 0;
    margin: 0;
    background-color: light-dark(white, #141413);
    border: 1px solid var(--gray-border);
    border-radius: var(--space-3xs);

    > li + li {
      border-top: inherit;
    }
  }

  .crates-unrestricted {
    padding: var(--space-xs) var(--space-s);
    font-size: 0.9em;
  }

  .crates-scope {
    display: flex;

    > div {
      padding: var(--space-xs) var(--space-s);
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-xs);
      font-size: 0.9em;
      flex-grow: 1;
    }

    input {
      margin: calc(-1 * var(--space-4xs)) 0;
      padding: var(--space-3xs) var(--space-2xs);
      border: 1px solid var(--gray-border);
      border-radius: var(--space-3xs);
    }

    &.invalid input {
      background: light-dark(#fff2f2, #170808);
      border-color: red;
    }

    > button {
      margin: 0;
      padding: 0 var(--space-xs);
      border: none;
      background: none;
      cursor: pointer;
      color: var(--grey700);
      flex-shrink: 0;
      display: flex;
      align-items: center;
      --icon-size: 1.5em;

      &:hover {
        background: light-dark(var(--grey200), #333333);
        color: light-dark(var(--grey900), white);
      }
    }

    &:first-child button {
      border-top-right-radius: var(--space-3xs);
    }
  }

  .pattern-description {
    flex-grow: 1;
    align-self: center;

    .invalid & {
      color: red;
    }
  }

  .crates-pattern-button button {
    padding: var(--space-xs) var(--space-s);
    font-size: 0.9em;
    width: 100%;
    border: none;
    background: none;
    border-bottom-left-radius: var(--space-3xs);
    border-bottom-right-radius: var(--space-3xs);
    cursor: pointer;
    font-weight: bold;

    &:hover {
      background: light-dark(var(--grey200), #333333);
    }
  }

  .generate-button {
    border-radius: 4px;

    :global(.spinner) {
      margin-left: var(--space-2xs);
    }
  }
</style>
