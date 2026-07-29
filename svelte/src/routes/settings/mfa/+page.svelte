<script lang="ts">
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import SettingsPage from '$lib/components/SettingsPage.svelte';
  import { getNotifications } from '$lib/notifications.svelte';
  import { getSession } from '$lib/utils/session.svelte';

  interface Credential {
    id: number;
    name: string;
    created_at: string;
    last_used_at: string | null;
  }

  interface ApiMfaStatus {
    enabled: boolean;
    credentials: Credential[];
    grant_expires_at: string | null;
    has_verified_email: boolean;
  }

  let session = getSession();
  let notifications = getNotifications();

  let status = $state<ApiMfaStatus | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let newPasskeyName = $state('Passkey');
  let emailOtp = $state('');
  let emailOtpHint = $state<string | null>(null);
  let emailOtpExpiresAt = $state<string | null>(null);

  async function loadStatus() {
    loading = true;
    try {
      let response = await fetch('/api/v1/me/mfa');
      if (!response.ok) {
        throw new Error('Failed to load API MFA status');
      }
      status = await response.json();
    } catch {
      notifications.error('Failed to load API MFA settings.');
    } finally {
      loading = false;
    }
  }

  async function sendEmailOtp() {
    busy = true;
    try {
      let response = await fetch('/api/v1/me/mfa/email_codes', { method: 'POST' });
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to send email code');
      }
      let body = await response.json();
      emailOtpHint = body.sent_to_hint;
      emailOtpExpiresAt = body.expires_at;
      notifications.success(`Verification code sent to ${body.sent_to_hint}.`);
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to send email code.');
    } finally {
      busy = false;
    }
  }

  async function setEnabled(enabled: boolean) {
    busy = true;
    try {
      let payload: { enabled: boolean; credential?: unknown; email_code?: string } = { enabled };

      if (enabled) {
        let otp = emailOtp.trim();
        if (!otp) {
          throw new Error('Request an email verification code, then enter it to enable API MFA.');
        }
        payload.email_code = otp;
      } else if (status?.enabled) {
        let otp = emailOtp.trim();
        if (otp) {
          payload.email_code = otp;
        } else {
          if (!globalThis.PublicKeyCredential) {
            throw new Error('This browser does not support passkeys. Use an email verification code instead.');
          }
          if ((status.credentials?.length ?? 0) === 0) {
            throw new Error('No passkeys registered. Request an email verification code to disable API MFA.');
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
          payload.credential = serializeCredential(credential);
        }
      }

      let response = await fetch('/api/v1/me/mfa', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to update API MFA');
      }
      emailOtp = '';
      await loadStatus();
      notifications.success(enabled ? 'API MFA enabled.' : 'API MFA disabled.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to update API MFA.');
      // Checkbox is controlled by `status.enabled`; reload so a failed disable does not look toggled off.
      await loadStatus();
    } finally {
      busy = false;
    }
  }

  async function registerPasskey() {
    if (!globalThis.PublicKeyCredential) {
      notifications.error('This browser does not support passkeys.');
      return;
    }

    busy = true;
    try {
      let startBody: { credential?: unknown; email_code?: string } = {};

      // With MFA enabled and an existing passkey, prove possession before enrollment.
      // Otherwise (first enroll / recovery / MFA off) require an email OTP.
      if (status?.enabled && (status.credentials?.length ?? 0) > 0) {
        let authStart = await fetch('/api/v1/me/mfa/authorize/start', { method: 'POST' });
        if (!authStart.ok) {
          let body = await authStart.json().catch(() => null);
          throw new Error(body?.errors?.[0]?.detail ?? 'Failed to start passkey verification');
        }
        let { public_key: authPublicKey } = await authStart.json();
        let assertion = (await navigator.credentials.get({
          publicKey: revivePublicKeyRequest(authPublicKey),
        })) as PublicKeyCredential | null;
        if (!assertion) {
          throw new Error('Passkey verification was cancelled');
        }
        startBody.credential = serializeCredential(assertion);
      } else {
        let otp = emailOtp.trim();
        if (!otp) {
          throw new Error('Request an email verification code, then enter it to register a passkey.');
        }
        startBody.email_code = otp;
      }

      let start = await fetch('/api/v1/me/mfa/passkeys/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(startBody),
      });
      if (!start.ok) {
        let body = await start.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to start passkey registration');
      }
      let { public_key } = await start.json();
      let credential = (await navigator.credentials.create({
        publicKey: revivePublicKeyCreation(public_key),
      })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('Passkey registration was cancelled');
      }

      let finish = await fetch('/api/v1/me/mfa/passkeys/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newPasskeyName.trim() || 'Passkey',
          credential: serializeCredential(credential),
        }),
      });
      if (!finish.ok) {
        let body = await finish.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to finish passkey registration');
      }

      emailOtp = '';
      await loadStatus();
      notifications.success('Passkey registered.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Passkey registration failed.');
    } finally {
      busy = false;
    }
  }

  async function deleteCredential(id: number) {
    busy = true;
    try {
      let payload: { credential?: unknown; email_code?: string } = {};

      if (status?.enabled) {
        let otp = emailOtp.trim();
        if (otp) {
          payload.email_code = otp;
        } else {
          if (!globalThis.PublicKeyCredential) {
            throw new Error('This browser does not support passkeys. Use an email verification code instead.');
          }
          if ((status.credentials?.length ?? 0) === 0) {
            throw new Error('No passkeys registered. Request an email verification code to delete.');
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
          payload.credential = serializeCredential(credential);
        }
      }

      let response = await fetch(`/api/v1/me/mfa/passkeys/${id}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        let body = await response.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to delete passkey');
      }
      emailOtp = '';
      await loadStatus();
      notifications.success('Passkey deleted.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to delete passkey.');
    } finally {
      busy = false;
    }
  }

  async function authorizeApiActions() {
    if (!globalThis.PublicKeyCredential) {
      notifications.error('This browser does not support passkeys.');
      return;
    }

    busy = true;
    try {
      let start = await fetch('/api/v1/me/mfa/authorize/start', { method: 'POST' });
      if (!start.ok) {
        let body = await start.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to start authorization');
      }
      let { public_key } = await start.json();
      let credential = (await navigator.credentials.get({
        publicKey: revivePublicKeyRequest(public_key),
      })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('Passkey verification was cancelled');
      }

      let finish = await fetch('/api/v1/me/mfa/authorize/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serializeCredential(credential) }),
      });
      if (!finish.ok) {
        let body = await finish.json().catch(() => null);
        throw new Error(body?.errors?.[0]?.detail ?? 'Failed to finish authorization');
      }

      await loadStatus();
      notifications.success('API actions authorized for 15 minutes. You can run cargo publish now.');
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Authorization failed.');
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

  function revivePublicKeyCreation(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
    let user = options.user as Record<string, unknown>;
    return {
      ...(options as PublicKeyCredentialCreationOptions),
      challenge: b64urlToBuffer(options.challenge as string),
      user: {
        ...(user as PublicKeyCredentialUserEntity),
        id: b64urlToBuffer(user.id as string),
      },
      excludeCredentials: ((options.excludeCredentials as Array<Record<string, unknown>>) ?? []).map(cred => ({
        ...(cred as PublicKeyCredentialDescriptor),
        id: b64urlToBuffer(cred.id as string),
      })),
    };
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

  function serializeCredential(credential: PublicKeyCredential) {
    let response = credential.response;
    if (response instanceof AuthenticatorAttestationResponse) {
      return {
        id: credential.id,
        rawId: bufferToB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToB64url(response.clientDataJSON),
          attestationObject: bufferToB64url(response.attestationObject),
        },
      };
    }

    let assertion = response as AuthenticatorAssertionResponse;
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
    if (session.currentUser) {
      loadStatus();
    }
  });
</script>

<PageTitle title="Settings" />
<PageHeader title="Account Settings" />

<SettingsPage>
  {#if loading || !status}
    <LoadingSpinner />
  {:else}
    <section>
      <h2>API MFA</h2>
      <p>
        When enabled, publish, yank, and owner changes require a recent passkey verification — for API tokens and for
        actions from this website. Use Authorize for 15 minutes below, or complete a CLI challenge verification link
        (similar to RubyGems WebAuthn MFA).
      </p>
      <p>Trusted Publishing tokens are not affected.</p>

      <label class="checkbox-input">
        <input
          type="checkbox"
          checked={status.enabled}
          disabled={busy || (!status.enabled && status.credentials.length === 0)}
          onchange={event => setEnabled(event.currentTarget.checked)}
        />
        <span class="label">Require passkey verification for publish, yank, and owner changes</span>
      </label>
      {#if !status.enabled && status.credentials.length === 0}
        <p class="hint">Register at least one passkey, then enter an email verification code to enable API MFA.</p>
      {:else if !status.enabled}
        <p class="hint">Enter an email verification code below, then enable API MFA.</p>
      {:else if status.credentials.length === 0}
        <p class="hint">
          API MFA is enabled with no passkeys. Dangerous actions stay blocked until you register a passkey (email code)
          or disable API MFA (email code).
        </p>
      {:else}
        <p class="hint">
          Disabling API MFA requires a passkey confirmation or an email verification code. Registering another passkey
          requires a passkey confirmation.
        </p>
      {/if}
    </section>

    <section>
      <h2>Email verification code</h2>
      <p>
        Used to enable API MFA, register a passkey when you have none (or when API MFA is off), and to disable API MFA
        without a passkey. Codes are sent to your verified email address.
      </p>
      {#if !status.has_verified_email}
        <p class="hint">
          Set and verify an email under <a href="/settings/profile">Settings → Profile</a> before requesting a code.
        </p>
      {:else}
        <div class="email-otp">
          <button type="button" class="button" disabled={busy} onclick={sendEmailOtp} data-test-send-email-otp>
            Send code
          </button>
          <input
            type="text"
            bind:value={emailOtp}
            maxlength="32"
            autocomplete="one-time-code"
            spellcheck="false"
            aria-label="Email verification code"
            placeholder="Enter code"
            data-test-email-otp
          />
        </div>
        {#if emailOtpHint && emailOtpExpiresAt}
          <p class="hint">
            Code sent to {emailOtpHint}. Expires {new Date(emailOtpExpiresAt).toLocaleString()}.
          </p>
        {/if}
      {/if}
    </section>

    <section>
      <h2>Authorize API actions</h2>
      <p>
        Verify a passkey to allow <code>cargo publish</code>, website publish, and other dangerous actions for the next
        15 minutes without repeating the challenge.
      </p>
      {#if status.grant_expires_at}
        <p class="grant" data-test-grant-expiry>
          Active grant until <strong>{new Date(status.grant_expires_at).toLocaleString()}</strong>
        </p>
      {:else}
        <p class="hint">No active grant.</p>
      {/if}
      <button
        type="button"
        class="button"
        disabled={busy || status.credentials.length === 0}
        onclick={authorizeApiActions}
        data-test-authorize-api
      >
        Authorize for 15 minutes
      </button>
    </section>

    <section>
      <h2>Passkeys</h2>
      <div class="register">
        <input type="text" bind:value={newPasskeyName} maxlength="64" aria-label="Passkey name" />
        <button type="button" class="button" disabled={busy} onclick={registerPasskey} data-test-register-passkey>
          Register passkey
        </button>
      </div>
      {#if !status.enabled || status.credentials.length === 0}
        <p class="hint">Enter an email verification code above before registering.</p>
      {/if}
      {#if status.enabled && status.credentials.length > 0}
        <p class="hint">Deleting a passkey requires passkey verification (or an email code).</p>
      {/if}

      {#if status.credentials.length === 0}
        <p class="hint">No passkeys registered yet.</p>
      {:else}
        <ul class="credentials">
          {#each status.credentials as credential (credential.id)}
            <li>
              <div>
                <strong>{credential.name}</strong>
                <div class="meta">Added {new Date(credential.created_at).toLocaleString()}</div>
              </div>
              <button
                type="button"
                class="button button--red button--small"
                disabled={busy}
                onclick={() => deleteCredential(credential.id)}
              >
                Delete
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section>
      <h2>CLI handshake</h2>
      <p>
        Dangerous API calls (publish, yank, change owners) return a short-lived <code>operation_id</code> and
        <code>verification_url</code> (<code>/mfa/verify/…</code>, passkey only — no crates.io sign-in). Open that link,
        complete passkey auth, while the CLI polls until <code>acknowledged</code>, then retries. Optional headers:
        <code>Crates-MFA-Operation-Id</code>, <code>Crates-MFA-Port</code>,
        <code>Crates-OTP</code>.
      </p>
    </section>
  {/if}
</SettingsPage>

<style>
  section {
    margin-bottom: var(--space-l);
  }

  p {
    max-width: 45rem;
  }

  .hint,
  .grant,
  .meta {
    color: var(--grey600);
    font-size: 0.9rem;
  }

  .register,
  .email-otp {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2xs);
    margin: var(--space-s) 0;
  }

  .credentials {
    list-style: none;
    padding: 0;
    margin: var(--space-s) 0 0;
    display: grid;
    gap: var(--space-2xs);
  }

  .credentials li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-s);
    padding: var(--space-2xs) 0;
    border-bottom: 1px solid var(--gray-border);
  }

  .checkbox-input {
    display: flex;
    gap: var(--space-2xs);
    align-items: flex-start;
    margin: var(--space-s) 0;
  }
</style>
