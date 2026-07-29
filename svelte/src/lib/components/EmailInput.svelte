<script lang="ts">
  import type { AuthenticatedUser } from '$lib/utils/session.svelte';
  import type { HTMLAttributes } from 'svelte/elements';

  import { createClient } from '@crates-io/api-client';

  import { getNotifications } from '$lib/notifications.svelte';

  interface Props extends HTMLAttributes<HTMLDivElement> {
    /** MUST be passed with `bind:user` since this component mutates the user object directly after saving. */
    user: AuthenticatedUser;
  }

  let { user = $bindable(), class: className, ...restProps }: Props = $props();

  let notifications = getNotifications();
  let client = createClient({ fetch });

  let value = $state('');
  let isEditing = $state(false);
  let disableResend = $state(false);
  let isSaving = $state(false);
  let isResending = $state(false);
  let isSendingOtp = $state(false);
  let emailOtp = $state('');
  let emailOtpHint = $state<string | null>(null);

  let requiresEmailOtp = $derived(
    Boolean(user.email_verified && user.email && value.trim() && value.trim().toLowerCase() !== user.email.toLowerCase()),
  );

  function editEmail() {
    value = user.email_pending ?? user.email ?? '';
    emailOtp = '';
    emailOtpHint = null;
    isEditing = true;
  }

  function cancelEdit() {
    isEditing = false;
    emailOtp = '';
    emailOtpHint = null;
  }

  async function sendEmailOtp() {
    isSendingOtp = true;
    try {
      let response = await fetch('/api/v1/me/mfa/email_codes', { method: 'POST' });
      if (!response.ok) {
        let body = (await response.json().catch(() => null)) as { errors?: { detail?: string }[] } | null;
        let detail = body?.errors?.[0]?.detail;
        throw new Error(detail ?? 'Failed to send email verification code.');
      }
      let body = (await response.json()) as { sent_to_hint?: string };
      emailOtpHint = body.sent_to_hint ?? null;
      notifications.success('Verification code sent to your current email address.');
    } catch (error) {
      let msg = error instanceof Error ? error.message : 'Failed to send email verification code.';
      notifications.error(msg);
    } finally {
      isSendingOtp = false;
    }
  }

  async function saveEmail(event: SubmitEvent) {
    event.preventDefault();

    isSaving = true;

    try {
      let result = await client.PUT('/api/v1/users/{user}', {
        params: { path: { user: user.id } },
        body: {
          user: { email: value },
          ...(requiresEmailOtp ? { email_code: emailOtp.trim() } : {}),
        },
      });

      if (!result.response.ok) {
        let detail = (result.error as unknown as { errors?: { detail?: string }[] })?.errors?.[0]?.detail;

        let msg =
          detail && !detail.startsWith('{')
            ? `An error occurred while saving this email, ${detail}`
            : 'An unknown error occurred while saving this email.';

        throw new Error(msg);
      }

      if (user.email_verified && user.email && value.trim().toLowerCase() !== user.email.toLowerCase()) {
        // Dual-email: verified inbox stays; new address awaits confirm link.
        user.email_pending = value;
        user.email_verification_sent = true;
      } else if (user.email_verified && user.email && value.trim().toLowerCase() === user.email.toLowerCase()) {
        user.email_pending = null;
      } else {
        user.email = value;
        user.email_verified = false;
        user.email_verification_sent = true;
        user.email_pending = null;
      }

      isEditing = false;
      disableResend = false;
      emailOtp = '';
      emailOtpHint = null;
    } catch (error) {
      let msg = error instanceof Error ? error.message : 'An unknown error occurred while saving this email.';
      notifications.error(`Error in saving email: ${msg}`);
    } finally {
      isSaving = false;
    }
  }

  async function resendEmail() {
    isResending = true;

    try {
      let result = await client.PUT('/api/v1/users/{id}/resend', {
        params: { path: { id: user.id } },
      });

      if (!result.response.ok) {
        let detail = (result.error as unknown as { errors?: { detail?: string }[] })?.errors?.[0]?.detail;

        let msg =
          detail && !detail.startsWith('{')
            ? `Error in resending message: ${detail}`
            : 'Unknown error in resending message';

        throw new Error(msg);
      }

      disableResend = true;
    } catch (error) {
      let msg = error instanceof Error ? error.message : 'Unknown error in resending message';
      notifications.error(msg);
    } finally {
      isResending = false;
    }
  }
</script>

<div class={['email-input', className]} data-test-email-input {...restProps}>
  {#if !user.email}
    <div class="friendly-message" data-test-no-email>
      <p>
        Please add your email address. We will only use it to contact you about your account. We promise we'll never
        share it!
      </p>
    </div>
  {/if}

  {#if isEditing}
    <div class="row">
      <div class="label">
        <label for="email-input">Email</label>
      </div>
      <form class="email-form" onsubmit={saveEmail}>
        <input type="email" bind:value id="email-input" placeholder="Email" class="input" data-test-input />

        {#if requiresEmailOtp}
          <div class="otp-row" data-test-email-otp-step>
            <p class="otp-hint">
              Changing a verified email requires a code sent to your current address
              {#if emailOtpHint}
                ({emailOtpHint})
              {/if}. Your current address stays active until you confirm the new one.
            </p>
            <button
              type="button"
              class="button button--small"
              disabled={isSendingOtp || isSaving}
              onclick={sendEmailOtp}
              data-test-send-email-otp
            >
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
              class="otp-input"
              data-test-email-otp
            />
          </div>
        {/if}

        <div class="actions">
          <button
            type="submit"
            class="save-button button button--small"
            disabled={!value || isSaving || (requiresEmailOtp && !emailOtp.trim())}
            data-test-save-button
          >
            Save
          </button>

          <button type="button" class="button button--small" data-test-cancel-button onclick={cancelEdit}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  {:else}
    <div class="row">
      <div class="label">
        <dt>Email</dt>
      </div>
      <div class="email-column" data-test-email-address>
        <dd>
          {user.email}
          {#if user.email_verified}
            <span class="verified" data-test-verified>Verified!</span>
          {/if}
        </dd>
      </div>
      <div class="actions">
        <button type="button" class="button button--small" data-test-edit-button onclick={editEmail}> Edit </button>
      </div>
    </div>
    {#if user.email_pending}
      <div class="row" data-test-email-pending>
        <div class="label">
          <p>
            Pending confirmation: <span data-test-pending-address>{user.email_pending}</span>. Your current verified
            address stays active until you confirm the new one.
          </p>
          {#if user.email_verification_sent}
            <p data-test-verification-sent>We have sent a verification email to the pending address.</p>
          {/if}
        </div>
        <div class="actions">
          <button
            type="button"
            class="button button--small"
            disabled={disableResend || isResending}
            data-test-resend-button
            onclick={resendEmail}
          >
            {#if disableResend}
              Sent!
            {:else}
              Resend
            {/if}
          </button>
        </div>
      </div>
    {:else if user.email && !user.email_verified}
      <div class="row">
        <div class="label">
          {#if user.email_verification_sent}
            <p data-test-verification-sent>We have sent a verification email to your address.</p>
          {/if}
          <p data-test-not-verified>Your email has not yet been verified.</p>
        </div>
        <div class="actions">
          <button
            type="button"
            class="button button--small"
            disabled={disableResend || isResending}
            data-test-resend-button
            onclick={resendEmail}
          >
            {#if disableResend}
              Sent!
            {:else if user.email_verification_sent}
              Resend
            {:else}
              Send verification email
            {/if}
          </button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .friendly-message {
    margin-top: 0;
  }

  .row {
    width: 100%;
    border: 1px solid var(--gray-border);
    border-bottom-width: 0;
    padding: var(--space-2xs) var(--space-s);
    display: flex;
    align-items: center;

    &:last-child {
      border-bottom-width: 1px;
    }
  }

  .label {
    flex: 1;
    margin-right: var(--space-xs);
    font-weight: bold;
  }

  .email-column {
    flex: 20;
  }

  .verified {
    color: green;
    font-weight: bold;
  }

  .email-form {
    flex: 10;
    display: inline-flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: var(--space-2xs);
  }

  .input {
    width: 400px;
    margin-right: var(--space-xs);
  }

  .otp-row {
    flex-basis: 100%;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2xs);
  }

  .otp-hint {
    flex-basis: 100%;
    margin: 0;
    font-weight: normal;
    font-size: 0.9em;
  }

  .otp-input {
    width: 12rem;
  }

  .actions {
    display: flex;
    align-items: center;
  }

  .save-button {
    margin-right: var(--space-2xs);
  }
</style>
