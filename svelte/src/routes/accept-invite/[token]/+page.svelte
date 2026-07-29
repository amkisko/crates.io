<script lang="ts">
  import { onMount } from 'svelte';
  import { resolve } from '$app/paths';
  import { createClient } from '@crates-io/api-client';

  import { getSession } from '$lib/utils/session.svelte';

  let { data } = $props();

  let session = getSession();
  let result: 'loading' | 'need-login' | 'success' | 'error' = $state('loading');
  let errorText: string | undefined = $state();

  async function acceptInvite() {
    result = 'loading';
    errorText = undefined;
    let client = createClient({ fetch });

    try {
      let response = await client.PUT('/api/v1/me/crate_owner_invitations/accept/{token}', {
        params: { path: { token: data.token } },
      });

      if (response.response.ok) {
        result = 'success';
        return;
      }

      let status = response.response.status;
      if (status === 403 || status === 401) {
        // Not signed in as the invitee (or at all).
        if (!session.currentUser) {
          result = 'need-login';
          return;
        }
      }

      errorText = (response.error as unknown as { errors?: { detail?: string }[] })?.errors?.[0]?.detail;
      result = 'error';
    } catch {
      result = 'error';
    }
  }

  // Using `onMount` instead of `load()` because this is a mutation (PUT),
  // not data loading. `onMount` only runs in the browser, which avoids
  // issues with SSR and preloading re-firing the mutation.
  onMount(async () => {
    if (!session.currentUser) {
      result = 'need-login';
      return;
    }
    await acceptInvite();
  });
</script>

{#if result === 'loading'}
  <h1>Accepting invitation…</h1>
{:else if result === 'need-login'}
  <h1>Sign in to accept this invitation</h1>
  <p data-test-need-login-message>
    Ownership invitations must be accepted while signed in as the invited crates.io account. Sign in, then return to
    this page (or open the link from your email again).
  </p>
  <p>
    <button type="button" class="button" onclick={() => session.login()} data-test-accept-invite-login>
      Sign in with GitHub
    </button>
  </p>
{:else if result === 'success'}
  <h1>You've been added as a crate owner!</h1>
  <p data-test-success-message>
    Visit your
    <a href={resolve('/dashboard')}>dashboard</a>
    to view all of your crates, or
    <a href={resolve('/me')}>account settings</a>
    to manage email notification preferences for all of your crates.
  </p>
{:else if result === 'error'}
  <h1>Error in accepting crate ownership.</h1>
  <p data-test-error-message>
    {#if errorText}
      {errorText}
      {#if errorText.includes('Authorize for 15 minutes')}
        <br />
        Open
        <a href={resolve('/settings/mfa')}>Settings → API MFA</a>, choose Authorize for 15 minutes, then
        <button type="button" class="button-reset link" onclick={acceptInvite}>try again</button>.
      {/if}
    {:else}
      You may want to visit
      <a href={resolve('/me/pending-invites')}>crates.io/me/pending-invites</a>
      to try again.
    {/if}
  </p>
{/if}

<style>
  .link {
    color: var(--main-color);
    text-decoration: underline;
    cursor: pointer;
  }
</style>
