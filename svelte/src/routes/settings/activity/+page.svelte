<script lang="ts">
  import { formatDistanceToNow } from 'date-fns';

  import PageHeader from '$lib/components/PageHeader.svelte';
  import PageTitle from '$lib/components/PageTitle.svelte';
  import SettingsPage from '$lib/components/SettingsPage.svelte';
  import { getNotifications } from '$lib/notifications.svelte';

  interface SecurityEvent {
    id: number;
    event_type: string;
    api_token_id: number | null;
    ip: string | null;
    metadata: Record<string, string | null>;
    created_at: string;
  }

  interface Meta {
    total: number;
    next_page?: string | null;
  }

  let { data } = $props();
  let notifications = getNotifications();

  let events = $state<SecurityEvent[]>([]);
  let meta = $state<Meta>({ total: 0 });
  let loadingMore = $state(false);

  $effect(() => {
    events = [...data.securityEvents];
    meta = { ...data.meta };
  });

  const LABELS: Record<string, string> = {
    session_login: 'Signed in with GitHub',
    session_logout_all: 'Signed out everywhere',
    cli_login_approved: 'Approved CLI login',
    token_created: 'Created API token',
    token_revoked: 'Revoked API token',
    token_revoked_github: 'API token revoked (GitHub secret scanning)',
    token_used: 'API token used',
    api_mfa_enabled: 'Enabled API MFA',
    api_mfa_disabled: 'Disabled API MFA',
    passkey_registered: 'Registered passkey',
    passkey_deleted: 'Deleted passkey',
    api_mfa_authorized: 'Authorized API MFA for 15 minutes',
    api_mfa_challenge_verified: 'Verified API MFA challenge',
    email_changed: 'Changed verified email',
  };

  function labelFor(event: SecurityEvent): string {
    return LABELS[event.event_type] ?? event.event_type.replaceAll('_', ' ');
  }

  function detailFor(event: SecurityEvent): string | null {
    let parts: string[] = [];
    if (event.metadata.token_name) {
      parts.push(`token “${event.metadata.token_name}”`);
    }
    if (event.metadata.passkey_name) {
      parts.push(`passkey “${event.metadata.passkey_name}”`);
    }
    if (event.metadata.operation) {
      let op = event.metadata.operation;
      if (event.metadata.crate_name) {
        op += ` (${event.metadata.crate_name})`;
      }
      parts.push(op);
    }
    if (event.ip) {
      parts.push(`IP ${event.ip}`);
    }
    return parts.length === 0 ? null : parts.join(' · ');
  }

  async function loadMore() {
    if (!meta.next_page || loadingMore) return;

    loadingMore = true;
    try {
      // meta.next_page already includes the leading `?`.
      let response = await fetch(`/api/v1/me/security_events${meta.next_page}`);
      if (!response.ok) {
        throw new Error('Failed to load more activity');
      }
      let body = await response.json();
      events = [...events, ...(body.security_events ?? [])];
      meta = body.meta ?? meta;
    } catch (error) {
      notifications.error(error instanceof Error ? error.message : 'Failed to load more activity.');
    } finally {
      loadingMore = false;
    }
  }
</script>

<PageTitle title="Settings" />

<PageHeader title="Account Settings" />

<SettingsPage>
  <section aria-labelledby="activity-heading">
    <h2 id="activity-heading">Recent security activity</h2>

    <p class="explainer">Sign-ins, token changes, and API MFA events from the last 90 days.</p>

    {#if events.length === 0}
      <p class="empty" data-test-activity-empty>No recent security activity.</p>
    {:else}
      <ul role="list" class="events" data-test-activity-list aria-labelledby="activity-heading">
        {#each events as event (event.id)}
          <li class="event" data-test-activity-event={event.event_type}>
            <div class="main">
              <span class="label">{labelFor(event)}</span>
              {#if detailFor(event)}
                <span class="detail">{detailFor(event)}</span>
              {/if}
            </div>
            <time datetime={event.created_at} title={new Date(event.created_at).toLocaleString()}>
              {formatDistanceToNow(event.created_at, { addSuffix: true })}
            </time>
          </li>
        {/each}
      </ul>
      {#if meta.next_page}
        <button
          type="button"
          class="button button--small"
          data-test-activity-load-more
          disabled={loadingMore}
          aria-busy={loadingMore}
          onclick={loadMore}
        >
          {loadingMore ? 'Loading…' : `Load more (${events.length} of ${meta.total})`}
        </button>
      {:else if meta.total > 0}
        <p class="more" data-test-activity-complete>Showing all {events.length} events.</p>
      {/if}
    {/if}
  </section>
</SettingsPage>

<style>
  h2 {
    margin: 0 0 var(--space-2xs);
  }

  .explainer {
    margin: 0 0 var(--space-m);
    color: var(--grey600);
  }

  .empty {
    margin: 0;
    color: var(--grey600);
  }

  .events {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .event {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2xs) var(--space-s);
    justify-content: space-between;
    align-items: baseline;
    padding: var(--space-xs) 0;
    border-bottom: 1px solid var(--gray-border);
  }

  .main {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
    min-width: 0;
  }

  .label {
    font-weight: 600;
  }

  .detail {
    color: var(--grey600);
    font-size: 0.95rem;
  }

  time {
    flex-shrink: 0;
    color: var(--grey600);
    font-size: 0.9rem;
  }

  .more {
    margin: var(--space-s) 0 0;
    color: var(--grey600);
    font-size: 0.9rem;
  }

  button {
    margin-top: var(--space-s);
  }
</style>
