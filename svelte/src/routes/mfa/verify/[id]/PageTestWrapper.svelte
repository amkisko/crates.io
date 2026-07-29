<script lang="ts">
  import { NotificationsState, setNotifications } from '$lib/notifications.svelte';
  import { PageTitleState, setPageTitle } from '$lib/page-title.svelte';
  import Page from './+page.svelte';

  setNotifications(new NotificationsState());
  setPageTitle(new PageTitleState());
</script>

<Page />
