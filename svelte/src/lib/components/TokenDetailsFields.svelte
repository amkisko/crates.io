<script lang="ts">
  import type { TokenFormState } from '$lib/utils/token-form.svelte';

  import Icon from '$lib/components/Icon.svelte';
  import PatternDescription from '$lib/components/PatternDescription.svelte';
  import { TOKEN_ENDPOINT_SCOPES } from '$lib/utils/token-form.svelte';
  import { scopeDescription } from '$lib/utils/token-scopes';

  let {
    id,
    state,
    disabled = false,
    autofocus = false,
  } = $props<{
    id: string;
    state: TokenFormState;
    disabled?: boolean;
    autofocus?: boolean;
  }>();
</script>

<div class="form-group" data-test-name-group>
  <label for="{id}-name" class="form-group-name">Name</label>

  <!-- svelte-ignore a11y_autofocus -->
  <input
    id="{id}-name"
    type="text"
    bind:value={state.name}
    {disabled}
    autocomplete="off"
    aria-required="true"
    aria-invalid={state.nameInvalid}
    class="name-input base-input"
    data-test-name
    {autofocus}
    oninput={() => (state.nameInvalid = false)}
  />

  {#if state.nameInvalid}
    <div class="form-group-error" data-test-error>Please enter a name for this token.</div>
  {/if}
</div>

<div class="form-group" data-test-expiry-group>
  <label for="{id}-expiry" class="form-group-name">Expiration</label>

  <div class="select-group">
    <select
      id="{id}-expiry"
      {disabled}
      class="expiry-select base-input"
      data-test-expiry
      onchange={event => state.updateExpirySelection(event.currentTarget.value)}
    >
      <option value="none">No expiration</option>
      <option value="7">7 days</option>
      <option value="30">30 days</option>
      <option value="60">60 days</option>
      <option value="90" selected={state.expirySelection === '90'}>90 days</option>
      <option value="365">365 days</option>
      <option value="custom">Custom...</option>
    </select>

    {#if state.expirySelection === 'custom'}
      <input
        type="date"
        bind:value={state.expiryDateInput}
        min={state.today}
        {disabled}
        aria-invalid={state.expiryDateInvalid}
        aria-label="Custom expiration date"
        class="expiry-date-input base-input"
        data-test-expiry-date
        oninput={() => (state.expiryDateInvalid = false)}
      />
    {:else}
      <span class="expiry-description" data-test-expiry-description>
        {state.expiryDescription}
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

  <ul role="list" class="scopes-list" class:invalid={state.scopesInvalid}>
    {#each TOKEN_ENDPOINT_SCOPES as scope (scope)}
      <li>
        <label data-test-scope={scope}>
          <input
            type="checkbox"
            checked={state.scopes.includes(scope)}
            {disabled}
            onchange={() => state.toggleScope(scope)}
          />

          <span class="scope-id">{scope}</span>
          <span class="scope-description">{scopeDescription(scope)}</span>
        </label>
      </li>
    {/each}
  </ul>

  {#if state.scopesInvalid}
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
    {#each state.crateScopes as pattern, index (pattern)}
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

        <button type="button" data-test-remove onclick={() => state.removeCratePattern(index)}>
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
      <button type="button" data-test-add-crate-pattern onclick={() => state.addCratePattern()}> Add pattern </button>
    </li>
  </ul>
</div>

<style>
  .form-group {
    position: relative;
    margin: var(--space-m) 0;
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

  .expiry-date-input,
  .expiry-description {
    margin-left: var(--space-2xs);
  }

  .expiry-description,
  .scopes-list,
  .crates-unrestricted,
  .crates-scope,
  .crates-pattern-button button {
    font-size: 0.9em;
  }

  .scopes-list,
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

  .scopes-list {
    &.invalid {
      background: light-dark(#fff2f2, #170808);
      border-color: red;
    }

    label {
      padding: var(--space-xs) var(--space-s);
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-xs);
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

  .crates-unrestricted {
    padding: var(--space-xs) var(--space-s);
  }

  .crates-scope {
    display: flex;

    > div {
      padding: var(--space-xs) var(--space-s);
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-xs);
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
</style>
