/** Endpoint scopes supported by crates.io API tokens. */
export const TOKEN_ENDPOINT_SCOPES = ['change-owners', 'publish-new', 'publish-update', 'trusted-publishing', 'yank'];

/** Reactive crate-pattern field used by token forms. */
export class CratePattern {
  pattern = $state('');
  showAsInvalid = $state(false);

  constructor(pattern: string) {
    this.pattern = pattern;
  }

  get isValid(): boolean {
    return isValidCratePattern(this.pattern);
  }
}

interface TokenFormOptions {
  name?: string;
  endpointScopes?: string[];
  crateScopes?: string[];
}

/** Shared reactive state and validation for API-token creation forms. */
export class TokenFormState {
  name = $state('');
  nameInvalid = $state(false);
  expirySelection = $state('90');
  expiryDateInput = $state('');
  expiryDateInvalid = $state(false);
  scopes = $state<string[]>([]);
  scopesInvalid = $state(false);
  crateScopes = $state<CratePattern[]>([]);

  constructor(options: TokenFormOptions = {}) {
    this.name = options.name ?? '';
    this.scopes = options.endpointScopes ? [...options.endpointScopes] : [];
    this.crateScopes = (options.crateScopes ?? []).map(pattern => new CratePattern(pattern));
  }

  get today(): string {
    return new Date().toISOString().slice(0, 10);
  }

  get expiryDate(): Date | null {
    if (this.expirySelection === 'none') return null;

    let now = new Date();
    if (this.expirySelection === 'custom') {
      if (!this.expiryDateInput) return null;
      return new Date(this.expiryDateInput + now.toISOString().slice(10));
    }

    return new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() + Number(this.expirySelection),
      now.getHours(),
      now.getMinutes(),
      now.getSeconds(),
    );
  }

  get expiryDescription(): string {
    if (this.expirySelection === 'none') return 'The token will never expire';
    return `The token will expire on ${this.expiryDate?.toLocaleDateString(undefined, { dateStyle: 'long' })}`;
  }

  /** Toggles an endpoint scope and clears its validation error. */
  toggleScope(scope: string): void {
    this.scopes = this.scopes.includes(scope) ? this.scopes.filter(value => value !== scope) : [...this.scopes, scope];
    this.scopesInvalid = false;
  }

  /** Preserves the selected date when switching expiration modes. */
  updateExpirySelection(value: string): void {
    this.expiryDateInput = this.expiryDate?.toISOString().slice(0, 10) ?? '';
    this.expirySelection = value;
  }

  /** Adds an empty crate-pattern field. */
  addCratePattern(): void {
    this.crateScopes = [...this.crateScopes, new CratePattern('')];
  }

  /** Removes a crate-pattern field by index. */
  removeCratePattern(index: number): void {
    this.crateScopes = this.crateScopes.filter((_, patternIndex) => patternIndex !== index);
  }

  /** Validates shared token fields and marks invalid controls for display. */
  validate(): boolean {
    this.nameInvalid = !this.name;
    this.expiryDateInvalid = this.expirySelection === 'custom' && !this.expiryDateInput;
    this.scopesInvalid = this.scopes.length === 0;

    let crateScopesValid = this.crateScopes
      .map(pattern => {
        pattern.showAsInvalid = !pattern.isValid;
        return pattern.isValid;
      })
      .every(Boolean);

    return !this.nameInvalid && !this.expiryDateInvalid && !this.scopesInvalid && crateScopesValid;
  }
}

/** Returns whether a crate token-scope pattern follows Cargo identifier rules. */
export function isValidCratePattern(pattern: string): boolean {
  if (!pattern) return false;
  if (pattern === '*') return true;

  let identifier = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
  return (
    [...identifier].every(character => isAsciiAlphanumeric(character) || character === '_' || character === '-') &&
    identifier[0] !== '_' &&
    identifier[0] !== '-'
  );
}

function isAsciiAlphanumeric(character: string): boolean {
  return (
    (character >= '0' && character <= '9') ||
    (character >= 'A' && character <= 'Z') ||
    (character >= 'a' && character <= 'z')
  );
}
