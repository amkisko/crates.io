# API MFA (registry mutation authorization)

Opt-in protection so publish, yank, and owner changes require recent interactive
authentication — for API tokens and for website cookie sessions.

Cargo preflights a token-authenticated mutation before sending it. If policy
requires user presence, the browser completes passkey verification without a
crates.io cookie while Cargo observes readiness through a read-only poll token.
An optional loopback callback only wakes Cargo for an immediate poll.
`cargo login` still mints the primary API token. Cookie sessions use the
settings "Authorize for 15 minutes" grant instead of the Cargo protocol.

### Glossary

Architecture (IAM vocabulary; not route names):

- Step-up authentication — an already authenticated principal must authenticate
  more strongly or more recently before a sensitive action. Used in design prose
  only; see RFC 9470 for the OAuth analogue (which obtains a new token; this
  flow does not).

Registry protocol:

- Mutation record — one logical invocation under a Cargo `preflight_id` and a
  registry `mutation_id`.
- Authorization challenge — a pending mutation record awaiting the registry's
  chosen verification method.
- Poll token — independent read-only capability for `pending`, `ready`,
  `denied`, or `expired` status.
- Grant — server-side exact authorization bound to credential identity and
  mutation fingerprint.
- Browser page: `/verify/{mutation_id}` — capability URL; no crates.io cookie.
- Product setting: API MFA — crates.io settings/docs/metrics when the account
  promises multi-factor composition for this policy.

NIST note: MFA describes the factor composition of an authentication event.
Passkeys, OTP authenticators, out-of-band approvals, and security keys are
authentication methods or authenticator types whose factor properties may vary
(for example a passkey may be single-factor or multi-factor depending on user
verification).

CLI login approve meta may still expose `mfa_required: true` when the account
has API MFA enabled — product state, not a mutation-authorization response.

Org or maintainer approvals that are not this authorization flow should use a
distinct error such as `approval_required`.

HTTP status: `403` when the API token is valid but inadequate for the protected
operation. Spec requires a non-2xx response; any historical crates.io `200` +
error-body handling in Cargo is a compatibility exception, not the contract.

## Threat model

Long-lived API token (`~/.cargo/credentials`):

- Without API MFA: immediate publish, yank, or owner change
- With API MFA: Cargo final endpoints are blocked until an exact preflight
  mutation record is ready. Browser-session authorization and recovery codes
  cannot authorize them.

Website session / crates.io cookie:

- Without API MFA: can mint tokens and act in the browser
- With API MFA: publish, yank, and owner changes from the site require an active grant (Authorize for 15 minutes); Settings → New Token, token revoke-by-id, and CLI link-login approve require a passkey assertion (or email OTP on CLI approve when MFA is on with zero passkeys); registering an additional passkey requires a passkey assertion when one exists. Self-revoke of the current token (`DELETE /api/v1/tokens/current`) stays free.
- Bootstrap / recovery: enabling API MFA, first passkey enrollment, and recovery enrollment (zero passkeys) require a verified-email OTP so a stolen session cookie alone cannot enroll a passkey and turn on enforcement. Enabling MFA also bumps `users.session_generation` (other browsers are signed out; the enabling browser keeps a refreshed cookie). Disabling API MFA requires a passkey assertion or email OTP. Enforcement may remain on with zero passkeys (dangerous actions stay blocked until a passkey is re-registered or MFA is disabled via email OTP).
- Changing away from a verified email requires an email OTP sent to the current verified address, and the verified inbox stays active until the new address is confirmed (`emails.pending_email`). A stolen session cannot redirect MFA recovery to an attacker inbox without both the OTP and control of the new inbox.
- Sessions are signed client cookies carrying `user_id` and `session_generation`. Settings → Profile → Sign out everywhere bumps generation so every other browser session fails cookie auth.

Trusted Publishing (`cio_tp_…`) OIDC token:

- Trusted Publishing is the automation path; API MFA is the interactive-token path. OIDC publish skips MFA either way (OIDC identity is the second factor) so CI is not blocked on a passkey prompt. Non-OIDC CI that still uses a long-lived API token needs a human MFA step (or Trusted Publishing / a future scoped automation token).
- TrustPub only becomes available after the crate already exists. The first publish (and other bootstrap ownership work) still needs a long-lived API token or a cookie session — the window where a stolen token is most dangerous. API MFA covers that bootstrap window; mutation authorization can later cover other unsafe operations that still need human supervision (yank, owners, delete, TrustPub config, and similar).

Passkeys vs token scopes / identity:

- OAuth login remains account identity. Passkeys are account-wide second factors for settings step-up and the current mutation-verification method; they are not a login replacement and have no capability scopes in v1. Least privilege stays on API token scopes. Passkey `name` and `last_used_at` (plus register/delete in the security activity feed) are hygiene only.

Multi-owner / team crates:

- If any individual owner has `api_mfa_enabled`, dangerous mutates on that crate require MFA for the acting user (including team members and co-owners who have not opted in yet). Actors without MFA enabled get a clear error to enable API MFA first. Instant OAuth team owner-add is unchanged. Trusted Publishing OIDC publish still skips MFA. Optional `trustpub_only` remains a separate crate-level control.
- Enabling API MFA is therefore an individual opt-in with crate-wide effects:
  co-owners and team publishers may need to enable API MFA and upgrade to a
  Cargo release that implements protocol version 1 before they can mutate the
  crate. The settings UI and rollout communication must state this consequence.

Upstream identity-provider account 2FA does not protect a leaked cargo token.

## Design intention: human-in-the-loop authorization

API MFA requires a recent, interactive second factor for each dangerous action. Possession of another long-lived secret is insufficient.

Publishers must use a passkey, or another factor with equivalent properties:
a key, token, or service that authenticates the user to crates.io and normally
requires manual interaction on the user's machine (confirm, touch, or
presence). The verify page is a separate browser step: open the URL, complete
the authenticator prompt, and leave a server-side acknowledgment tied to that
ceremony and the stored mutation descriptor. WebAuthn does not sign the
human-readable operation summary.

The goal is to make a silent publish from a stolen cargo token require a recent interactive second factor. Full automation remains possible in principle (headless WebAuthn, remote authenticators, malware on the machine); this design only removes the easy paths.

Acceptable factors share these properties:

- The verification ceremony acknowledges one registry mutation record, which
  the registry binds to the stored operation.
- Normal use involves human presence (user gesture, biometric, PIN + touch) at verification time.
- Crates.io records mutation-authorization and product-session ceremonies in
  the account security activity feed.

WebAuthn passkeys are the supported verification method for mutation authorization today.

Email OTP is not an API MFA factor for publish, yank, or owner actions. It is only a bootstrap / recovery step-up for settings changes (enable MFA, first or recovery passkey enrollment, disable MFA when passkeys are unavailable, and staging a verified-email change). Possession of a verified inbox is weaker than a presence-bound passkey; it blocks session-hijack paths without replacing the human-in-the-loop rule for dangerous API calls.

SSH pubkey authentication is out of scope as an API MFA factor. SSH auth proves
key possession to an SSH server; API MFA needs fresh crates.io authentication,
an intentional presence step, and a server-side ceremony record bound to the
stored mutation. Agent-backed SSH (`ssh-agent`, CI keys, forwarded agents)
typically supplies only silent key use. Accepting "can SSH as this user" would
treat another long-lived key as MFA and miss the human-in-the-loop rule above.

Any future factor (hardware token protocol, external signing service, etc.) must
keep per-operation verification, intentional user interaction in the common
case, and an auditable acknowledgment path. Silent pubkey possession alone is
insufficient.

## Challenge binding and security properties

Mutation records and grants are bound to:

- the user and API token that started mutation authorization
- the operation type and crate
- a mutation fingerprint (for publish: version, metadata hash, and tarball hash)

Completion for one request must not authorize a modified publication or a different protected mutation.

Additional properties:

- Mutation ids and independent poll tokens are unguessable and short-lived.
- When the optional loopback extension is used, Cargo keeps callback state
  locally and preflights the exact `127.0.0.1` callback URL containing that
  state. The verification page obtains this URL from the stored record.
- `poll_url` must share the registry API origin; Cargo refuses cross-origin
  poll URLs and does not follow poll redirects. `detail` contains the complete
  bounded plain-text verification instructions; it is displayed as inert text.
- Non-interactive automatic mode uses `allow_pending: false`, so it cannot
  create an abandoned challenge.
- Poll responses use `pending`, `ready`, `denied`, or `expired`.

## Mutation preflight and extension negotiation

Cargo sends an authenticated `POST /api/v1/auth/mutation-challenges` before
the ordinary request. The body contains a fresh `preflight_id`,
`protocol_version: 1`, `allow_pending`, a `requested_extensions` array, the
raw-body digest and size, and operation-specific facts. Publish also binds the
archive digest and size; the verification page displays that archive digest for
independent comparison. The registry stores and echoes the supported subset as
`active_extensions`; Cargo relies on an extension only after that confirmation.
When `idempotent-final` is activated, Cargo additionally sends the exact
method, request target, and content type needed for safe final-request replay.

No index capability block is used. A definitive preflight `404 Not Found`
means mutation authorization is not implemented, so Cargo sends the ordinary
mutation unless an explicit mode requires an unavailable extension. Transport
errors, other statuses, and malformed responses fail without fallback.
Protected ordinary endpoints still require an exact ready record; preflight
discovery is not the security boundary.

The response is `ready` (200), `pending` (202), or
`interaction_required` (403). The last result is used when `allow_pending` is
false; it creates no record or actionable URL. Pending responses contain
complete plain-text instructions, a mutation id, an independent poll-token URL,
and a relative lifetime. The verification-page URL is part of `detail`, not a
separate response field.

Cargo-facing responses expose conservative relative durations such as
`challenge_expires_in`, `grant_expires_in`, and `receive_lease_secs`; fields
that do not apply to the current status or active extensions are omitted.
crates.io stores authoritative absolute deadlines as `expires_at` timestamps
and exposes one to its internal browser verification page for display. Those
timestamps are not part of the Cargo protocol.

A core-only record atomically consumes its ready grant after one complete exact
request match and before endpoint execution. An activated `idempotent-final`
record replaces that minimal transition with receive, execution, and terminal
states. Its ready response includes `receive_lease_secs`, which bounds Cargo's
automatic retry window without itself granting mutation authority.

crates.io advertises a 1,800-second (30-minute) receive lease. The middleware
starts that lease only after checking the bound credential, live grant, HTTP
method, exact request target, media type, absence of content encoding, and
declared body length. It then reads at most the preflighted body length and
checks the raw digest before endpoint parsing. A mismatch found before claim
leaves the record `ready`; an incomplete or digest-mismatched body can consume
time only within the already bounded receive lease.

For `idempotent-final`, the mutation middleware authenticates the mutation id
before buffering the body, verifies the credential, method, request target,
content type, declared and actual size, digest, and parsed operation fields
against the stored descriptor, and returns `425 Too Early` to a concurrent
attempt. The endpoint changes `receiving` to `executing` and stores its bounded
JSON response inside the same database transaction as the mutation effect. A
committed retry therefore replays the response, while a rolled-back or crashed
transaction leaves the record receivable. The middleware never holds a
database connection while the endpoint runs. Publish follow-up and index jobs
are queued in that transaction, and owner-invite email delivery uses the same
transactional job outbox when this extension is active.

The `receiving` to `executing` transition and terminal response write occur in
the endpoint's mutation transaction. A process or database failure before
commit therefore rolls `executing` back to `receiving`; a successful commit
stores `terminal` with the effect. A persistently visible `executing` record is
an invariant violation, not a state the cleanup job should reset blindly.

Core-only records use the same exact request validation but consume the grant
without retaining a response. `idempotent-final` is active only when requested,
confirmed, and accompanied by its descriptor fields. The server must not
activate it until every covered endpoint uses transactional outcome storage.

## Cargo mutation authorization (primary flow)

1. Register a passkey under Settings → API MFA and enable enforcement.
2. Cargo preflights the exact mutation. Each logical invocation has its own
   `preflight_id`; only an ambiguous retry reuses it.
3. Interactive Cargo can request `loopback-callback` and listen at an
   exact URL such as
   `http://127.0.0.1:{port}/cargo/registry-authorization?state={random}` and
   includes it in preflight. Polling remains the fallback; remote users select
   `poll`.
4. After passkey verification, the page obtains the registered callback URL
   from the stored record and requests it unchanged.
5. The callback is only a wake-up signal. Cargo immediately polls and continues
   only after `ready`. Polling uses no primary credential.
6. Cargo sends the original request with its ordinary credential and only
   `Cargo-Mutation-Id`. The registry-side exact grant authorizes that mutation.

Core `CARGO_REGISTRY_MUTATION_AUTHORIZATION_MODE` and
`--mutation-authorization-mode` values are `auto`, `poll`, and `disabled`;
`loopback-callback` adds `loopback`. Automatic non-interactive mode preflights
with `allow_pending: false`.

## Enforced endpoints

When `users.api_mfa_enabled` is true, token-authenticated Cargo final endpoints
require an exact ready `Cargo-Mutation-Id`:

- `PUT /api/v1/crates/new` (publish)
- `PUT` / `DELETE /api/v1/crates/{name}/owners`
- yank / unyank version endpoints

Other product endpoints use browser-session authorization grants:

- `PATCH /api/v1/crates/{name}` when `trustpub_only` changes (enable or disable)
- `DELETE /api/v1/crates/{name}` (crate delete; cookie sessions)
- Trusted Publishing config create/delete (`/api/v1/trusted_publishing/…`)

Grant matching:

- Settings → Authorize issues a browser-session grant.
- Browser authorization never authorizes a Cargo token.

Cookie sessions without a grant receive `400` asking the user to Authorize for 15 minutes under Settings → API MFA.

Owner invitation accept (`PUT /api/v1/me/crate_owner_invitations/accept/{token}` and the authenticated accept path) requires a cookie session for the invitee. The path token selects the invitation; it is not a standalone bearer capability. When the invitee has API MFA enabled (or the crate already has an MFA owner), accept requires an Authorize grant.

## Manual authorize

"Authorize for 15 minutes" on the settings page issues a wildcard grant (any operation/crate). Use it for:

- website publish / yank / owner / delete / Trusted Publishing config changes while MFA is enabled
- toggling `trustpub_only` on crate settings while MFA is enabled

Challenge acknowledgment remains scoped to the API token, operation, crate, and
mutation fingerprint that created the challenge. Users who opt in must use a
Cargo release that supports protocol version 1; website authorization is not a
compatibility path for older Cargo clients.

## Configuration

- `WEBAUTHN_RP_ID` (default: `DOMAIN_NAME`) — WebAuthn RP ID
- `WEBAUTHN_RP_ORIGIN` (default: `https://{DOMAIN_NAME}`) — expected browser origin
- `WEBAUTHN_RP_NAME` (default: `crates.io`) — authenticator display name
- `RATE_LIMITER_API_MFA_CHALLENGE_CREATE_RATE_SECONDS` (default: `30`) — refill interval for new challenge inserts and for challenge start/finish (per IP and per challenge owner)
- `RATE_LIMITER_API_MFA_CHALLENGE_CREATE_BURST` (default: `10`) — burst for those create/ceremony actions
- `RATE_LIMITER_API_MFA_CHALLENGE_POLL_RATE_SECONDS` (default: `2`) — refill interval for challenge polls (token clients per user; verify page per IP)
- `RATE_LIMITER_API_MFA_CHALLENGE_POLL_BURST` (default: `15`) — burst for those poll actions
- `RATE_LIMITER_API_MFA_EMAIL_OTP_SEND_RATE_SECONDS` (default: `60`) — refill interval for email OTP sends
- `RATE_LIMITER_API_MFA_EMAIL_OTP_SEND_BURST` (default: `3`) — burst for email OTP sends
- `RATE_LIMITER_CHANGE_OWNERS_RATE_SECONDS` / `_BURST` (defaults: `60` / `20`) — owner add/remove
- `RATE_LIMITER_EMAIL_UPDATE_RATE_SECONDS` / `_BURST` (defaults: `60` / `5`) — email stage/resend
- `RATE_LIMITER_TOKEN_CREATE_RATE_SECONDS` / `_BURST` (defaults: `60` / `10`) — API token create
- `RATE_LIMITER_TOKEN_REVOKE_RATE_SECONDS` / `_BURST` (defaults: `60` / `20`) — API token revoke-by-id
- `RATE_LIMITER_PUBLISH_REQUEST_RATE_SECONDS` / `_BURST` (defaults: `2` / `30`) —
  pre-authorization publish upload protection keyed by API token and source IP;
  separate from the successful publish mutation quota
- `API_MFA_ENFORCEMENT_ENABLED` (default: `false`) — when `false`, skips MFA on dangerous mutates only (publish/yank/owners/delete/trustpub/invite-accept). Bootstrap / enrollment gates stay on (enable/disable OTP, passkey enroll/delete, New Token, token revoke-by-id, CLI approve, verified-email change). Status GET reports `enabled` (user opt-in) and `enforcement_active` (this flag). Enable explicitly after compatible Cargo and staging checks; disable for emergency bypass (e.g. WebAuthn/RP outage).
- `SECURITY_ACTIVITY_ENABLED` (default: `false`) — controls collection and
  exposure of the user activity feed. Enable only after the privacy notice and
  monitored retention schedule are operational.

For local frontend development against a local API, set `WEBAUTHN_RP_ID=localhost` and `WEBAUTHN_RP_ORIGIN=http://localhost:5173` (or your SvelteKit origin).

## Operations

Enqueue periodic cleanup (Heroku Scheduler):

```bash
crates-admin enqueue-job api_mfa_cleanup
```

The job:

- clears `auth_state_json` on expired challenges (free TOAST early)
- deletes pending challenges 24 hours after `expires_at` and terminal mutation
  records 24 hours after `completed_at`
- deletes expired grants and WebAuthn ceremony states
- deletes expired or consumed email OTPs

Instance metrics: `cratesio_instance_api_mfa_ensure_total{result=…}`, ensure duration histogram, challenges created, challenge polls.

Service gauge: `cratesio_service_api_mfa_challenges_pending`.

## Cargo integration

Cargo preflights each supported mutation unless authorization is disabled. It
requests extensions it implements and uses only those confirmed by the
preflight response. The loopback channel only accelerates polling and never
carries mutation authority or a final-request credential. Use `poll` for an SSH
session whose browser runs on another machine.

While Cargo lacks built-in mutation-authorization support, an opted-in user
must:

- upgrade to a supported Cargo release;
- use a compatible wrapper that implements the complete version 1 contract; or
- use Trusted Publishing where applicable.

Settings → Authorize covers browser-cookie actions only and cannot authorize an
older Cargo API token.

## CLI link-login

Prefer browser-assisted `cargo login` with `cargo-credential-crates-io` so tokens are never shown in the UI or terminal. When API MFA is enabled, approving that login also requires a passkey assertion. See [`CLI-LOGIN.md`](CLI-LOGIN.md).

## Email OTP (settings only)

`POST /api/v1/me/mfa/email_codes` emails an 8-character code to the user's verified address (10-minute TTL, rate-limited). Include it as `email_code` on:

- `PUT /api/v1/me/mfa` when enabling (always) or disabling (alternative to passkey)
- `POST /api/v1/me/mfa/passkeys/start` when the account has no passkeys, or when API MFA is off
- `PUT /api/v1/users/{id}` when staging a change away from a verified email address

Verified-email changes use dual-email confirmation: after a valid OTP, the new address is stored in `emails.pending_email` and gets a confirm link; `email` / `verified` stay on the current inbox until `PUT /api/v1/confirm/{token}` promotes the pending address. `/api/v1/me` exposes the staged address as `email_pending`. Resend sends to the pending address when one is staged. Unverified addresses still replace in place.

Deleting a passkey while API MFA is enabled requires a passkey assertion or email OTP. The last passkey may still be deleted while enforcement stays on. Dangerous API calls then fail until a passkey is registered via email OTP recovery (or MFA is disabled with an email OTP).

Settings changes (enable/disable, passkey register/delete) also send a notification email to the verified address when present.

## Security activity

Settings changes and successful challenge acknowledgments are recorded in the owner-only security activity feed (90-day retention). See [SECURITY-ACTIVITY.md](SECURITY-ACTIVITY.md).

## Limitations

- Opt-in only; popular-crate mandates are out of scope here.
- When API MFA is enabled, Settings → New Token and CLI link-login approve require a passkey assertion via the authorize ceremony (`POST /api/v1/me/mfa/authorize/start` + `credential`). Registering an additional passkey while API MFA is enabled and at least one passkey remains also requires a recent passkey assertion. This closes the trustpub-only untick → mint token → publish chain from a stolen session.
- Disabling API MFA requires a passkey assertion or email code.
- Pending challenges are capped per user (currently 10) to limit write amplification from a stolen token.
- WebAuthn ceremony state for register/authorize is stored server-side; challenge auth state is stored on the challenge row.
- Settings → Authorize issues a browser-session grant that API-token requests
  cannot reuse.

## Related improvement vectors (out of v1)

Treat API MFA as the interactive mutation-authorization layer only. Separate tracks remain:

- Package / index signing (artifact attestation): MFA proves a recent human ceremony for a mutation; it does not bind the published tarball to a long-term publisher key. Mutation authorization and package signing compose; neither replaces the other. Transport or long-lived key possession (including SSH agents) is not a substitute for presence-bound verification or for signed package bytes.
- Tighter ceremony binding: publish acknowledgment already includes metadata and
  tarball hashes. The loopback callback only wakes Cargo; the mutation record
  is token- and request-scoped. Browser Authorize remains a separate product
  session mechanism.
- Scoped automation tokens: Trusted Publishing covers OIDC CI; non-OIDC automation still needs a human MFA step or a future short-lived / scoped automation token (automation bypass policy is a separate product decision, not part of this design).
- Local token storage and login UX (Cargo): API MFA assumes a long-lived token already on disk; it does not fix plaintext `~/.cargo/credentials.toml`, OS-keychain defaults, CLI token paste, multi-identity login, or runtime token injection. Those stay Cargo-side tracks (credential providers, login UX, CI token injection). See [CLI-LOGIN.md](CLI-LOGIN.md) for the browser-assisted mint path.
- Consumer trust policy: optional client or UI signals for `trustpub_only`, MFA-enabled owners, or signed crates; complements ecosystem MFA / download-threshold mandates.

- Public provenance: optional version metadata that a publish completed after an MFA ceremony or Trusted Publishing exchange, without exposing private activity IPs or challenge ids.
- Compromise hygiene: passkey / credential revocation feeds or Activity prompts when credentials are known-bad, beyond settings-change emails.
- Optional passkey alternative on verified-email change when API MFA is on (OTP to the current inbox remains the v1 step-up).

## Related work

This design is a form of step-up authentication for protected registry
operations. The closest standards analogue is
[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) (OAuth step-up
challenge protocol), which obtains a new access token; this protocol instead
keeps the existing API token and records a request-bound challenge completion.
Authentication-method vocabulary follows
[NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

Complementary Cargo documentation (credential storage and providers, not this
mutation-authorization flow):

- [Registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
- [Credential provider protocol](https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html)

Trusted Publishing remains the preferred path for non-interactive CI:
[crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing).

Asymmetric credentials and related RFCs (protocol cousins, separate track):
RFC 3231 (Cargo asymmetric tokens).

This protocol limits what a stolen long-lived API token can do for protected
operations. Credential providers reduce token exposure at rest; Trusted
Publishing can remove long-lived registry credentials from CI. Neither replaces
interactive step-up for human-held API tokens.
