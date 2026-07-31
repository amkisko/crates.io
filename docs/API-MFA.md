# API MFA (passkey step-up)

Opt-in protection so publish, yank, and owner changes require recent interactive
authentication — for API tokens and for website cookie sessions.

A token-authenticated protected API call returns a short-lived authentication
challenge; the browser completes passkey verification without a crates.io cookie
while the CLI receives a one-time proof (localhost OTP callback) or observes the
same challenge through a scoped step-up grant (poll). Both completion channels
remain available for a callback-enabled challenge. `cargo login` still mints the API token before
`cargo publish`. Cookie sessions use the settings "Authorize for 15 minutes"
grant instead of that handshake.

### Glossary

Architecture (IAM vocabulary; not route names):

- Step-up authentication — an already authenticated principal must authenticate
  more strongly or more recently before a sensitive action. Used in design prose
  only; see RFC 9470 for the OAuth analogue (which obtains a new token; this
  flow does not).

Registry protocol:

- Additional interactive authentication — what Cargo and registry docs say the
  client must do for a protected operation.
- Wire error: `step_up_required` — compact `errors[].id` cargo matches. Names the
  unmet condition without claiming OAuth Bearer compliance or MFA factor counts.
  (A longer self-describing alternative is `additional_authentication_required`;
  this design keeps the shorter id.)
- Protocol version: `protocol_version: 1`. Cargo handles only version 1 with
  `interaction: "browser"`; unknown or incomplete contracts remain ordinary
  registry errors rather than causing Cargo to follow URLs.
- Authentication challenge — temporary server object under
  `/api/v1/auth/challenges/{challenge_id}` (`stp_…` ids).
- Browser page: `/verify/{challenge_id}` — capability URL; no crates.io cookie.
- `interaction: "browser"` — how the human participates. Completion transport is
  separate (localhost callback or poll). Authentication method stays on the
  website (passkey today).
- Step-up completion — browser ceremony finished for this challenge.
- One-time proof — localhost callback OTP bound to the challenge / mutation;
  consumed on retry (`Cargo-Step-Up-Proof`).
- Scoped step-up grant — server-side authorization for the poll/retry path,
  bound to token + operation + crate (+ mutation fingerprint). Not a synonym
  for the one-time proof.
- Product setting: API MFA — crates.io settings/docs/metrics when the account
  promises multi-factor composition for this policy.

NIST note: MFA describes the factor composition of an authentication event.
Passkeys, OTP authenticators, out-of-band approvals, and security keys are
authentication methods or authenticator types whose factor properties may vary
(for example a passkey may be single-factor or multi-factor depending on user
verification).

CLI login approve meta may still expose `mfa_required: true` when the account
has API MFA enabled — product state, not the publish handshake error id.

Org or maintainer approvals that are not this security handshake should use a
distinct error such as `approval_required`.

HTTP status: `403` when the API token is valid but inadequate for the protected
operation. Spec requires a non-2xx response; any historical crates.io `200` +
error-body handling in Cargo is a compatibility exception, not the contract.

## Threat model

Long-lived API token (`~/.cargo/credentials`):

- Without API MFA: immediate publish, yank, or owner change
- With API MFA: blocked until passkey acknowledgment (token-bound CLI challenge,
  scoped grant, or OTP)

Website session / crates.io cookie:

- Without API MFA: can mint tokens and act in the browser
- With API MFA: publish, yank, and owner changes from the site require an active grant (Authorize for 15 minutes); Settings → New Token, token revoke-by-id, and CLI link-login approve require a passkey assertion (or email OTP on CLI approve when MFA is on with zero passkeys); registering an additional passkey requires a passkey assertion when one exists. Self-revoke of the current token (`DELETE /api/v1/tokens/current`) stays free.
- Bootstrap / recovery: enabling API MFA, first passkey enrollment, and recovery enrollment (zero passkeys) require a verified-email OTP so a stolen session cookie alone cannot enroll a passkey and turn on enforcement. Enabling MFA also bumps `users.session_generation` (other browsers are signed out; the enabling browser keeps a refreshed cookie). Disabling API MFA requires a passkey assertion or email OTP. Enforcement may remain on with zero passkeys (dangerous actions stay blocked until a passkey is re-registered or MFA is disabled via email OTP).
- Changing away from a verified email requires an email OTP sent to the current verified address, and the verified inbox stays active until the new address is confirmed (`emails.pending_email`). A stolen session cannot redirect MFA recovery to an attacker inbox without both the OTP and control of the new inbox.
- Sessions are signed client cookies carrying `user_id` and `session_generation`. Settings → Profile → Sign out everywhere bumps generation so every other browser session fails cookie auth.

Trusted Publishing (`cio_tp_…`) OIDC token:

- Trusted Publishing is the automation path; API MFA is the interactive-token path. OIDC publish skips MFA either way (OIDC identity is the second factor) so CI is not blocked on a passkey prompt. Non-OIDC CI that still uses a long-lived API token needs a human MFA step (or Trusted Publishing / a future scoped automation token).
- TrustPub only becomes available after the crate already exists. The first publish (and other bootstrap ownership work) still needs a long-lived API token or a cookie session — the window where a stolen token is most dangerous. API MFA covers that bootstrap window; the same step-up can later cover other unsafe operations that still need human supervision (yank, owners, delete, TrustPub config, and similar).

Passkeys vs token scopes / identity:

- OAuth login remains account identity. Passkeys are account-wide second factors for step-up (approve and mutate); they are not a login replacement and have no capability scopes in v1. Least privilege stays on API token scopes. Passkey `name` and `last_used_at` (plus register/delete in the security activity feed) are hygiene only.

Multi-owner / team crates:

- If any individual owner has `api_mfa_enabled`, dangerous mutates on that crate require MFA for the acting user (including team members and co-owners who have not opted in yet). Actors without MFA enabled get a clear error to enable API MFA first. Instant OAuth team owner-add is unchanged. Trusted Publishing OIDC publish still skips MFA. Optional `trustpub_only` remains a separate crate-level control.
- Enabling API MFA is therefore an individual opt-in with crate-wide effects:
  co-owners and team publishers may need to enable API MFA and upgrade to a
  Cargo release that implements protocol version 1 before they can mutate the
  crate. The settings UI and rollout communication must state this consequence.

Upstream identity-provider account 2FA does not protect a leaked cargo token.

## Design intention: human-in-the-loop signature

API MFA requires a recent, interactive second factor for each dangerous action. Possession of another long-lived secret is insufficient.

Publishers must use a passkey, or another factor with equivalent properties: a key, token, or service that produces a cryptographic signature for this specific operation and normally requires manual interaction on the user's machine (confirm, touch, or presence). The verify page is a separate browser step: open the URL, complete the authenticator prompt, leave a server-side acknowledgment tied to that ceremony.

The goal is to make a silent publish from a stolen cargo token require a recent interactive second factor. Full automation remains possible in principle (headless WebAuthn, remote authenticators, malware on the machine); this design only removes the easy paths.

Acceptable factors share these properties:

- Signature (or equivalent proof) is single-use and bound to this challenge / operation.
- Normal use involves human presence (user gesture, biometric, PIN + touch) at verification time.
- Crates.io records a ceremony trace (challenge → acknowledgment / grant / OTP) linked to the dangerous API call.

WebAuthn passkeys are the supported mechanism for per-operation step-up today.

Email OTP is not an API MFA factor for publish, yank, or owner actions. It is only a bootstrap / recovery step-up for settings changes (enable MFA, first or recovery passkey enrollment, disable MFA when passkeys are unavailable, and staging a verified-email change). Possession of a verified inbox is weaker than a presence-bound passkey; it blocks session-hijack paths without replacing the human-in-the-loop rule for dangerous API calls.

SSH pubkey authentication is out of scope as an API MFA factor. SSH auth proves key possession to an SSH server; API MFA needs a crates.io-bound signature over the publish/yank/owner challenge, a per-operation presence step on the machine that is about to act, and a server-side ceremony record for that `challenge_id`. Agent-backed SSH (`ssh-agent`, CI keys, forwarded agents) typically supplies only silent key use. Accepting "can SSH as this user" would treat another long-lived key as MFA and miss the human-in-the-loop rule above.

Any future factor (hardware token protocol, external signing service, etc.) must keep per-operation proof, intentional user interaction in the common case, and an auditable acknowledgment path. Silent pubkey possession alone is insufficient.

## Challenge binding and security properties

Challenges, one-time proofs, and scoped grants are bound to:

- the user and API token that started the handshake
- the operation type and crate
- a mutation fingerprint (for publish: version, metadata hash, and tarball hash)

Completion for one request must not authorize a modified publication or a different protected mutation.

Additional properties:

- Challenge ids (`stp_…`) are unguessable, short-lived, and request-bound.
- The localhost callback secret is hashed at rest; the plaintext is carried in the
  verification URL fragment (not sent to crates.io as a query/path) so ordinary
  HTTP access logs do not record it. Callback port replacement requires that
  secret. The server includes it as callback `state`, and Cargo rejects
  callbacks whose state does not match before accepting an OTP.
- `poll_url` and `verification_url` must share the registry API origin; Cargo
  refuses cross-origin poll URLs and does not follow poll redirects.
- Cargo allowlists `step_up_required` only; it must not follow arbitrary URLs from
  a generic challenge handler.
- Non-interactive clients (`CI=true` / non-TTY) fail fast instead of hanging.
- Poll responses use `status`: `pending` or `acknowledged` (`acknowledged` /
  `verified` bools are aliases). Missing or expired challenges return `404`.
  Future states may include `denied` / `expired` without changing the error id.

## CLI handshake (primary flow)

1. Register a passkey under Settings → API MFA and enable enforcement.
2. CLI performs a dangerous action (`cargo publish`, yank, change owners) with an API token.
3. Preferred (localhost OTP / one-time proof): CLI binds `127.0.0.1`, sends
   `Cargo-Step-Up-Port` plus a client-held `Cargo-Step-Up-Callback-Secret`, and
   waits for the verify page to
   `GET http://127.0.0.1:{port}/?code={otp}&state={callback_secret}` while also
   polling the challenge as a fallback.
4. Remote/SSH users select polling with `CARGO_REGISTRY_STEP_UP_CHANNEL=poll`. Automatic
   mode uses localhost on an interactive TTY and falls back to polling after a
   bind failure. A callback-enabled challenge remains pollable, so delivery
   failure does not strand the mutation.
5. API `403` fields:
   - `id` — `step_up_required` (cargo matches this)
   - `protocol_version` — `1`
   - `detail` — leads with "Additional authentication is required"
   - `interaction` — `browser`
   - `challenge_id` — temporary challenge id (`stp_…`)
   - `operation` / `crate` / `operation_summary` — protected operation context
     (`operation_summary` is safe to display; Cargo may show `operation` + `crate`)
   - `verification_url` — `/verify/{challenge_id}` (no sign-in)
   - `poll_url` — `GET /api/v1/auth/challenges/{challenge_id}`
   - `expires_at` — short TTL (5 minutes)
   - `recommended_poll_interval_secs` — advisory poll interval (currently `5`)
6. User opens the link and completes passkey check. The verify page does not
   require a crates.io cookie; the opaque `challenge_id` is the capability, and
   the passkey proves control of the account that owns the token.
7. CLI retries the original request (idempotent):
   - With `Cargo-Step-Up-Port`: finish returns `localhost_callback_url` plus a
     one-time proof; retry with `Cargo-Step-Up-Proof` when callback wins.
   - Finish always issues a scoped grant bound to the same API token, operation,
     crate, and fingerprint. If polling observes acknowledgment first, Cargo
     retries without OTP and uses that grant.

Optional headers on the dangerous request:

- `Cargo-Step-Up-Port` — localhost port for proof callback after verification
- `Cargo-Step-Up-Callback-Secret` — URL-safe client secret authorizing callback
  port refreshes and authenticating listener callback state; required with the
  port
- `Cargo-Step-Up-Proof` — one-time proof after verification (localhost path)

Retries of the same token + operation + crate + fingerprint reuse the pending
challenge until it expires or is completed.

## Enforced endpoints

When `users.api_mfa_enabled` is true (API token or cookie session):

- `PUT /api/v1/crates/new` (publish)
- `PUT` / `DELETE /api/v1/crates/{name}/owners`
- yank / unyank version endpoints
- `PATCH /api/v1/crates/{name}` when `trustpub_only` changes (enable or disable)
- `DELETE /api/v1/crates/{name}` (crate delete; cookie sessions)
- Trusted Publishing config create/delete (`/api/v1/trusted_publishing/…`)

Acceptance: an active `api_mfa_grants` row covering the operation/crate, or (token clients) a valid unused OTP bound to that same operation/crate, or (token clients without grant/OTP) the `403` challenge handshake.

Grant matching:

- Challenge acknowledgment issues a grant bound to `api_token_id` (only that token can reuse it).
- Settings → Authorize issues a browser wildcard grant with `api_token_id = NULL`.
- Cookie requests accept only `api_token_id IS NULL` grants.
- API-token requests require an exact token-bound operation grant; browser
  authorization never authorizes a Cargo token.

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
- deletes challenges with `expires_at` older than 24 hours
- deletes expired grants and WebAuthn ceremony states
- deletes expired or consumed email OTPs

Instance metrics: `cratesio_instance_api_mfa_ensure_total{result=…}`, ensure duration histogram, challenges created, challenge polls.

Service gauge: `cratesio_service_api_mfa_challenges_pending`.

## Cargo integration

When Cargo understands protocol version 1, it prefers a localhost OTP callback
(`Cargo-Step-Up-Port` + `Cargo-Step-Up-Proof`) when interactive and concurrently retains
polling as a completion fallback, then retries publish / yank / unyank / owner
changes. Set `CARGO_REGISTRY_STEP_UP_CHANNEL` to `auto`, `localhost`, `poll`, or
`disabled`.
Use `poll` for an interactive SSH session whose browser runs on another machine.
The older `CARGO_STEP_UP_PREFER_LOCALHOST` test/demo override remains supported.

While Cargo lacks built-in handshake support, an opted-in user must:

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
- When API MFA is enabled, Settings → New Token and CLI link-login approve require a passkey assertion via the authorize ceremony (`POST /api/v1/me/mfa/authorize/start` + `credential`). Grant / operation OTP / challenge handshake apply only to dangerous crate ops (publish, yank, owners, `trustpub_only`). Registering an additional passkey while API MFA is enabled and at least one passkey remains also requires a recent passkey assertion. Addresses the trustpub-only untick → mint token → publish chain from a stolen session.
- Disabling API MFA requires a passkey assertion or email code.
- Pending challenges are capped per user (currently 10) to limit write amplification from a stolen token.
- WebAuthn ceremony state for register/authorize is stored server-side; challenge auth state is stored on the challenge row.
- Challenge acknowledgment issues mutation-scoped grants bound to the API token
  that created the challenge. Settings → Authorize issues a browser-cookie
  wildcard (`api_token_id` NULL) that API-token requests cannot reuse.

## Related improvement vectors (out of v1)

Treat API MFA as the interactive publish step-up layer only. Separate tracks remain:

- Package / index signing (artifact attestation): MFA proves a recent human ceremony for a mutate; it does not bind the published tarball to a long-term publisher key. Step-up MFA and package signing compose; neither replaces the other. Transport or long-lived key possession (including SSH agents) is not a substitute for presence-bound step-up or for signed package bytes.
- Tighter ceremony binding: publish acknowledgment already includes metadata and
  tarball hashes. Callback OTP is one-shot, while the polling fallback grant is
  token- and mutation-scoped. Keep browser Authorize separate from token grants.
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
challenge protocol), which obtains a new access token; this handshake instead
keeps the existing API token and records a request-bound challenge completion.
Authentication-method vocabulary follows
[NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

Complementary Cargo documentation (credential storage and providers, not this
mutate handshake):

- [Registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
- [Credential provider protocol](https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html)

Trusted Publishing remains the preferred path for non-interactive CI:
[crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing).

Asymmetric credentials and related RFCs (protocol cousins, separate track):
RFC 3231 (Cargo asymmetric tokens).

This handshake limits what a stolen long-lived API token can do for protected
operations. Credential providers reduce token exposure at rest; Trusted
Publishing can remove long-lived registry credentials from CI. Neither replaces
interactive step-up for human-held API tokens.
