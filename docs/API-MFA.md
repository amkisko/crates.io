# API MFA (passkey step-up)

Opt-in protection so publish, yank, and owner changes require a recent passkey verification — for API tokens and for website cookie sessions.

A token-authenticated dangerous API call returns a short-lived operation handshake; the browser completes passkey verification without a crates.io cookie while the CLI receives acknowledgment (localhost OTP callback, or poll). `cargo login` still mints the API token before `cargo publish`. Cookie sessions use the settings "Authorize for 15 minutes" grant instead of that handshake.

## Threat model

Long-lived API token (`~/.cargo/credentials`):

- Without API MFA: immediate publish, yank, or owner change
- With API MFA: blocked until passkey acknowledgment (CLI challenge or active grant / OTP)

GitHub session / crates.io cookie:

- Without API MFA: can mint tokens and act in the browser
- With API MFA: publish, yank, and owner changes from the site require an active grant (Authorize for 15 minutes); Settings → New Token, token revoke-by-id, and CLI link-login approve require a passkey assertion (or email OTP on CLI approve when MFA is on with zero passkeys); registering an additional passkey requires a passkey assertion when one exists. Self-revoke of the current token (`DELETE /api/v1/tokens/current`) stays free.
- Bootstrap / recovery: enabling API MFA, first passkey enrollment, and recovery enrollment (zero passkeys) require a verified-email OTP so a stolen session cookie alone cannot plant a passkey and turn on enforcement. Enabling MFA also bumps `users.session_generation` (other browsers are signed out; the enabling browser keeps a refreshed cookie). Disabling API MFA requires a passkey assertion or email OTP. Enforcement may remain on with zero passkeys (dangerous actions stay blocked until a passkey is re-registered or MFA is disabled via email OTP).
- Changing away from a verified email requires an email OTP sent to the current verified address, and the verified inbox stays active until the new address is confirmed (`emails.pending_email`). A stolen session cannot redirect MFA recovery to an attacker inbox without both the OTP and control of the new inbox.
- Sessions are signed client cookies carrying `user_id` and `session_generation`. Settings → Profile → Sign out everywhere bumps generation so every other browser session fails cookie auth.

Trusted Publishing (`cio_tp_…`) OIDC token:

- Trusted Publishing is the automation path; API MFA is the interactive-token path. OIDC publish stays ungated either way (OIDC identity is the second factor) so CI does not sit on a passkey prompt. Non-OIDC CI that still uses a long-lived API token needs a human MFA step (or Trusted Publishing / a future scoped automation token).
- TrustPub only becomes available after the crate already exists. The first publish (and other bootstrap ownership work) still needs a long-lived API token or a cookie session — the window where a stolen token is most dangerous. API MFA closes that bootstrap gap; the same step-up can later cover other unsafe operations that still need human supervision (yank, owners, delete, TrustPub config, and similar).

Passkeys vs token scopes / identity:

- GitHub OAuth remains account identity. Passkeys are account-wide second factors for step-up (approve and mutate); they are not a login replacement and have no capability scopes in v1. Least privilege stays on API token scopes. Passkey `name` and `last_used_at` (plus register/delete in the security activity feed) are hygiene only.

Multi-owner / team crates:

- If any individual owner has `api_mfa_enabled`, dangerous mutates on that crate require MFA for the acting user (including team members and co-owners who have not opted in yet). Actors without MFA enabled get a clear error to enable API MFA first. Instant GitHub team owner-add is unchanged. Trusted Publishing OIDC publish still skips MFA. Optional `trustpub_only` remains a separate crate-level control.

GitHub account 2FA does not protect a leaked cargo token ([rust-lang/crates.io#815](https://github.com/rust-lang/crates.io/issues/815)).

## Design intention: human-in-the-loop signature

API MFA requires a recent, interactive second factor for each dangerous action. Possession of another long-lived secret is insufficient.

Publishers must use a passkey, or another factor with equivalent properties: a key, token, or service that produces a cryptographic signature for this specific operation and normally requires manual interaction on the user's machine (confirm, touch, or presence). The verify page is a separate browser step: open the URL, complete the authenticator prompt, leave a server-side acknowledgment tied to that ceremony.

The goal is to raise the cost of going from a stolen cargo token to a silent publish. Full automation remains possible in principle (headless WebAuthn, remote authenticators, malware on the machine); this design only shrinks the easy paths.

Acceptable factors share these properties:

- Signature (or equivalent proof) is single-use and bound to this challenge / operation.
- Normal use involves human presence (user gesture, biometric, PIN + touch) at verification time.
- Crates.io records a ceremony trace (challenge → acknowledgment / grant / OTP) linked to the dangerous API call.

WebAuthn passkeys are the supported mechanism for per-operation step-up today.

Email OTP is not an API MFA factor for publish, yank, or owner actions. It is only a bootstrap / recovery step-up for settings changes (enable MFA, first or recovery passkey enrollment, disable MFA when passkeys are unavailable, and staging a verified-email change). Possession of a verified inbox is weaker than a presence-bound passkey; it closes session-hijack paths without replacing the human-in-the-loop rule for dangerous API calls.

SSH pubkey authentication is out of scope as an API MFA factor. SSH auth proves key possession to an SSH server; API MFA needs a crates.io-bound signature over the publish/yank/owner challenge, a per-operation presence step on the machine that is about to act, and a server-side ceremony record for that `operation_id`. Agent-backed SSH (`ssh-agent`, CI keys, forwarded agents) typically supplies only silent key use. Accepting "can SSH as this user" would treat another long-lived key as MFA and miss the human-in-the-loop rule above.

Any future factor (hardware token protocol, external signing service, etc.) must keep per-operation proof, intentional user interaction in the common case, and an auditable acknowledgment path. Silent pubkey possession alone is insufficient.

## CLI handshake (primary flow)

1. Register a passkey under Settings → API MFA and enable enforcement.
2. CLI performs a dangerous action (`cargo publish`, yank, change owners) with an API token.
3. Preferred (localhost OTP): CLI binds `127.0.0.1`, sends `Crates-MFA-Port` plus a client-held `Crates-MFA-Callback-Secret`, and waits for the verify page to `GET http://127.0.0.1:{port}/?code={otp}`.
4. Fallback (stock / remote): omit the port; API responds `403` with structured fields and the CLI polls until acknowledged.
5. API `403` fields:
   - `operation_id` — temporary transaction id (`mfa_…`)
   - `verification_url` — browser page for passkey verification (`/mfa/verify/{operation_id}`; no sign-in)
   - `poll_url` — `GET /api/v1/mfa/challenges/{operation_id}`
   - `expires_at` — short TTL (5 minutes)
   - `recommended_poll_interval_secs` — currently `2` (do not poll faster)
6. User opens the link and completes passkey check. The verify page does not require a crates.io cookie; the opaque `operation_id` is the capability, and the passkey proves control of the account that owns the token.
7. CLI retries the original request (idempotent):
   - With `Crates-MFA-Port`: finish returns `localhost_callback_url` + OTP and does not insert a grant; retry with `Crates-OTP` / `OTP`.
   - Without port: finish issues a 15-minute scoped grant (same operation + crate) so poll-then-retry works without OTP headers.

Optional headers on the dangerous request:

- `Crates-MFA-Port` — localhost port for OTP callback after verification (skips scoped grant; refreshed if a pending challenge is reused)
- `Crates-MFA-Callback-Secret` — URL-safe client secret authorizing callback port refreshes; callback mode cannot be downgraded to a polling grant
- `Crates-MFA-Operation-Id` — reuse a previous `operation_id` for an idempotent handshake
- `Crates-OTP` / `OTP` — one-time code after verification (required for the localhost path; alternative to grant retry)

Retries of the same token + operation + crate reuse the pending challenge until it expires or is acknowledged.

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

- Challenge acknowledgment issues a grant bound to `api_token_id` (only that token can ride it).
- Settings → Authorize issues a wildcard grant with `api_token_id = NULL` (covers cookie sessions and any of that user’s tokens — stock cargo escape hatch).
- Cookie requests accept only `api_token_id IS NULL` grants.

Cookie sessions without a grant receive `400` asking the user to Authorize for 15 minutes under Settings → API MFA.

Owner invitation accept (`PUT /api/v1/me/crate_owner_invitations/accept/{token}` and the authenticated accept path) requires a cookie session for the invitee. The path token selects the invitation; it is not a standalone bearer capability. When the invitee has API MFA enabled (or the crate already has an MFA owner), accept requires an Authorize grant.

## Manual authorize

"Authorize for 15 minutes" on the settings page issues a wildcard grant (any operation/crate). Use it for:

- website publish / yank / owner / delete / Trusted Publishing config changes while MFA is enabled
- toggling `trustpub_only` on crate settings while MFA is enabled
- CLI clients that do not yet speak `mfa_required` (released stock cargo until MFA support lands; see [Cargo integration](#cargo-integration))

Challenge acknowledgment remains scoped to the operation + crate that created the challenge. With cargo MFA support, challenge acknowledgment already issues a scoped grant for the operation + crate; the settings wildcard grant remains the escape hatch for the website and older clients.

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
- `API_MFA_ENFORCEMENT_ENABLED` (default: `true`) — when `false`, skips MFA on dangerous mutates only (publish/yank/owners/delete/trustpub/invite-accept). Bootstrap / plant-prevention gates stay on (enable/disable OTP, passkey enroll/delete, New Token, token revoke-by-id, CLI approve, verified-email change). Status GET reports `enabled` (user opt-in) and `enforcement_active` (this flag). Use for emergency bypass (e.g. WebAuthn/RP outage).

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

Upstream support lives in the cargo fork branch
[`feature/crates-io-api-mfa`](https://github.com/amkisko/cargo/tree/feature/crates-io-api-mfa)
(`amkisko/cargo`): on `mfa_required`, cargo prefers a localhost OTP callback
(`Crates-MFA-Port` + `Crates-OTP`) when interactive, and falls back to polling
`poll_url` until acknowledged, then retries publish / yank / unyank / owner
changes. Set `CARGO_API_MFA_PREFER_LOCALHOST=1` to force the OTP path.

Until that lands in rust-lang/cargo releases:

- use the settings "Authorize for 15 minutes" grant, or
- build/run cargo from that branch, or
- a wrapper/tool can show `verification_url`, complete localhost OTP or poll
  `poll_url` every `recommended_poll_interval_secs`, then retry.

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

- Opt-in only; popular-crate mandates are out of scope here ([#815](https://github.com/rust-lang/crates.io/issues/815)).
- When API MFA is enabled, Settings → New Token and CLI link-login approve require a passkey assertion via the authorize ceremony (`POST /api/v1/me/mfa/authorize/start` + `credential`). Grant / operation OTP / challenge handshake apply only to dangerous crate ops (publish, yank, owners, `trustpub_only`). Registering an additional passkey while API MFA is enabled and at least one passkey remains also requires a fresh passkey assertion. Addresses the untick step in [discussion #13369](https://github.com/rust-lang/crates.io/discussions/13369) / [#13367](https://github.com/rust-lang/crates.io/issues/13367).
- Disabling API MFA requires a passkey assertion or email code.
- Pending challenges are capped per user (currently 10) to limit write amplification from a stolen token.
- WebAuthn ceremony state for register/authorize is stored server-side; challenge auth state lives on the challenge row.
- Challenge acknowledgment issues operation+crate grants bound to the API token that created the challenge. Settings → Authorize issues a user-scoped wildcard (`api_token_id` NULL) that cookie sessions and any of that user’s tokens can ride for the grant TTL (stock cargo escape hatch).

## Related improvement vectors (out of v1)

Treat API MFA as the interactive publish step-up layer only. Separate tracks remain:

- Package / index signing (artifact attestation): MFA proves a recent human ceremony for a mutate; it does not bind the published tarball to a long-term publisher key. Step-up MFA and package signing compose; neither replaces the other. Transport or long-lived key possession (including SSH agents) is not a substitute for presence-bound step-up or for signed package bytes.
- Tighter ceremony binding: bind acknowledgment to upload content hashes and/or prefer one-shot OTP once cargo speaks `mfa_required`. Challenge grants are already token-scoped; keep wildcard Authorize as the multi-use website escape hatch.
- Scoped automation tokens: Trusted Publishing covers OIDC CI; non-OIDC automation still needs a human MFA step or a future short-lived / scoped automation token (automation bypass policy is a separate product decision, not part of this design).
- Consumer trust policy: optional client or UI signals for `trustpub_only`, MFA-enabled owners, or signed crates; complements ecosystem mandates under [#815](https://github.com/rust-lang/crates.io/issues/815).
- Public provenance: optional version metadata that a publish completed after an MFA ceremony or Trusted Publishing exchange, without exposing private activity IPs or challenge ids.
- Compromise hygiene: passkey / credential revocation feeds or Activity prompts when credentials are known-bad, beyond settings-change emails.
- Optional passkey alternative on verified-email change when API MFA is on (OTP to the current inbox remains the v1 step-up).
