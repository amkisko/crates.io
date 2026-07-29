# CLI link-login

Browser-assisted cargo login that mints a crates.io API token without showing the secret in the browser or the terminal. You pick scopes on the website; the CLI receives the token once over a poll API and stores it locally.

Stock cargo login still expects a pasted token. Settings → New Token shows that secret in the UI. Link-login is the path that keeps it off-screen. New Token remains available for CI and other manual setups.

## Install

From a crates.io checkout:

```bash
cargo install --path crates/cargo_credential_crates_io --locked
```

Put `cargo-credential-crates-io` on your PATH, then in `~/.cargo/config.toml`:

```toml
[registry]
global-credential-providers = ["cargo-credential-crates-io", "cargo:token"]
```

## Use it

Run `cargo login`. The provider starts a short-lived session, prints a login URL and a confirmation code on stderr, and waits. Open that URL, sign in, enter the confirmation code from the terminal, choose name, scopes, and expiry, then approve. The code binds the browser step to the CLI that started the session (it is not shown on the page). The provider polls until the token is ready, writes it to `~/.cargo/credentials.toml` under `[registry]`, and finishes without printing the secret. Later cargo commands load it through the provider’s get action.

If API MFA is enabled, approve also asks for a passkey (same step-up as disabling MFA). When MFA is on with zero passkeys, approve accepts an email OTP instead so recovery is not a dead-end. See [API-MFA.md](API-MFA.md).

## Staging or local

```bash
export CARGO_REGISTRY_CRATES_IO_URL=https://staging.crates.io
cargo login
```

You can also pass `--api-base=…` in the credential-provider entry in config.toml (for example `http://127.0.0.1:8888`).

## How the API fits together

Unauthenticated clients create a session with `POST /api/v1/cli_login` and receive a login URL, a poll URL, a one-time `confirmation_code`, a `poll_secret`, an expiry, and a recommended poll interval (currently 2 seconds; do not poll faster). The confirmation code and poll secret are stored hashed; `meta` never returns either. The confirmation code binds the browser approve step; the poll secret binds redeem to the CLI that started the session (observers of `login_id` / `login_url` alone cannot take the token).

`GET /api/v1/cli_login/{id}` requires header `Crates-Cli-Login-Secret: <poll_secret>` and reports pending, ready (with the token once), consumed, or expired.

Signed-in browsers load metadata from `GET /api/v1/cli_login/{id}/meta` (including the starter client IP) and finish with `POST /api/v1/cli_login/{id}/approve`, which requires `confirmation_code` matching the CLI start. Approve mints the token but does not return the plaintext; the response may include `localhost_port` so the browser can ping a waiting CLI without the secret. The CLI picks the token up on the next successful poll (with `poll_secret`). While waiting for redeem, the server stores an encrypted blob, not the raw token.

Approving a CLI login records a durable `cli_login_approved` security event (truncated starter IP). See [SECURITY-ACTIVITY.md](SECURITY-ACTIVITY.md).

## Ops

Enqueue `crates-admin enqueue-job api_mfa_cleanup` at least every 15 minutes so expired and consumed `cli_login_sessions` rows are deleted. Prometheus gauge `cratesio_service_cli_login_sessions` (label `status`) tracks table size by status.

Set `CLI_LOGIN_ENABLED=false` to disable session creation and poll (approve returns the same unavailable response). Default is enabled.

Create/poll pacing honors `RATE_LIMITER_CLI_LOGIN_CREATE_RATE_SECONDS` / `_BURST` and `RATE_LIMITER_CLI_LOGIN_POLL_RATE_SECONDS` (defaults: 30s window / burst 10 creates per IP; 2s min poll interval).
