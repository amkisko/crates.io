# Security activity feed

Settings → Activity and `GET /api/v1/me/security_events` show recent account security events to the signed-in owner only. The feed exists so people can see sign-ins, API token changes, CLI login approvals, and API MFA actions. It is not used for analytics, ads, or ranking. This is a best-effort user activity feed, not an authoritative forensic audit log; an event-write failure does not fail the parent account operation.

## Events

These event types may appear:

- `session_login` — GitHub OAuth session established
- `session_logout_all` — Sign out everywhere (session generation bumped)
- `cli_login_approved` — browser approved a CLI link-login
- `token_created`, `token_revoked`, `token_revoked_github` — API token lifecycle
- `token_used` — at most once per token per UTC day; no IP stored
- `api_mfa_enabled`, `api_mfa_disabled` — enforcement toggle
- `passkey_registered`, `passkey_deleted` — passkey lifecycle
- `api_mfa_authorized` — Settings “Authorize for 15 minutes”
- `api_mfa_challenge_verified` — CLI challenge acknowledgment
- `email_changed` — pending verified-email change promoted after OTP step-up and confirm-link (no address stored in metadata)

## Retention and access

The retention policy is up to 90 days. Enforcement depends on a monitored daily
`crates-admin enqueue-job security_events_cleanup` schedule
(`security_events::purge_expired`). Deleting a user account cascades and removes
their events.

Only the account owner’s cookie session can read the feed (internal API). Responses never include secrets, hashes, passkey material, or sealed CLI tokens. The Activity page and list API are the access path for data-subject requests about this feed.

## What we store with each event

Metadata is limited to these keys when present: `token_name`, `crate_name`, `operation`, `passkey_name`, `challenge_id`. Nothing else (no user-agent, geo, email, ASN, or free-form request dumps).

IP addresses are stored only when useful for that event (for example session login or CLI approve). They are truncated at write time to IPv4 /24 or IPv6 /56. `token_used` never stores an IP. IPs from this feed are not written to application or Sentry logs; see LOGGING.md.

## Abuse limits

A user may have at most 50 active (non-revoked, non-expired) API tokens and at most 10 passkeys.

## Deployment gate

Collection and feed reads are controlled by `SECURITY_ACTIVITY_ENABLED`, which
defaults to `false`. When disabled, event producers do not insert rows and the
owner endpoint returns an empty feed.

Enable it only after:

- the privacy notice below is approved and published;
- ownership for the daily purge job is assigned;
- missed/failed purge runs alert an operator;
- monitoring verifies that the oldest retained row remains within policy;
- event-write failures have a metric or alert, since best-effort recording can
  otherwise leave gaps.

## Privacy notice update (Rust Foundation)

Propose the following addition to the crates.io section of the [Rust Foundation privacy notice](https://foundation.rust-lang.org/policies/privacy-policy/) (Specific services → crates.io). Process under security / legitimate interest, not analytics.

---

When you use crates.io account security features, we may also process:

- truncated IP addresses and short security-event records (for example sign-in, API token create or revoke, CLI login approval, API MFA enable or disable, passkey register or delete, and MFA challenge acknowledgment) so you can review recent activity on your account and so we can support account security. These records are visible only to you, are retained for up to 90 days, and are deleted when your account is deleted;
- emails about API MFA settings changes, and short-lived email verification codes used to enable or disable API MFA, enroll or recover a passkey, or change a verified email address (not as the second factor for publish, yank, or owner changes);
- during browser-assisted cargo login, the client IP that started the login session, shown to you on the approve page so you can spot unexpected requests. If you approve, a truncated form of that IP may appear in your security activity feed as above.

We do not use this security activity information for product analytics, advertising, or ranking.

---

Related: [API-MFA.md](API-MFA.md), [CLI-LOGIN.md](CLI-LOGIN.md).
