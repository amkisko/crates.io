//! API MFA endpoints: passkey registration, grants, and CLI verification challenges.

pub mod authorize;
pub mod challenges;
pub mod email_codes;
pub(crate) mod notify;
pub mod passkeys;
pub mod status;
pub(crate) mod webauthn_util;
