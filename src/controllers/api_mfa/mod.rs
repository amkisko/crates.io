//! API MFA endpoints: passkey registration, grants, and CLI verification challenges.

pub mod authorize;
pub mod challenges;
pub mod credentials;
pub mod status;
pub(crate) mod webauthn_util;
