//! Models for passkeys, product-session API MFA, and Cargo mutation authorization.

mod ceremony;
mod challenge;
mod email_otp;
mod grant;
mod webauthn_credential;

pub use ceremony::{KIND_AUTHENTICATION, KIND_REGISTRATION, WebauthnCeremonyState};
pub use challenge::{
    ApiMfaChallenge, DEFAULT_CHALLENGE_DURATION_SECS, MAX_PENDING_CHALLENGES_PER_USER,
    MUTATION_RECEIVE_LEASE_SECS, MUTATION_TERMINAL_RETENTION_SECS, MutationPollStatus,
    NewApiMfaChallenge, NewApiMfaChallengeOperation, NewApiMfaMutationDescriptor,
};
pub use email_otp::{ApiMfaEmailOtp, DEFAULT_EMAIL_OTP_DURATION_SECS};
pub use grant::{ApiMfaGrant, NewApiMfaGrant};
pub use webauthn_credential::{MAX_PASSKEYS_PER_USER, NewWebauthnCredential, WebauthnCredential};
