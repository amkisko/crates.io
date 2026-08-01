//! Models for API MFA (passkey step-up for sensitive token-authenticated actions).

mod ceremony;
mod challenge;
mod email_otp;
mod grant;
mod webauthn_credential;

pub use ceremony::{KIND_AUTHENTICATION, KIND_REGISTRATION, WebauthnCeremonyState};
pub use challenge::{
    ApiMfaChallenge, DEFAULT_CHALLENGE_DURATION_SECS, MAX_PENDING_CHALLENGES_PER_USER,
    MUTATION_RECEIVE_LEASE_SECS, MutationPollStatus, NewApiMfaChallenge,
    NewApiMfaChallengeOperation, NewApiMfaMutationDescriptor,
};
pub use email_otp::{ApiMfaEmailOtp, DEFAULT_EMAIL_OTP_DURATION_SECS};
pub use grant::{ApiMfaGrant, NewApiMfaGrant};
pub use webauthn_credential::{MAX_PASSKEYS_PER_USER, NewWebauthnCredential, WebauthnCredential};
