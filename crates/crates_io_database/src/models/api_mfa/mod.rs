//! Models for API MFA (passkey step-up for sensitive token-authenticated actions).

mod ceremony;
mod challenge;
mod email_otp;
mod grant;
mod webauthn_credential;

pub use ceremony::{WebauthnCeremonyState, KIND_AUTHENTICATION, KIND_REGISTRATION};
pub use challenge::{
    ApiMfaChallenge, NewApiMfaChallenge, NewApiMfaChallengeOperation, NewApiMfaMutationDescriptor,
    MAX_PENDING_CHALLENGES_PER_USER,
};
pub use email_otp::{ApiMfaEmailOtp, DEFAULT_EMAIL_OTP_DURATION_SECS};
pub use grant::{ApiMfaGrant, NewApiMfaGrant};
pub use webauthn_credential::{NewWebauthnCredential, WebauthnCredential, MAX_PASSKEYS_PER_USER};
