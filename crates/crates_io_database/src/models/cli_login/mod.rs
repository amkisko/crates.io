//! Models for browser-assisted cargo CLI login ceremonies.

mod session;

pub use session::{
    CliLoginSession, NewCliLoginSession, TouchPollOutcome, MAX_PENDING_CLI_LOGIN_PER_IP,
    STATUS_CONSUMED, STATUS_EXPIRED, STATUS_PENDING, STATUS_READY,
};
