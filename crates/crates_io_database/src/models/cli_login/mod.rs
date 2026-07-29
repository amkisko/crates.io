//! Models for browser-assisted cargo CLI login ceremonies.

mod session;

pub use session::{
    CliLoginSession, MAX_PENDING_CLI_LOGIN_PER_IP, NewCliLoginSession, STATUS_CONSUMED,
    STATUS_EXPIRED, STATUS_PENDING, STATUS_READY, TouchPollOutcome,
};
