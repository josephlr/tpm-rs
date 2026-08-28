//! TPM 2.0 Commands and Request/Response Protocol Layout
//!
//! This module defines the request parameters, response parameters, handle lists,
//! and [`Command`](crate::Command) trait implementations for TPM 2.0 commands.

mod random;
mod startup;

pub use {
    random::{GetRandom, StirRandom},
    startup::{Shutdown, Startup},
};

pub mod responses {
    pub use super::random::GetRandomRsp as GetRandom;
}
