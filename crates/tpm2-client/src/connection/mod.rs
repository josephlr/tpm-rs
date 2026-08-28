//! The connection module provides the top level [`Connection`] trait and
//! common implementations (as submodules) of the trait.

#[cfg(feature = "connection-tcp")]
pub mod tcp;

pub use tpm2::Connection;
