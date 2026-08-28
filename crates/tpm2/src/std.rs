//! Standard Library Integrations
//!
//! This module implements standard-library-specific traits and type conversions
//! for types defined in the `tpm2` crate.

extern crate std;

use crate::errors::{TpmRc, UnmarshalError};

impl From<TpmRc> for std::io::Error {
    fn from(value: TpmRc) -> Self {
        std::io::Error::other(value)
    }
}

impl From<UnmarshalError> for std::io::Error {
    fn from(value: UnmarshalError) -> Self {
        std::io::Error::other(value)
    }
}
