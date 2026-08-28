use core::{error::Error, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerError {
    DrbgError,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::DrbgError => write!(f, "Drbg operation failed"),
        }
    }
}

impl Error for ServerError {}
