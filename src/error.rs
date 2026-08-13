use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Authentication,
    CannotOpen,
    IdentityMismatch,
    InvalidInput(&'static str),
    Io(io::Error),
    NotFound(&'static str),
    Randomness,
    Usage(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => formatter.write_str("authentication failed"),
            Self::CannotOpen => formatter.write_str("Cannot open blob."),
            Self::IdentityMismatch => formatter.write_str("IDENTITY MISMATCH\nPOSSIBLE MITM"),
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::NotFound(message) => formatter.write_str(message),
            Self::Randomness => formatter.write_str("operating-system randomness failed"),
            Self::Usage(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
