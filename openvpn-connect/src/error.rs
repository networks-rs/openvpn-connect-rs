use std::fmt;

/// Errors returned by the safe OpenVPN client API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// OpenVPN Core rejected an operation.
    Core {
        /// Stable short status when supplied by OpenVPN Core.
        status: String,
        /// Human-readable diagnostic.
        message: String,
    },
    /// An operation was not valid in the client's current lifecycle state.
    InvalidState(&'static str),
    /// A requested optional Core capability is absent from the linked artifact.
    UnsupportedCapability {
        /// Stable native capability name.
        capability: &'static str,
        /// Actionable build or configuration guidance.
        detail: &'static str,
    },
    /// The native client could not be allocated.
    Initialization(String),
    /// A Tokio task or channel required by an asynchronous session failed.
    Runtime(String),
    /// The asynchronous session has already exited.
    SessionClosed,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core { status, message } if status.is_empty() => formatter.write_str(message),
            Self::Core { status, message } if message.is_empty() => formatter.write_str(status),
            Self::Core { status, message } => write!(formatter, "{status}: {message}"),
            Self::InvalidState(message) => formatter.write_str(message),
            Self::UnsupportedCapability { capability, detail } => {
                write!(
                    formatter,
                    "OpenVPN Core capability `{capability}` is unavailable: {detail}"
                )
            }
            Self::Initialization(message) | Self::Runtime(message) => formatter.write_str(message),
            Self::SessionClosed => formatter.write_str("the OpenVPN session is closed"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias used by this crate.
pub type Result<T> = std::result::Result<T, Error>;
