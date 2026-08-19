use std::io;

/// A [`TorConfigBuilder`](crate::low_level::TorConfigBuilder) configuration
/// failed validation.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TorConfigError {
    /// Neither a Control Port nor any SOCKS listener was configured.
    #[error("at least one listener is required")]
    NoListeners,

    /// The Control Port is configured with no authentication on a
    /// non-loopback address, which would expose it to the network.
    #[error("unauthenticated non-loopback ControlPort is forbidden")]
    UnauthenticatedNonLoopbackControlPort,

    /// [`SocksConfig::port_range`](crate::low_level::SocksConfig::port_range)
    /// was called with a count of zero.
    #[error("SOCKS port count cannot be zero")]
    EmptySocksPortRange,

    /// [`SocksConfig::port_range`](crate::low_level::SocksConfig::port_range)'s
    /// requested range does not fit in `u16`.
    #[error("SOCKS port range exceeds u16")]
    PortRangeOverflow,

    /// Two listeners (Control Port and/or SOCKS) were configured on the
    /// same TCP port.
    #[error("listener port {0} is duplicated")]
    DuplicatePort(u16),

    /// A bridge references a pluggable transport with no matching
    /// `ClientTransportPlugin` registered.
    #[error("bridge transport `{0}` has no plugin")]
    MissingTransportPlugin(String),

    /// An obfs4 bridge is missing a required field or has an invalid value.
    #[error("invalid obfs4 bridge: {0}")]
    InvalidObfs4Bridge(&'static str),

    /// [`TorOption::new`](crate::low_level::TorOption::new)'s key was empty
    /// or contained whitespace/control characters.
    #[error("invalid raw option key")]
    InvalidRawOptionKey,

    /// [`TorOption::new`](crate::low_level::TorOption::new)'s value
    /// contained a newline or NUL byte.
    #[error("invalid raw option value")]
    InvalidRawOptionValue,
}

/// Writing a rendered `torrc` to disk failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorWriteError {
    /// The destination path has no parent directory to create.
    #[error("destination path has no parent directory")]
    MissingParentDirectory,

    /// The underlying file write failed.
    #[error("I/O error while writing torrc: {0}")]
    Io(#[from] io::Error),
}
