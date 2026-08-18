use std::io;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TorConfigError {
    #[error("at least one listener is required")]
    NoListeners,

    #[error("unauthenticated non-loopback ControlPort is forbidden")]
    UnauthenticatedNonLoopbackControlPort,

    #[error("SOCKS port count cannot be zero")]
    EmptySocksPortRange,

    #[error("SOCKS port range exceeds u16")]
    PortRangeOverflow,

    #[error("listener port {0} is duplicated")]
    DuplicatePort(u16),

    #[error("bridge transport `{0}` has no plugin")]
    MissingTransportPlugin(String),

    #[error("invalid obfs4 bridge: {0}")]
    InvalidObfs4Bridge(&'static str),

    #[error("invalid raw option key")]
    InvalidRawOptionKey,

    #[error("invalid raw option value")]
    InvalidRawOptionValue,
}

#[derive(Debug, thiserror::Error)]
pub enum TorWriteError {
    #[error("destination path has no parent directory")]
    MissingParentDirectory,

    #[error("I/O error while writing torrc: {0}")]
    Io(#[from] io::Error),
}
