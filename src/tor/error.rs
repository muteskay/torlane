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

    #[error("bridges enabled but no bridges configured")]
    BridgesEnabledButNoneConfigured,

    #[error("bridge transport `{0}` has no plugin")]
    MissingTransportPlugin(String),

    #[error("invalid obfs4 bridge: {0}")]
    InvalidObfs4Bridge(&'static str),

    #[error("{option}={value} outside range {min}..={max}")]
    OutOfRange {
        option: &'static str,
        value: i64,
        min: i64,
        max: i64,
    },

    #[error("metrics bound to a non-loopback address require an explicit access policy")]
    MetricsNonLoopbackWithoutPolicy,

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

#[derive(Debug, thiserror::Error)]
pub enum TorVerifyError {
    #[error("failed to write temporary torrc for verification: {0}")]
    Write(#[from] TorWriteError),

    #[error("failed to execute tor: {0}")]
    Io(#[from] io::Error),

    #[error("tor --verify-config failed with status {status:?}")]
    Failed {
        status: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum TorVersionError {
    #[error("failed to execute tor --version: {0}")]
    Io(#[from] io::Error),

    #[error("tor --version failed with status {status:?}: {stderr}")]
    Failed { status: Option<i32>, stderr: String },

    #[error("could not parse Tor version from output: {0}")]
    Parse(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TorRuntimeValidationError {
    #[error("path does not exist: {0}")]
    MissingPath(String),

    #[error("path is not executable: {0}")]
    NotExecutable(String),

    #[error("I/O error during runtime validation: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum TorIdentityError {
    #[error("identity count cannot be zero")]
    EmptyIdentityPool,

    #[error("failed to read secure random bytes: {0}")]
    Random(io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum TorProcessError {
    #[error("failed to start tor process: {0}")]
    Io(#[from] io::Error),

    #[error("tor child stdin was not available")]
    MissingStdin,
}
