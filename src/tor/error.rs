use std::io;

use crate::tor::torc::TorWriteError;

/// Running `tor --verify-config` failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorVerifyError {
    /// Writing the rendered `torrc` for verification failed.
    #[error("failed to write torrc for verification: {0}")]
    Write(#[from] TorWriteError),

    /// Launching the `tor` executable failed.
    #[error("failed to execute tor: {0}")]
    Io(#[from] io::Error),

    /// `tor --verify-config` exited with a non-success status.
    #[error("tor --verify-config failed with status {status:?}")]
    Failed {
        /// The process exit code, if available.
        status: Option<i32>,
        /// The captured standard output.
        stdout: String,
        /// The captured standard error.
        stderr: String,
    },
}

/// Detecting the installed Tor version failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorVersionError {
    /// Launching `tor --version` failed.
    #[error("failed to execute tor --version: {0}")]
    Io(#[from] io::Error),

    /// `tor --version` exited with a non-success status.
    #[error("tor --version failed with status {status:?}: {stderr}")]
    Failed {
        /// The process exit code, if available.
        status: Option<i32>,
        /// The captured standard error.
        stderr: String,
    },

    /// The version string in `tor --version`'s output could not be parsed.
    #[error("could not parse Tor version from output: {0}")]
    Parse(String),
}

/// Validating that a Tor binary and its configured paths are usable failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorRuntimeValidationError {
    /// A required path does not exist.
    #[error("path does not exist: {0}")]
    MissingPath(String),

    /// A required path exists but is not executable.
    #[error("path is not executable: {0}")]
    NotExecutable(String),

    /// An I/O error occurred while checking paths.
    #[error("I/O error during runtime validation: {0}")]
    Io(#[from] io::Error),
}

/// Generating a [`TorIdentityPool`](crate::low_level::TorIdentityPool)
/// failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorIdentityError {
    /// The requested identity count was zero.
    #[error("identity count cannot be zero")]
    EmptyIdentityPool,

    /// Reading secure random bytes for a credential failed.
    #[error("failed to read secure random bytes: {0}")]
    Random(#[from] rand::Error),
}

/// Spawning or communicating with a [`TorProcess`](crate::low_level::TorProcess) failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorProcessError {
    /// Launching the `tor` executable failed.
    #[error("failed to start tor process: {0}")]
    Io(#[from] io::Error),

    /// Writing the rendered `torrc` (to a file, or to the child's stdin)
    /// failed.
    #[error("failed to write torrc for tor process: {0}")]
    Write(#[from] TorWriteError),

    /// The child process's stdin handle was not available to write the
    /// configuration to.
    #[error("tor child stdin was not available")]
    MissingStdin,
}
