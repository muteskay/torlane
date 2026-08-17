use std::io;

use crate::tor::torc::TorWriteError;

#[derive(Debug, thiserror::Error)]
pub enum TorVerifyError {
    #[error("failed to write torrc for verification: {0}")]
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
    Random(#[from] rand::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum TorProcessError {
    #[error("failed to start tor process: {0}")]
    Io(#[from] io::Error),

    #[error("failed to write torrc for tor process: {0}")]
    Write(#[from] TorWriteError),

    #[error("tor child stdin was not available")]
    MissingStdin,
}
