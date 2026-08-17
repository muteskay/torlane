#[derive(Debug, thiserror::Error)]
pub enum LaneError {
    #[error("lane epoch overflow for lane {0}")]
    EpochOverflow(u32),

    #[error("failed to generate lane credentials: {0}")]
    Random(#[from] rand::Error),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PoolConfigError {
    EmptyLanes,
    TooManyLanes { actual: usize, max: usize },
    ZeroLaneTtl,
    ZeroLaneMaxAssignments,
    ZeroBootstrapTimeout,
}

impl std::fmt::Display for PoolConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLanes => formatter.write_str("lane count must be greater than zero"),
            Self::TooManyLanes { actual, max } => {
                write!(formatter, "lane count {actual} exceeds maximum {max}")
            }
            Self::ZeroLaneTtl => formatter.write_str("lane TTL must be greater than zero"),
            Self::ZeroLaneMaxAssignments => {
                formatter.write_str("lane max assignments must be greater than zero")
            }
            Self::ZeroBootstrapTimeout => {
                formatter.write_str("bootstrap timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for PoolConfigError {}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("pool configuration is invalid: {0}")]
    Config(#[from] PoolConfigError),

    #[error("Tor instance failed: {0}")]
    Instance(#[from] crate::tor::instance::TorInstanceError),

    #[error("lane operation failed: {0}")]
    Lane(#[from] LaneError),

    #[error("pool work directory is required")]
    MissingWorkDir,

    #[error("no ready lanes")]
    NoReadyLanes,

    #[error("lane {0:?} is unavailable")]
    LaneUnavailable(crate::pool::LaneId),

    #[error("unknown lane {0:?}")]
    UnknownLane(crate::pool::LaneId),

    #[error("pool manager is closed")]
    ManagerClosed,

    #[error("restart requires a managed Tor instance")]
    RestartUnavailable,

    #[error("pool manager task failed: {0}")]
    ManagerTask(#[from] tokio::task::JoinError),
}
