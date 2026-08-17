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
    ZeroRestartBackoffInitial,
    ZeroRestartBackoffMax,
    RestartBackoffInitialExceedsMax,
    InvalidRestartBackoffMultiplier(f32),
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
            Self::ZeroRestartBackoffInitial => {
                formatter.write_str("restart backoff initial delay must be greater than zero")
            }
            Self::ZeroRestartBackoffMax => {
                formatter.write_str("restart backoff maximum delay must be greater than zero")
            }
            Self::RestartBackoffInitialExceedsMax => {
                formatter.write_str("restart backoff initial delay exceeds maximum delay")
            }
            Self::InvalidRestartBackoffMultiplier(value) => write!(
                formatter,
                "restart backoff multiplier must be finite and at least 1.0, got {value}"
            ),
        }
    }
}

impl std::error::Error for PoolConfigError {}
