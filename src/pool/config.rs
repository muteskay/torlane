use std::time::Duration;

use crate::pool::PoolConfigError;

pub const MAX_LANES: usize = 65_536;

#[derive(Debug, Clone, PartialEq)]
pub struct PoolConfig {
    pub lanes: usize,
    pub lane_ttl: Option<Duration>,
    pub lane_max_assignments: Option<u64>,
    pub bootstrap_timeout: Duration,
}

impl PoolConfig {
    pub fn new(lanes: usize) -> Self {
        Self {
            lanes,
            ..Self::default()
        }
    }

    pub fn lane_ttl(mut self, ttl: Duration) -> Self {
        self.lane_ttl = Some(ttl);
        self
    }

    pub fn lane_max_assignments(mut self, assignments: u64) -> Self {
        self.lane_max_assignments = Some(assignments);
        self
    }

    pub fn bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.bootstrap_timeout = timeout;
        self
    }

    pub fn validate(&self) -> Result<(), PoolConfigError> {
        if self.lanes == 0 {
            return Err(PoolConfigError::EmptyLanes);
        }
        if self.lanes > MAX_LANES {
            return Err(PoolConfigError::TooManyLanes {
                actual: self.lanes,
                max: MAX_LANES,
            });
        }
        if self.lane_ttl.is_some_and(|ttl| ttl.is_zero()) {
            return Err(PoolConfigError::ZeroLaneTtl);
        }
        if self.lane_max_assignments == Some(0) {
            return Err(PoolConfigError::ZeroLaneMaxAssignments);
        }
        if self.bootstrap_timeout.is_zero() {
            return Err(PoolConfigError::ZeroBootstrapTimeout);
        }
        Ok(())
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            lanes: 16,
            lane_ttl: None,
            lane_max_assignments: None,
            bootstrap_timeout: Duration::from_secs(90),
        }
    }
}
