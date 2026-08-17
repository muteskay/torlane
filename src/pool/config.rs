use std::time::Duration;

use crate::pool::PoolConfigError;

pub const MAX_LANES: usize = 65_536;

#[derive(Debug, Clone, PartialEq)]
pub struct RestartBackoff {
    pub initial: Duration,
    pub max: Duration,
    pub multiplier: f32,
}

impl Default for RestartBackoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolConfig {
    pub lanes: usize,
    pub lane_ttl: Option<Duration>,
    pub lane_max_assignments: Option<u64>,
    pub bootstrap_timeout: Duration,
    pub restart_backoff: RestartBackoff,
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

    pub fn restart_backoff(mut self, backoff: RestartBackoff) -> Self {
        self.restart_backoff = backoff;
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
        self.validate_restart_backoff()
    }

    fn validate_restart_backoff(&self) -> Result<(), PoolConfigError> {
        let backoff = &self.restart_backoff;
        if backoff.initial.is_zero() {
            return Err(PoolConfigError::ZeroRestartBackoffInitial);
        }
        if backoff.max.is_zero() {
            return Err(PoolConfigError::ZeroRestartBackoffMax);
        }
        if backoff.initial > backoff.max {
            return Err(PoolConfigError::RestartBackoffInitialExceedsMax);
        }
        if !backoff.multiplier.is_finite() || backoff.multiplier < 1.0 {
            return Err(PoolConfigError::InvalidRestartBackoffMultiplier(
                backoff.multiplier,
            ));
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
            restart_backoff: RestartBackoff::default(),
        }
    }
}
