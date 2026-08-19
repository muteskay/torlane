use std::time::Duration;

use crate::RotationPolicy;

/// The largest number of lanes a [`PoolConfig`] can request.
pub const MAX_LANES: usize = 65_536;

/// Managed pool topology: lane count, rotation policy, and bootstrap
/// timeout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoolConfig {
    pub(crate) lanes: usize,
    pub(crate) rotation: RotationPolicy,
    pub(crate) bootstrap_timeout: Duration,
}

impl PoolConfig {
    /// Creates a configuration for `lanes` logical lanes, with no rotation
    /// limits and the default bootstrap timeout.
    pub fn new(lanes: usize) -> Self {
        Self {
            lanes,
            ..Self::default()
        }
    }

    /// Sets the lane rotation policy.
    pub fn with_rotation(mut self, rotation: RotationPolicy) -> Self {
        self.rotation = rotation;
        self
    }

    /// Sets the upper bound on Tor bootstrap time.
    pub fn with_bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.bootstrap_timeout = timeout;
        self
    }

    /// Deprecated alias for `with_rotation(RotationPolicy::new().after(ttl))`.
    #[deprecated(
        since = "0.2.0",
        note = "use `PoolConfig::with_rotation` and `RotationPolicy::after` instead"
    )]
    pub fn lane_ttl(mut self, ttl: Duration) -> Self {
        self.rotation.set_duration(ttl);
        self
    }

    /// Deprecated alias for
    /// `with_rotation(RotationPolicy::new().after_assignments(n))`.
    #[deprecated(
        since = "0.2.0",
        note = "use `PoolConfig::with_rotation` and `RotationPolicy::after_assignments` instead"
    )]
    pub fn lane_max_assignments(mut self, assignments: u64) -> Self {
        self.rotation.set_assignment_limit(assignments);
        self
    }

    /// The number of logical lanes.
    pub fn lanes(&self) -> usize {
        self.lanes
    }

    /// The configured lane rotation policy.
    pub fn rotation(&self) -> RotationPolicy {
        self.rotation
    }

    /// The upper bound on Tor bootstrap time.
    pub fn bootstrap_timeout(&self) -> Duration {
        self.bootstrap_timeout
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.lanes == 0 {
            return Err(ConfigError::EmptyLanes);
        }
        if self.lanes > MAX_LANES {
            return Err(ConfigError::TooManyLanes {
                actual: self.lanes,
                max: MAX_LANES,
            });
        }
        self.rotation.validate()?;
        if self.bootstrap_timeout.is_zero() {
            return Err(ConfigError::ZeroBootstrapTimeout);
        }
        Ok(())
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            lanes: 16,
            rotation: RotationPolicy::new(),
            bootstrap_timeout: Duration::from_secs(90),
        }
    }
}

/// A [`PoolConfig`] or [`RotationPolicy`] value failed validation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// `PoolConfig::lanes` must be greater than zero.
    EmptyLanes,
    /// `PoolConfig::lanes` exceeds [`MAX_LANES`].
    TooManyLanes {
        /// The requested lane count.
        actual: usize,
        /// The maximum allowed lane count.
        max: usize,
    },
    /// `RotationPolicy::after` was set to a zero duration.
    ZeroRotationDuration,
    /// `RotationPolicy::after_assignments` was set to zero.
    ZeroRotationAssignments,
    /// `PoolConfig::with_bootstrap_timeout` was set to zero.
    ZeroBootstrapTimeout,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLanes => formatter.write_str("lane count must be greater than zero"),
            Self::TooManyLanes { actual, max } => {
                write!(formatter, "lane count {actual} exceeds maximum {max}")
            }
            Self::ZeroRotationDuration => {
                formatter.write_str("rotation duration must be greater than zero")
            }
            Self::ZeroRotationAssignments => {
                formatter.write_str("rotation assignment limit must be greater than zero")
            }
            Self::ZeroBootstrapTimeout => {
                formatter.write_str("bootstrap timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pool_config_passes_validation() {
        let config = PoolConfig::new(64)
            .with_rotation(
                RotationPolicy::new()
                    .after(Duration::from_secs(600))
                    .after_assignments(100),
            )
            .with_bootstrap_timeout(Duration::from_secs(30));

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn pool_config_rejects_invalid_lane_limits() {
        assert_eq!(PoolConfig::new(0).validate(), Err(ConfigError::EmptyLanes));
        assert!(matches!(
            PoolConfig::new(MAX_LANES + 1).validate(),
            Err(ConfigError::TooManyLanes { .. })
        ));
        assert_eq!(
            PoolConfig::new(1)
                .with_rotation(RotationPolicy::new().after(Duration::ZERO))
                .validate(),
            Err(ConfigError::ZeroRotationDuration)
        );
        assert_eq!(
            PoolConfig::new(1)
                .with_rotation(RotationPolicy::new().after_assignments(0))
                .validate(),
            Err(ConfigError::ZeroRotationAssignments)
        );
    }

    #[test]
    fn pool_config_rejects_zero_bootstrap_timeout() {
        assert_eq!(
            PoolConfig::new(1)
                .with_bootstrap_timeout(Duration::ZERO)
                .validate(),
            Err(ConfigError::ZeroBootstrapTimeout)
        );
    }
}
