//! Lane rotation policy.

use std::time::Duration;

use crate::config::ConfigError;

/// Groups a lane's rotation limits.
///
/// A lane rotates when the first configured limit is reached:
///
/// - no configured limits means manual rotation only (via
///   [`Pool::rotate`](crate::Pool::rotate));
/// - [`RotationPolicy::after`] rotates a lane once it has been ready for at
///   least that long;
/// - [`RotationPolicy::after_assignments`] rotates a lane after it has been
///   handed out that many times.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use torlane::RotationPolicy;
///
/// let policy = RotationPolicy::new()
///     .after(Duration::from_secs(10 * 60))
///     .after_assignments(100);
/// assert_eq!(policy.duration(), Some(Duration::from_secs(600)));
/// assert_eq!(policy.assignment_limit(), Some(100));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RotationPolicy {
    duration: Option<Duration>,
    assignment_limit: Option<u64>,
}

impl RotationPolicy {
    /// Creates a policy with no configured limits (manual rotation only).
    pub fn new() -> Self {
        Self::default()
    }

    /// Rotates the lane once it has been ready for at least `duration`.
    pub fn after(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Rotates the lane after it has been handed out `count` times.
    pub fn after_assignments(mut self, count: u64) -> Self {
        self.assignment_limit = Some(count);
        self
    }

    /// The configured age-based rotation limit, if any.
    pub fn duration(&self) -> Option<Duration> {
        self.duration
    }

    /// The configured assignment-count rotation limit, if any.
    pub fn assignment_limit(&self) -> Option<u64> {
        self.assignment_limit
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.duration == Some(Duration::ZERO) {
            return Err(ConfigError::ZeroRotationDuration);
        }
        if self.assignment_limit == Some(0) {
            return Err(ConfigError::ZeroRotationAssignments);
        }
        Ok(())
    }
}
