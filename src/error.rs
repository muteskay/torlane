//! The error type returned by managed pool operations.

use crate::LaneId;

/// The error type returned by [`Pool`](crate::Pool) and
/// [`PoolBuilder`](crate::PoolBuilder) operations.
///
/// Variants are grouped by when they can occur: [`Error::Config`] only
/// happens while building a pool, [`Error::Instance`] can happen while
/// starting, restarting, or shutting one down, and the rest are returned by
/// an already-running [`Pool`](crate::Pool).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The pool or Tor policy configuration was invalid. This is a
    /// configuration error: retrying without changing the configuration
    /// will fail again.
    #[error("pool configuration is invalid: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// The managed Tor instance failed to start (process launch, config
    /// verification, control port discovery, authentication, or bootstrap),
    /// or failed while stopping during [`Pool::restart`](crate::Pool::restart)
    /// or [`Pool::shutdown`](crate::Pool::shutdown). Depending on the cause
    /// this may be transient (for example a slow bootstrap) and worth
    /// retrying.
    #[error("managed Tor instance error: {0}")]
    Instance(#[from] crate::low_level::TorInstanceError),

    /// No lane is currently ready to hand out. This is usually transient:
    /// lanes become ready again once rotation completes.
    #[error("no ready lanes are available")]
    NoReadyLanes,

    /// The lane selected by [`Pool::for_key`](crate::Pool::for_key) is not
    /// currently ready (for example, mid-rotation). Retrying later may
    /// succeed.
    #[error("lane {0:?} is unavailable")]
    LaneUnavailable(LaneId),

    /// The lane id does not belong to this pool.
    #[error("unknown lane {0:?}")]
    UnknownLane(LaneId),

    /// The pool has been shut down. Every operation after
    /// [`Pool::shutdown`](crate::Pool::shutdown) returns this error.
    #[error("pool is closed")]
    Closed,

    /// [`Pool::restart`](crate::Pool::restart) was called on a pool that was
    /// not created from a managed Tor instance.
    #[error("restart requires a managed Tor instance")]
    RestartUnavailable,

    /// The background pool manager task failed unexpectedly (for example,
    /// it panicked). This is not expected during normal operation.
    #[error("pool manager task failed")]
    ManagerTask(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// An internal invariant was violated (for example, lane credential
    /// generation failed). This is not expected during normal operation.
    #[error("internal pool error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
