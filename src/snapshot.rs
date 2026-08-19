//! Read-only pool and lane state snapshots.
//!
//! [`Pool::snapshot`](crate::Pool::snapshot) returns a [`PoolSnapshot`]: an
//! immutable, point-in-time view of the managed Tor instance and every
//! lane. Call `snapshot()` again to observe newer state.

pub use crate::pool::{InstanceSnapshot, LaneSnapshot, LaneState, PoolSnapshot};
