use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pool::{Lane, LaneId, LaneState};
use crate::tor::instance::InstanceId;

/// A point-in-time view of the managed Tor instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceSnapshot {
    pub(crate) id: InstanceId,
    pub(crate) pid: Option<u32>,
    pub(crate) socks_addr: SocketAddr,
    pub(crate) generation: u64,
    pub(crate) restart_count: u64,
}

impl InstanceSnapshot {
    /// The instance's identifier within the pool.
    pub fn id(&self) -> InstanceId {
        self.id
    }

    /// The Tor process id, if the process is currently running.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// The shared Tor SOCKS5 listener address.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// Increments on every successful [`Pool::restart`](crate::Pool::restart).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The number of times [`Pool::restart`](crate::Pool::restart) has
    /// succeeded.
    pub fn restart_count(&self) -> u64 {
        self.restart_count
    }
}

/// A point-in-time view of one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneSnapshot {
    pub(crate) id: LaneId,
    pub(crate) epoch: u64,
    pub(crate) state: LaneState,
    pub(crate) assignments: u64,
    pub(crate) age: Duration,
}

impl LaneSnapshot {
    /// The lane's canonical identifier.
    pub fn id(&self) -> LaneId {
        self.id
    }

    /// The lane's current rotation epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The lane's current readiness state.
    pub fn state(&self) -> LaneState {
        self.state
    }

    /// The number of proxies handed out for the current epoch.
    pub fn assignments(&self) -> u64 {
        self.assignments
    }

    /// How long the lane has held its current epoch.
    pub fn age(&self) -> Duration {
        self.age
    }
}

/// An immutable, point-in-time view of a [`Pool`](crate::Pool)'s state.
///
/// Returned by [`Pool::snapshot`](crate::Pool::snapshot). Call `snapshot()`
/// again to observe newer state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshot {
    pub(crate) instance: InstanceSnapshot,
    pub(crate) lanes: Vec<LaneSnapshot>,
    pub(crate) ready_lane_count: usize,
    pub(crate) unavailable_lane_count: usize,
}

impl PoolSnapshot {
    /// The managed Tor instance's state.
    pub fn instance(&self) -> &InstanceSnapshot {
        &self.instance
    }

    /// Every lane's state, in `LaneId` order.
    pub fn lanes(&self) -> &[LaneSnapshot] {
        &self.lanes
    }

    /// The number of lanes currently ready to be handed out.
    pub fn ready_lane_count(&self) -> usize {
        self.ready_lane_count
    }

    /// The number of lanes currently unavailable (rotating or failed).
    pub fn unavailable_lane_count(&self) -> usize {
        self.unavailable_lane_count
    }
}

#[derive(Clone)]
pub(crate) struct PublishedSnapshot {
    pub(crate) snapshot: PoolSnapshot,
    published_at: Instant,
}

impl PublishedSnapshot {
    pub(crate) fn new(instance: InstanceSnapshot, lanes: &[Lane]) -> Self {
        let ready_lane_count = lanes
            .iter()
            .filter(|lane| lane.state == LaneState::Ready)
            .count();
        Self {
            snapshot: PoolSnapshot {
                instance,
                lanes: lanes
                    .iter()
                    .map(|lane| LaneSnapshot {
                        id: lane.id,
                        epoch: lane.epoch,
                        state: lane.state,
                        assignments: lane.assignments,
                        age: lane.created_at.elapsed(),
                    })
                    .collect(),
                ready_lane_count,
                unavailable_lane_count: lanes.len() - ready_lane_count,
            },
            published_at: Instant::now(),
        }
    }

    pub(crate) fn current(&self) -> PoolSnapshot {
        let elapsed = self.published_at.elapsed();
        let mut snapshot = self.snapshot.clone();
        for lane in &mut snapshot.lanes {
            lane.age = lane.age.saturating_add(elapsed);
        }
        snapshot
    }
}
