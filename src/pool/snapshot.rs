use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pool::{Lane, LaneId, LaneState};
use crate::tor::instance::InstanceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSnapshot {
    pub id: InstanceId,
    pub pid: Option<u32>,
    pub socks_addr: SocketAddr,
    pub generation: u64,
    pub restart_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneSnapshot {
    pub id: LaneId,
    pub epoch: u64,
    pub state: LaneState,
    pub assignments: u64,
    pub age: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshot {
    pub instance: InstanceSnapshot,
    pub lanes: Vec<LaneSnapshot>,
    pub ready_lane_count: usize,
    pub unavailable_lane_count: usize,
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
