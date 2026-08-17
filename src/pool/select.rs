use std::net::SocketAddr;
use std::sync::Arc;

use crate::pool::{LaneEndpoint, LaneId, SocksAuth};

#[derive(Debug, Clone)]
pub struct Proxy {
    pub(crate) inner: Arc<LaneEndpoint>,
}

impl Proxy {
    pub fn lane(&self) -> LaneId {
        self.inner.lane
    }

    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    pub fn auth(&self) -> &SocksAuth {
        &self.inner.auth
    }

    pub fn socks5h_url(&self) -> String {
        format!(
            "socks5h://{}:{}@{}",
            self.inner.auth.username, self.inner.auth.password, self.inner.addr
        )
    }
}

#[derive(Debug, Clone)]
pub struct ReadySnapshot {
    pub lanes: Arc<[Arc<LaneEndpoint>]>,
}

impl ReadySnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            lanes: Arc::from([]),
        }
    }
}

pub(crate) fn stable_lane_index(session: &str, lane_count: usize) -> usize {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let hash = session.as_bytes().iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    });
    (hash % lane_count as u64) as usize
}
