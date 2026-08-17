use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;

use crate::pool::LaneError;
use crate::tor::instance::InstanceId;

const PASSWORD_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksAuth {
    pub username: Arc<str>,
    pub password: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct LaneEndpoint {
    pub lane: LaneId,
    pub epoch: u64,
    pub instance: InstanceId,
    pub addr: SocketAddr,
    pub auth: SocksAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    Ready,
    Retiring,
    Failed,
}

#[derive(Debug)]
pub struct Lane {
    pub id: LaneId,
    pub epoch: u64,
    pub endpoint: Arc<LaneEndpoint>,
    pub created_at: Instant,
    pub assignments: u64,
    pub state: LaneState,
}

impl Lane {
    pub fn new(
        id: LaneId,
        socks_addr: SocketAddr,
        instance: InstanceId,
    ) -> Result<Self, LaneError> {
        let epoch = 1;
        let auth = generate_lane_auth(id, epoch)?;
        Ok(Self {
            id,
            epoch,
            endpoint: Arc::new(LaneEndpoint {
                lane: id,
                epoch,
                instance,
                addr: socks_addr,
                auth,
            }),
            created_at: Instant::now(),
            assignments: 0,
            state: LaneState::Ready,
        })
    }
}

pub fn generate_lane_auth(id: LaneId, epoch: u64) -> Result<SocksAuth, LaneError> {
    let username: Arc<str> = Arc::from(format!("lane-{:06}-{:08}", id.0, epoch));
    let mut random = [0_u8; PASSWORD_BYTES];
    rand::rngs::OsRng.try_fill_bytes(&mut random)?;
    let password: Arc<str> = Arc::from(hex_encode(&random));
    Ok(SocksAuth { username, password })
}

pub fn rotate_lane(
    lane: &mut Lane,
    socks_addr: SocketAddr,
    instance: InstanceId,
) -> Result<(), LaneError> {
    lane.state = LaneState::Retiring;
    let epoch = lane
        .epoch
        .checked_add(1)
        .ok_or(LaneError::EpochOverflow(lane.id.0))?;
    let auth = generate_lane_auth(lane.id, epoch)?;

    lane.epoch = epoch;
    lane.endpoint = Arc::new(LaneEndpoint {
        lane: lane.id,
        epoch,
        instance,
        addr: socks_addr,
        auth,
    });
    lane.assignments = 0;
    lane.created_at = Instant::now();
    lane.state = LaneState::Ready;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
