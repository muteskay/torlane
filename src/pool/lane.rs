use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;

use crate::pool::LaneError;
use crate::tor::instance::InstanceId;

const PASSWORD_BYTES: usize = 32;
pub(crate) const REDACTED: &str = "<redacted>";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(pub u32);

#[derive(Clone, PartialEq, Eq)]
pub struct SocksAuth {
    pub username: Arc<str>,
    pub password: Arc<str>,
}

impl fmt::Debug for SocksAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocksAuth")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    fn address() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19050))
    }

    fn auth() -> SocksAuth {
        SocksAuth {
            username: Arc::from("lane-000001-00000001"),
            password: Arc::from("f00dcafe"),
        }
    }

    #[test]
    fn socks_auth_debug_redacts_password_only() {
        let debug = format!("{:?}", auth());

        assert_eq!(
            debug,
            "SocksAuth { username: \"lane-000001-00000001\", password: \"<redacted>\" }"
        );
    }

    #[test]
    fn lane_endpoint_debug_redacts_password() {
        let endpoint = LaneEndpoint {
            lane: LaneId(1),
            epoch: 1,
            instance: InstanceId(0),
            addr: address(),
            auth: auth(),
        };
        let debug = format!("{endpoint:?}");

        assert!(!debug.contains("f00dcafe"), "{debug}");
        assert!(debug.contains(REDACTED), "{debug}");
    }

    #[test]
    fn lane_debug_redacts_generated_password() {
        let lane = Lane::new(LaneId(1), address(), InstanceId(0)).unwrap();
        let password = lane.endpoint.auth.password.clone();
        let debug = format!("{lane:?}");

        assert!(!debug.contains(&*password), "{debug}");
        assert!(debug.contains(REDACTED), "{debug}");
    }

    #[test]
    fn rotated_lane_debug_redacts_new_password() {
        let mut lane = Lane::new(LaneId(1), address(), InstanceId(0)).unwrap();
        rotate_lane(&mut lane, address(), InstanceId(0)).unwrap();
        let password = lane.endpoint.auth.password.clone();
        let debug = format!("{lane:?}");

        assert!(!debug.contains(&*password), "{debug}");
        assert!(debug.contains(REDACTED), "{debug}");
    }
}
