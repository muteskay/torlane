use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use rand::TryRng;

use crate::pool::LaneError;
use crate::tor::instance::InstanceId;

const PASSWORD_BYTES: usize = 32;
pub(crate) const REDACTED: &str = "<redacted>";

/// A lane's canonical identifier.
///
/// A lane's `LaneId` is stable across rotation; only its epoch and
/// credentials change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(pub u32);

/// SOCKS5 username/password credentials for one lane epoch.
///
/// Not part of the public API: callers read credentials through
/// [`Proxy::username`](crate::Proxy::username) and
/// [`Proxy::expose_password`](crate::Proxy::expose_password), or the
/// equivalent methods on [`TorIdentity`](crate::low_level::TorIdentity).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SocksAuth {
    pub(crate) username: Arc<str>,
    pub(crate) password: Arc<str>,
}

impl SocksAuth {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn expose_password(&self) -> &str {
        &self.password
    }
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
pub(crate) struct LaneEndpoint {
    pub(crate) lane: LaneId,
    pub(crate) epoch: u64,
    #[allow(
        dead_code,
        reason = "carried for debugging/diagnostics, not read by pool logic"
    )]
    pub(crate) instance: InstanceId,
    pub(crate) addr: SocketAddr,
    pub(crate) auth: SocksAuth,
}

/// A lane's readiness state, as observed in a [`PoolSnapshot`](crate::snapshot::PoolSnapshot).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// The lane is ready to be handed out.
    Ready,
    /// The lane is rotating and temporarily unavailable.
    Retiring,
    /// The lane failed to rotate and will not become ready again.
    Failed,
}

#[derive(Debug)]
pub(crate) struct Lane {
    pub(crate) id: LaneId,
    pub(crate) epoch: u64,
    pub(crate) endpoint: Arc<LaneEndpoint>,
    pub(crate) created_at: Instant,
    pub(crate) assignments: u64,
    pub(crate) state: LaneState,
}

impl Lane {
    pub(crate) fn new(
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

pub(crate) fn generate_lane_auth(id: LaneId, epoch: u64) -> Result<SocksAuth, LaneError> {
    let username: Arc<str> = Arc::from(format!("lane-{:06}-{:08}", id.0, epoch));
    let mut random = [0_u8; PASSWORD_BYTES];
    rand::rngs::SysRng.try_fill_bytes(&mut random)?;
    let password: Arc<str> = Arc::from(hex_encode(&random));
    Ok(SocksAuth { username, password })
}

pub(crate) fn rotate_lane(
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

    #[test]
    fn lane_credentials_have_stable_username_and_url_safe_entropy() {
        let auth = generate_lane_auth(LaneId(17), 42).unwrap();

        assert_eq!(auth.username.as_ref(), "lane-000017-00000042");
        assert_eq!(auth.password.len(), 64);
        assert!(
            auth.password
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn generated_lane_passwords_are_unique() {
        let passwords: std::collections::HashSet<_> = (0..256)
            .map(|id| generate_lane_auth(LaneId(id), 1).unwrap().password)
            .collect();

        assert_eq!(passwords.len(), 256);
    }

    #[test]
    fn new_lane_starts_ready_at_epoch_one() {
        let addr = address();
        let lane = Lane::new(LaneId(3), addr, InstanceId(2)).unwrap();

        assert_eq!(lane.id, LaneId(3));
        assert_eq!(lane.epoch, 1);
        assert_eq!(lane.assignments, 0);
        assert_eq!(lane.state, LaneState::Ready);
        assert_eq!(lane.endpoint.lane, LaneId(3));
        assert_eq!(lane.endpoint.epoch, 1);
        assert_eq!(lane.endpoint.instance, InstanceId(2));
        assert_eq!(lane.endpoint.addr, addr);
        assert_eq!(lane.endpoint.auth.username.as_ref(), "lane-000003-00000001");
    }

    #[test]
    fn rotation_replaces_only_current_generation() {
        let old_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 19050));
        let new_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 29050));
        let mut lane = Lane::new(LaneId(4), old_addr, InstanceId(1)).unwrap();
        lane.assignments = 99;
        let old_created_at = lane.created_at;
        let old_endpoint = Arc::clone(&lane.endpoint);
        let old_password = Arc::clone(&old_endpoint.auth.password);

        rotate_lane(&mut lane, new_addr, InstanceId(2)).unwrap();

        assert_eq!(lane.epoch, 2);
        assert_eq!(lane.assignments, 0);
        assert_eq!(lane.state, LaneState::Ready);
        assert!(lane.created_at >= old_created_at);
        assert!(!Arc::ptr_eq(&lane.endpoint, &old_endpoint));
        assert_eq!(lane.endpoint.lane, LaneId(4));
        assert_eq!(lane.endpoint.epoch, 2);
        assert_eq!(lane.endpoint.instance, InstanceId(2));
        assert_eq!(lane.endpoint.addr, new_addr);
        assert_eq!(lane.endpoint.auth.username.as_ref(), "lane-000004-00000002");
        assert_ne!(lane.endpoint.auth.password, old_password);

        assert_eq!(old_endpoint.epoch, 1);
        assert_eq!(old_endpoint.instance, InstanceId(1));
        assert_eq!(old_endpoint.addr, old_addr);
    }

    #[test]
    fn rotation_detects_epoch_overflow_without_publishing_endpoint() {
        let addr = address();
        let mut lane = Lane::new(LaneId(5), addr, InstanceId(1)).unwrap();
        lane.epoch = u64::MAX;
        let endpoint = Arc::clone(&lane.endpoint);

        assert!(matches!(
            rotate_lane(&mut lane, addr, InstanceId(1)),
            Err(LaneError::EpochOverflow(5))
        ));
        assert_eq!(lane.state, LaneState::Retiring);
        assert!(Arc::ptr_eq(&lane.endpoint, &endpoint));
    }

    #[test]
    fn rotation_refreshes_creation_time() {
        let addr = address();
        let mut lane = Lane::new(LaneId(6), addr, InstanceId(1)).unwrap();
        lane.created_at = Instant::now() - std::time::Duration::from_secs(60);

        rotate_lane(&mut lane, addr, InstanceId(1)).unwrap();

        assert!(lane.created_at.elapsed() < std::time::Duration::from_secs(1));
    }
}
