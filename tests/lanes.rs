use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use torlane::{
    InstanceId, Lane, LaneError, LaneId, LaneState, PoolConfig, PoolConfigError,
    generate_lane_auth, rotate_lane,
};

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
    let passwords: HashSet<_> = (0..256)
        .map(|id| generate_lane_auth(LaneId(id), 1).unwrap().password)
        .collect();

    assert_eq!(passwords.len(), 256);
}

#[test]
fn new_lane_starts_ready_at_epoch_one() {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 19050));
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
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 19050));
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
fn valid_pool_config_passes_validation() {
    let config = PoolConfig::new(64)
        .lane_ttl(Duration::from_secs(600))
        .lane_max_assignments(100)
        .bootstrap_timeout(Duration::from_secs(30));

    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn pool_config_rejects_invalid_lane_limits() {
    assert_eq!(
        PoolConfig::new(0).validate(),
        Err(PoolConfigError::EmptyLanes)
    );
    assert!(matches!(
        PoolConfig::new(torlane::pool::MAX_LANES + 1).validate(),
        Err(PoolConfigError::TooManyLanes { .. })
    ));
    assert_eq!(
        PoolConfig::new(1).lane_ttl(Duration::ZERO).validate(),
        Err(PoolConfigError::ZeroLaneTtl)
    );
    assert_eq!(
        PoolConfig::new(1).lane_max_assignments(0).validate(),
        Err(PoolConfigError::ZeroLaneMaxAssignments)
    );
}

#[test]
fn pool_config_rejects_zero_bootstrap_timeout() {
    assert_eq!(
        PoolConfig::new(1)
            .bootstrap_timeout(Duration::ZERO)
            .validate(),
        Err(PoolConfigError::ZeroBootstrapTimeout)
    );
}

#[test]
fn rotation_refreshes_creation_time() {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 19050));
    let mut lane = Lane::new(LaneId(6), addr, InstanceId(1)).unwrap();
    lane.created_at = Instant::now() - Duration::from_secs(60);

    rotate_lane(&mut lane, addr, InstanceId(1)).unwrap();

    assert!(lane.created_at.elapsed() < Duration::from_secs(1));
}
