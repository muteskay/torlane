use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::pool::select::stable_lane_index;
use crate::pool::snapshot::PublishedSnapshot;
use crate::pool::{
    InstanceSnapshot, Lane, LaneId, LaneState, PoolBuilder, PoolConfig, PoolError, PoolSnapshot,
    Proxy, ReadySnapshot, rotate_lane,
};
use crate::tor::instance::{InstanceConfig, InstanceId, TorInstance};

#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    config: PoolConfig,
    ready: Arc<RwLock<Arc<ReadySnapshot>>>,
    unavailable: Arc<RwLock<HashSet<LaneId>>>,
    snapshot: Arc<RwLock<PublishedSnapshot>>,
    cursor: AtomicUsize,
    manager: mpsc::UnboundedSender<ManagerCommand>,
    manager_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

enum ManagerCommand {
    Assign { lane: LaneId, epoch: u64 },
    Retire(LaneId),
    Restart(oneshot::Sender<Result<(), PoolError>>),
    Shutdown(oneshot::Sender<Result<(), PoolError>>),
}

struct ManagerState {
    config: PoolConfig,
    lanes: Vec<Lane>,
    ready: Arc<RwLock<Arc<ReadySnapshot>>>,
    unavailable: Arc<RwLock<HashSet<LaneId>>>,
    snapshot: Arc<RwLock<PublishedSnapshot>>,
    runtime: RuntimeState,
    instance: Option<TorInstance>,
    instance_config: Option<InstanceConfig>,
}

#[derive(Clone, Copy)]
struct RuntimeState {
    id: InstanceId,
    pid: Option<u32>,
    socks_addr: SocketAddr,
    generation: u64,
    restart_count: u64,
}

impl Pool {
    pub fn builder() -> PoolBuilder {
        PoolBuilder::default()
    }

    pub fn next_proxy(&self) -> Result<Proxy, PoolError> {
        let ready = read_lock(&self.inner.ready).clone();
        if ready.lanes.is_empty() {
            return Err(PoolError::NoReadyLanes);
        }
        let index = self.inner.cursor.fetch_add(1, Ordering::Relaxed) % ready.lanes.len();
        self.proxy_from_endpoint(Arc::clone(&ready.lanes[index]))
    }

    pub fn proxy_for(&self, session: &str) -> Result<Proxy, PoolError> {
        let lane = LaneId(stable_lane_index(session, self.inner.config.lanes) as u32);
        let ready = read_lock(&self.inner.ready).clone();
        let endpoint = ready
            .lanes
            .iter()
            .find(|endpoint| endpoint.lane == lane)
            .cloned()
            .ok_or(PoolError::LaneUnavailable(lane))?;
        self.proxy_from_endpoint(endpoint)
    }

    pub fn retire(&self, lane: LaneId) -> Result<(), PoolError> {
        if lane.0 as usize >= self.inner.config.lanes {
            return Err(PoolError::UnknownLane(lane));
        }

        let current = read_lock(&self.inner.ready).clone();
        if !current.lanes.iter().any(|endpoint| endpoint.lane == lane) {
            return Err(PoolError::LaneUnavailable(lane));
        }
        write_lock(&self.inner.unavailable).insert(lane);
        let filtered: Vec<_> = current
            .lanes
            .iter()
            .filter(|endpoint| endpoint.lane != lane)
            .cloned()
            .collect();
        *write_lock(&self.inner.ready) = Arc::new(ReadySnapshot {
            lanes: Arc::from(filtered),
        });

        if self
            .inner
            .manager
            .send(ManagerCommand::Retire(lane))
            .is_err()
        {
            write_lock(&self.inner.unavailable).remove(&lane);
            return Err(PoolError::ManagerClosed);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        read_lock(&self.inner.snapshot).current()
    }

    pub async fn restart(&self) -> Result<(), PoolError> {
        let (response, receiver) = oneshot::channel();
        self.inner
            .manager
            .send(ManagerCommand::Restart(response))
            .map_err(|_| PoolError::ManagerClosed)?;
        receiver.await.map_err(|_| PoolError::ManagerClosed)?
    }

    pub async fn shutdown(self) -> Result<(), PoolError> {
        let (response, receiver) = oneshot::channel();
        self.inner
            .manager
            .send(ManagerCommand::Shutdown(response))
            .map_err(|_| PoolError::ManagerClosed)?;
        let shutdown = receiver.await.map_err(|_| PoolError::ManagerClosed)?;
        let task = { lock_mutex(&self.inner.manager_task).take() };
        if let Some(task) = task {
            task.await?;
        }
        shutdown
    }

    pub(crate) async fn from_instance(
        mut instance: TorInstance,
        instance_config: InstanceConfig,
        config: PoolConfig,
    ) -> Result<Self, PoolError> {
        let runtime = RuntimeState {
            id: instance.id,
            pid: instance.process_id(),
            socks_addr: instance.socks_addr(),
            generation: 1,
            restart_count: 0,
        };
        let lanes = match create_lanes(&config, runtime.socks_addr, runtime.id) {
            Ok(lanes) => lanes,
            Err(error) => {
                let _ = instance.shutdown().await;
                return Err(error);
            }
        };
        Ok(Self::spawn(
            config,
            lanes,
            runtime,
            Some(instance),
            Some(instance_config),
        ))
    }

    fn spawn(
        config: PoolConfig,
        lanes: Vec<Lane>,
        runtime: RuntimeState,
        instance: Option<TorInstance>,
        instance_config: Option<InstanceConfig>,
    ) -> Self {
        let unavailable = Arc::new(RwLock::new(HashSet::new()));
        let ready = Arc::new(RwLock::new(Arc::new(ready_snapshot(&lanes, &unavailable))));
        let snapshot = Arc::new(RwLock::new(PublishedSnapshot::new(
            instance_snapshot(runtime),
            &lanes,
        )));
        let (manager, commands) = mpsc::unbounded_channel();
        let state = ManagerState {
            config: config.clone(),
            lanes,
            ready: Arc::clone(&ready),
            unavailable: Arc::clone(&unavailable),
            snapshot: Arc::clone(&snapshot),
            runtime,
            instance,
            instance_config,
        };
        let task = tokio::spawn(run_manager(state, commands));
        Self {
            inner: Arc::new(PoolInner {
                config,
                ready,
                unavailable,
                snapshot,
                cursor: AtomicUsize::new(0),
                manager,
                manager_task: Mutex::new(Some(task)),
            }),
        }
    }

    fn proxy_from_endpoint(
        &self,
        endpoint: Arc<crate::pool::LaneEndpoint>,
    ) -> Result<Proxy, PoolError> {
        self.inner
            .manager
            .send(ManagerCommand::Assign {
                lane: endpoint.lane,
                epoch: endpoint.epoch,
            })
            .map_err(|_| PoolError::ManagerClosed)?;
        Ok(Proxy { inner: endpoint })
    }

    #[cfg(test)]
    pub(crate) fn for_test(config: PoolConfig, socks_addr: SocketAddr) -> Result<Self, PoolError> {
        config.validate()?;
        let runtime = RuntimeState {
            id: InstanceId(0),
            pid: Some(4242),
            socks_addr,
            generation: 1,
            restart_count: 0,
        };
        let lanes = create_lanes(&config, socks_addr, runtime.id)?;
        Ok(Self::spawn(config, lanes, runtime, None, None))
    }
}

async fn run_manager(
    mut state: ManagerState,
    mut commands: mpsc::UnboundedReceiver<ManagerCommand>,
) {
    let period = ttl_tick_period(state.config.lane_ttl);
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(ManagerCommand::Assign { lane, epoch }) => state.assign(lane, epoch),
                    Some(ManagerCommand::Retire(lane)) => state.retire(lane),
                    Some(ManagerCommand::Restart(response)) => {
                        let _ = response.send(state.restart().await);
                    }
                    Some(ManagerCommand::Shutdown(response)) => {
                        let _ = response.send(state.shutdown_instance().await);
                        break;
                    }
                    None => {
                        let _ = state.shutdown_instance().await;
                        break;
                    }
                }
            }
            _ = ticker.tick() => state.rotate_expired(),
        }
    }
}

impl ManagerState {
    fn assign(&mut self, id: LaneId, epoch: u64) {
        let Some(lane) = self
            .lanes
            .iter_mut()
            .find(|lane| lane.id == id && lane.epoch == epoch && lane.state == LaneState::Ready)
        else {
            return;
        };
        lane.assignments = lane.assignments.saturating_add(1);
        if self
            .config
            .lane_max_assignments
            .is_some_and(|maximum| lane.assignments >= maximum)
            && rotate_lane(lane, self.runtime.socks_addr, self.runtime.id).is_err()
        {
            lane.state = LaneState::Failed;
        }
        self.publish();
    }

    fn retire(&mut self, id: LaneId) {
        if let Some(lane) = self.lanes.iter_mut().find(|lane| lane.id == id) {
            if rotate_lane(lane, self.runtime.socks_addr, self.runtime.id).is_err() {
                lane.state = LaneState::Failed;
            } else {
                write_lock(&self.unavailable).remove(&id);
            }
            self.publish();
        }
    }

    fn rotate_expired(&mut self) {
        let Some(ttl) = self.config.lane_ttl else {
            return;
        };
        let mut changed = false;
        for lane in &mut self.lanes {
            if lane.state == LaneState::Ready && lane.created_at.elapsed() >= ttl {
                if rotate_lane(lane, self.runtime.socks_addr, self.runtime.id).is_err() {
                    lane.state = LaneState::Failed;
                }
                changed = true;
            }
        }
        if changed {
            self.publish();
        }
    }

    async fn restart(&mut self) -> Result<(), PoolError> {
        let config = self
            .instance_config
            .clone()
            .ok_or(PoolError::RestartUnavailable)?;
        *write_lock(&self.ready) = Arc::new(ReadySnapshot::empty());
        write_lock(&self.unavailable).extend(self.lanes.iter().map(|lane| lane.id));
        for lane in &mut self.lanes {
            lane.state = LaneState::Retiring;
        }
        self.publish_snapshot_only();

        if let Some(mut instance) = self.instance.take() {
            instance.shutdown().await?;
        }
        let instance = match TorInstance::start(config).await {
            Ok(instance) => instance,
            Err(error) => {
                for lane in &mut self.lanes {
                    lane.state = LaneState::Failed;
                }
                self.publish();
                return Err(error.into());
            }
        };

        self.runtime.id = instance.id;
        self.runtime.pid = instance.process_id();
        self.runtime.socks_addr = instance.socks_addr();
        self.runtime.generation = self.runtime.generation.saturating_add(1);
        self.runtime.restart_count = self.runtime.restart_count.saturating_add(1);
        self.instance = Some(instance);

        for lane in &mut self.lanes {
            if rotate_lane(lane, self.runtime.socks_addr, self.runtime.id).is_err() {
                lane.state = LaneState::Failed;
            } else {
                write_lock(&self.unavailable).remove(&lane.id);
            }
        }
        self.publish();
        Ok(())
    }

    async fn shutdown_instance(&mut self) -> Result<(), PoolError> {
        *write_lock(&self.ready) = Arc::new(ReadySnapshot::empty());
        if let Some(mut instance) = self.instance.take() {
            instance.shutdown().await?;
        }
        Ok(())
    }

    fn publish(&self) {
        *write_lock(&self.ready) = Arc::new(ready_snapshot(&self.lanes, &self.unavailable));
        self.publish_snapshot_only();
    }

    fn publish_snapshot_only(&self) {
        *write_lock(&self.snapshot) =
            PublishedSnapshot::new(instance_snapshot(self.runtime), &self.lanes);
    }
}

fn create_lanes(
    config: &PoolConfig,
    socks_addr: SocketAddr,
    instance: InstanceId,
) -> Result<Vec<Lane>, PoolError> {
    (0..config.lanes)
        .map(|id| Ok(Lane::new(LaneId(id as u32), socks_addr, instance)?))
        .collect()
}

fn ready_snapshot(lanes: &[Lane], unavailable: &RwLock<HashSet<LaneId>>) -> ReadySnapshot {
    let unavailable = read_lock(unavailable);
    ReadySnapshot {
        lanes: lanes
            .iter()
            .filter(|lane| lane.state == LaneState::Ready && !unavailable.contains(&lane.id))
            .map(|lane| Arc::clone(&lane.endpoint))
            .collect::<Vec<_>>()
            .into(),
    }
}

fn instance_snapshot(runtime: RuntimeState) -> InstanceSnapshot {
    InstanceSnapshot {
        id: runtime.id,
        pid: runtime.pid,
        socks_addr: runtime.socks_addr,
        generation: runtime.generation,
        restart_count: runtime.restart_count,
    }
}

fn ttl_tick_period(ttl: Option<Duration>) -> Duration {
    ttl.map(|ttl| (ttl / 4).clamp(Duration::from_millis(5), Duration::from_secs(1)))
        .unwrap_or(Duration::from_secs(24 * 60 * 60))
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_mutex<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::{sleep, timeout};

    use super::*;

    fn address() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19050))
    }

    #[tokio::test]
    async fn creates_exactly_k_lanes_with_shared_address_and_unique_credentials() {
        let pool = Pool::for_test(PoolConfig::new(16), address()).unwrap();
        let ready = read_lock(&pool.inner.ready).clone();

        assert_eq!(ready.lanes.len(), 16);
        assert!(ready.lanes.iter().all(|lane| lane.addr == address()));
        assert_eq!(
            ready
                .lanes
                .iter()
                .map(|lane| lane.auth.username.clone())
                .collect::<HashSet<_>>()
                .len(),
            16
        );
        assert_eq!(
            ready
                .lanes
                .iter()
                .map(|lane| lane.auth.password.clone())
                .collect::<HashSet<_>>()
                .len(),
            16
        );
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.ready_lane_count, 16);
        assert_eq!(snapshot.unavailable_lane_count, 0);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn round_robin_cycles_through_ready_lanes() {
        let pool = Pool::for_test(PoolConfig::new(3), address()).unwrap();
        let selected: Vec<_> = (0..8).map(|_| pool.next_proxy().unwrap().lane()).collect();

        assert_eq!(
            selected,
            vec![
                LaneId(0),
                LaneId(1),
                LaneId(2),
                LaneId(0),
                LaneId(1),
                LaneId(2),
                LaneId(0),
                LaneId(1),
            ]
        );
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn sticky_mapping_is_stable() {
        let pool = Pool::for_test(PoolConfig::new(8), address()).unwrap();
        let first = pool.proxy_for("customer-session-42").unwrap();

        for _ in 0..100 {
            let proxy = pool.proxy_for("customer-session-42").unwrap();
            assert_eq!(proxy.lane(), first.lane());
            assert_eq!(proxy.epoch(), first.epoch());
        }
        assert!(first.socks5h_url().starts_with("socks5h://lane-"));
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn retire_rotates_only_selected_lane_and_drops_stale_generation() {
        let pool = Pool::for_test(PoolConfig::new(3), address()).unwrap();
        let before = endpoints_by_lane(&pool);
        let stale = Arc::clone(before.get(&LaneId(1)).unwrap());

        pool.retire(LaneId(1)).unwrap();
        assert!(
            read_lock(&pool.inner.ready)
                .lanes
                .iter()
                .all(|endpoint| endpoint.lane != LaneId(1))
        );
        wait_for(&pool, |snapshot| {
            snapshot.ready_lane_count == 3
                && snapshot.lanes[1].epoch == 2
                && snapshot.lanes[1].state == LaneState::Ready
        })
        .await;

        let after = endpoints_by_lane(&pool);
        assert_eq!(after[&LaneId(0)].epoch, before[&LaneId(0)].epoch);
        assert_eq!(after[&LaneId(2)].epoch, before[&LaneId(2)].epoch);
        assert!(Arc::ptr_eq(&after[&LaneId(0)], &before[&LaneId(0)]));
        assert!(Arc::ptr_eq(&after[&LaneId(2)], &before[&LaneId(2)]));
        assert_eq!(after[&LaneId(1)].epoch, stale.epoch + 1);
        assert_ne!(after[&LaneId(1)].auth.password, stale.auth.password);
        assert!(!Arc::ptr_eq(&after[&LaneId(1)], &stale));
        assert_eq!(stale.epoch, 1);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ttl_rotates_only_expired_lane() {
        let config = PoolConfig::new(2).lane_ttl(Duration::from_millis(100));
        let pool = Pool::for_test(config, address()).unwrap();

        sleep(Duration::from_millis(60)).await;
        pool.retire(LaneId(0)).unwrap();
        wait_for(&pool, |snapshot| snapshot.lanes[0].epoch == 2).await;
        wait_for(&pool, |snapshot| snapshot.lanes[1].epoch == 2).await;

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.lanes[0].epoch, 2);
        assert_eq!(snapshot.lanes[1].epoch, 2);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn max_assignments_rotates_lane_without_blocking_current_proxy() {
        let config = PoolConfig::new(1).lane_max_assignments(2);
        let pool = Pool::for_test(config, address()).unwrap();

        let first = pool.next_proxy().unwrap();
        let second = pool.next_proxy().unwrap();
        assert_eq!(first.epoch(), 1);
        assert_eq!(second.epoch(), 1);
        wait_for(&pool, |snapshot| snapshot.lanes[0].epoch == 2).await;

        let current = pool.next_proxy().unwrap();
        assert_eq!(current.epoch(), 2);
        assert_ne!(current.auth().password, first.auth().password);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn empty_ready_snapshot_returns_no_ready_lanes() {
        let pool = Pool::for_test(PoolConfig::new(1), address()).unwrap();
        *write_lock(&pool.inner.ready) = Arc::new(ReadySnapshot::empty());

        assert!(matches!(pool.next_proxy(), Err(PoolError::NoReadyLanes)));
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn sticky_session_does_not_fall_back_when_lane_is_unavailable() {
        let pool = Pool::for_test(PoolConfig::new(4), address()).unwrap();
        let session = "fixed-session";
        let lane = pool.proxy_for(session).unwrap().lane();
        pool.retire(lane).unwrap();

        assert!(matches!(
            pool.proxy_for(session),
            Err(PoolError::LaneUnavailable(unavailable)) if unavailable == lane
        ));
        pool.shutdown().await.unwrap();
    }

    fn endpoints_by_lane(pool: &Pool) -> HashMap<LaneId, Arc<crate::pool::LaneEndpoint>> {
        read_lock(&pool.inner.ready)
            .lanes
            .iter()
            .map(|endpoint| (endpoint.lane, Arc::clone(endpoint)))
            .collect()
    }

    async fn wait_for(pool: &Pool, predicate: impl Fn(&PoolSnapshot) -> bool) {
        timeout(Duration::from_secs(2), async {
            loop {
                let snapshot = pool.snapshot();
                if predicate(&snapshot) {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("pool state did not converge");
    }
}
