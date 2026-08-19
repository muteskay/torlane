use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::Error;
use crate::pool::select::stable_lane_index;
use crate::pool::snapshot::PublishedSnapshot;
use crate::pool::{
    InstanceSnapshot, Lane, LaneId, LaneState, PoolBuilder, PoolConfig, PoolSnapshot, Proxy,
    ReadySnapshot, rotate_lane,
};
use crate::tor::instance::{InstanceConfig, InstanceId, TorInstance};

/// Runs one managed Tor process and hands out isolated SOCKS5 lanes.
///
/// `Pool` is cheaply cloneable: every clone shares the same background
/// manager task and Tor instance. [`Pool::shutdown`] is global across all
/// clones and idempotent.
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
    closed: AtomicBool,
    manager: mpsc::UnboundedSender<ManagerCommand>,
    manager_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

enum ManagerCommand {
    Assign {
        lane: LaneId,
        epoch: u64,
    },
    Rotate {
        lane: LaneId,
        response: Option<oneshot::Sender<Result<(), Error>>>,
    },
    Restart(oneshot::Sender<Result<(), Error>>),
    Shutdown(oneshot::Sender<Result<(), Error>>),
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
    /// Starts building a managed pool rooted at `work_dir`.
    ///
    /// `work_dir` holds the Tor data directory and runtime files (control
    /// port discovery file, and the generated `torrc` when
    /// [`PoolBuilder::torrc_file`] is used).
    pub fn builder(work_dir: impl Into<std::path::PathBuf>) -> PoolBuilder {
        PoolBuilder::new(work_dir)
    }

    /// Selects the next ready lane in round-robin order.
    ///
    /// Consecutive calls normally return different lanes when at least two
    /// are ready. Performs no network I/O.
    pub fn next(&self) -> Result<Proxy, Error> {
        self.ensure_open()?;
        let ready = read_lock(&self.inner.ready).clone();
        if ready.lanes.is_empty() {
            return Err(Error::NoReadyLanes);
        }
        let index = self.inner.cursor.fetch_add(1, Ordering::Relaxed) % ready.lanes.len();
        self.proxy_from_endpoint(Arc::clone(&ready.lanes[index]))
    }

    /// Deprecated alias for [`Pool::next`].
    #[deprecated(since = "0.2.0", note = "use `Pool::next` instead")]
    pub fn next_proxy(&self) -> Result<Proxy, Error> {
        self.next()
    }

    /// Selects a lane deterministically from `key`.
    ///
    /// The same key always maps to the same `LaneId`, which is useful for
    /// keeping related requests on one logical Tor identity. The mapping is
    /// not exclusive: different keys can map to the same lane. If the
    /// mapped lane is temporarily unavailable (for example, mid-rotation),
    /// this returns [`Error::LaneUnavailable`] instead of silently
    /// selecting a different lane. Performs no network I/O.
    pub fn for_key(&self, key: impl AsRef<[u8]>) -> Result<Proxy, Error> {
        self.ensure_open()?;
        let lane = LaneId(stable_lane_index(key.as_ref(), self.inner.config.lanes()) as u32);
        let ready = read_lock(&self.inner.ready).clone();
        let endpoint = ready
            .lanes
            .iter()
            .find(|endpoint| endpoint.lane == lane)
            .cloned()
            .ok_or(Error::LaneUnavailable(lane))?;
        self.proxy_from_endpoint(endpoint)
    }

    /// Deprecated alias for [`Pool::for_key`].
    #[deprecated(since = "0.2.0", note = "use `Pool::for_key` instead")]
    pub fn proxy_for(&self, session: &str) -> Result<Proxy, Error> {
        self.for_key(session.as_bytes())
    }

    /// Rotates `lane` and waits for the new epoch to be published and
    /// ready.
    ///
    /// Returns once the lane has a new epoch and fresh credentials, or an
    /// error if rotation failed. The `Proxy` values already handed out for
    /// the old epoch remain valid; only later selections observe the new
    /// epoch.
    pub async fn rotate(&self, lane: LaneId) -> Result<(), Error> {
        let (response, receiver) = oneshot::channel();
        self.queue_rotation(lane, Some(response))?;
        receiver.await.map_err(|_| Error::Closed)?
    }

    /// Deprecated alias for [`Pool::rotate`] that only queues rotation and
    /// returns immediately, without waiting for the new epoch to be
    /// published or ready.
    #[deprecated(
        since = "0.2.0",
        note = "use `Pool::rotate(lane).await` for a completion guarantee"
    )]
    pub fn retire(&self, lane: LaneId) -> Result<(), Error> {
        self.queue_rotation(lane, None)
    }

    fn queue_rotation(
        &self,
        lane: LaneId,
        response: Option<oneshot::Sender<Result<(), Error>>>,
    ) -> Result<(), Error> {
        self.ensure_open()?;
        if lane.0 as usize >= self.inner.config.lanes() {
            return Err(Error::UnknownLane(lane));
        }

        let current = read_lock(&self.inner.ready).clone();
        if !current.lanes.iter().any(|endpoint| endpoint.lane == lane) {
            return Err(Error::LaneUnavailable(lane));
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
            .send(ManagerCommand::Rotate { lane, response })
            .is_err()
        {
            write_lock(&self.inner.unavailable).remove(&lane);
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// Returns an immutable, point-in-time view of the pool's state.
    pub fn snapshot(&self) -> PoolSnapshot {
        read_lock(&self.inner.snapshot).current()
    }

    /// Stops and restarts the managed Tor process, refreshes the SOCKS
    /// address, and rotates every lane.
    ///
    /// Returns [`Error::RestartUnavailable`] if this pool was not created
    /// from a managed Tor instance.
    pub async fn restart(&self) -> Result<(), Error> {
        self.ensure_open()?;
        let (response, receiver) = oneshot::channel();
        self.inner
            .manager
            .send(ManagerCommand::Restart(response))
            .map_err(|_| Error::Closed)?;
        receiver.await.map_err(|_| Error::Closed)?
    }

    /// Shuts down the managed Tor process and background manager task.
    ///
    /// Shutdown is global across every clone of this `Pool` and idempotent:
    /// calling it more than once (from one or many clones, concurrently or
    /// sequentially) is safe and only performs the underlying shutdown
    /// once. After shutdown, [`Pool::next`], [`Pool::for_key`],
    /// [`Pool::rotate`], and [`Pool::restart`] return [`Error::Closed`].
    pub async fn shutdown(&self) -> Result<(), Error> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            self.join_manager_task().await;
            return Ok(());
        }

        let (response, receiver) = oneshot::channel();
        let result = if self
            .inner
            .manager
            .send(ManagerCommand::Shutdown(response))
            .is_ok()
        {
            receiver.await.unwrap_or(Ok(()))
        } else {
            Ok(())
        };
        self.join_manager_task().await;
        result
    }

    async fn join_manager_task(&self) {
        let task = { lock_mutex(&self.inner.manager_task).take() };
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    fn ensure_open(&self) -> Result<(), Error> {
        if self.inner.closed.load(Ordering::SeqCst) {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn from_instance(
        mut instance: TorInstance,
        instance_config: InstanceConfig,
        config: PoolConfig,
    ) -> Result<Self, Error> {
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
                return Err(Error::Internal(Box::new(error)));
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
            config,
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
                closed: AtomicBool::new(false),
                manager,
                manager_task: Mutex::new(Some(task)),
            }),
        }
    }

    fn proxy_from_endpoint(
        &self,
        endpoint: Arc<crate::pool::lane::LaneEndpoint>,
    ) -> Result<Proxy, Error> {
        self.inner
            .manager
            .send(ManagerCommand::Assign {
                lane: endpoint.lane,
                epoch: endpoint.epoch,
            })
            .map_err(|_| Error::Closed)?;
        Ok(Proxy { inner: endpoint })
    }

    #[cfg(test)]
    pub(crate) fn for_test(config: PoolConfig, socks_addr: SocketAddr) -> Result<Self, Error> {
        config.validate()?;
        let runtime = RuntimeState {
            id: InstanceId(0),
            pid: Some(4242),
            socks_addr,
            generation: 1,
            restart_count: 0,
        };
        let lanes = create_lanes(&config, socks_addr, runtime.id)
            .map_err(|e| Error::Internal(Box::new(e)))?;
        Ok(Self::spawn(config, lanes, runtime, None, None))
    }
}

async fn run_manager(
    mut state: ManagerState,
    mut commands: mpsc::UnboundedReceiver<ManagerCommand>,
) {
    let period = ttl_tick_period(state.config.rotation().duration());
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(ManagerCommand::Assign { lane, epoch }) => state.assign(lane, epoch),
                    Some(ManagerCommand::Rotate { lane, response }) => {
                        let result = state.rotate(lane);
                        if let Some(response) = response {
                            let _ = response.send(result);
                        }
                    }
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
            .rotation()
            .assignment_limit()
            .is_some_and(|maximum| lane.assignments >= maximum)
            && rotate_lane(lane, self.runtime.socks_addr, self.runtime.id).is_err()
        {
            lane.state = LaneState::Failed;
        }
        self.publish();
    }

    fn rotate(&mut self, id: LaneId) -> Result<(), Error> {
        let Some(lane) = self.lanes.iter_mut().find(|lane| lane.id == id) else {
            self.publish();
            return Err(Error::UnknownLane(id));
        };
        let result = match rotate_lane(lane, self.runtime.socks_addr, self.runtime.id) {
            Ok(()) => {
                write_lock(&self.unavailable).remove(&id);
                Ok(())
            }
            Err(error) => {
                lane.state = LaneState::Failed;
                Err(Error::Internal(Box::new(error)))
            }
        };
        self.publish();
        result
    }

    fn rotate_expired(&mut self) {
        let Some(ttl) = self.config.rotation().duration() else {
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

    async fn restart(&mut self) -> Result<(), Error> {
        let config = self
            .instance_config
            .clone()
            .ok_or(Error::RestartUnavailable)?;
        *write_lock(&self.ready) = Arc::new(ReadySnapshot::empty());
        write_lock(&self.unavailable).extend(self.lanes.iter().map(|lane| lane.id));
        for lane in &mut self.lanes {
            lane.state = LaneState::Retiring;
        }
        self.publish_snapshot_only();

        if let Some(mut instance) = self.instance.take() {
            instance.shutdown().await.map_err(Error::Instance)?;
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

    async fn shutdown_instance(&mut self) -> Result<(), Error> {
        *write_lock(&self.ready) = Arc::new(ReadySnapshot::empty());
        if let Some(mut instance) = self.instance.take() {
            instance.shutdown().await.map_err(Error::Instance)?;
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
) -> Result<Vec<Lane>, crate::pool::LaneError> {
    (0..config.lanes())
        .map(|id| Lane::new(LaneId(id as u32), socks_addr, instance))
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
    use crate::RotationPolicy;

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
        assert_eq!(snapshot.ready_lane_count(), 16);
        assert_eq!(snapshot.unavailable_lane_count(), 0);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn round_robin_cycles_through_ready_lanes() {
        let pool = Pool::for_test(PoolConfig::new(3), address()).unwrap();
        let selected: Vec<_> = (0..8).map(|_| pool.next().unwrap().lane_id()).collect();

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
        let first = pool.for_key("customer-session-42").unwrap();

        for _ in 0..100 {
            let proxy = pool.for_key("customer-session-42").unwrap();
            assert_eq!(proxy.lane_id(), first.lane_id());
            assert_eq!(proxy.epoch(), first.epoch());
        }
        assert!(first.socks5h_url().expose().starts_with("socks5h://lane-"));
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rotate_waits_for_new_epoch_and_drops_stale_generation() {
        let pool = Pool::for_test(PoolConfig::new(3), address()).unwrap();
        let before = endpoints_by_lane(&pool);
        let stale = Arc::clone(before.get(&LaneId(1)).unwrap());

        pool.rotate(LaneId(1)).await.unwrap();
        let after = endpoints_by_lane(&pool);
        assert_eq!(after[&LaneId(0)].epoch, before[&LaneId(0)].epoch);
        assert_eq!(after[&LaneId(2)].epoch, before[&LaneId(2)].epoch);
        assert!(Arc::ptr_eq(&after[&LaneId(0)], &before[&LaneId(0)]));
        assert!(Arc::ptr_eq(&after[&LaneId(2)], &before[&LaneId(2)]));
        assert_eq!(after[&LaneId(1)].epoch, stale.epoch + 1);
        assert_ne!(after[&LaneId(1)].auth.password, stale.auth.password);
        assert!(!Arc::ptr_eq(&after[&LaneId(1)], &stale));
        assert_eq!(stale.epoch, 1);

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.ready_lane_count(), 3);
        assert_eq!(snapshot.lanes()[1].epoch(), 2);
        assert_eq!(snapshot.lanes()[1].state(), LaneState::Ready);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn retire_queues_rotation_without_waiting() {
        let pool = Pool::for_test(PoolConfig::new(3), address()).unwrap();

        pool.retire(LaneId(1)).unwrap();
        assert!(
            read_lock(&pool.inner.ready)
                .lanes
                .iter()
                .all(|endpoint| endpoint.lane != LaneId(1))
        );
        wait_for(&pool, |snapshot| {
            snapshot.ready_lane_count() == 3
                && snapshot.lanes()[1].epoch() == 2
                && snapshot.lanes()[1].state() == LaneState::Ready
        })
        .await;
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ttl_rotates_only_expired_lane() {
        let config = PoolConfig::new(2)
            .with_rotation(RotationPolicy::new().after(Duration::from_millis(100)));
        let pool = Pool::for_test(config, address()).unwrap();

        sleep(Duration::from_millis(60)).await;
        pool.rotate(LaneId(0)).await.unwrap();
        wait_for(&pool, |snapshot| snapshot.lanes()[1].epoch() == 2).await;

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.lanes()[0].epoch(), 2);
        assert_eq!(snapshot.lanes()[1].epoch(), 2);
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn max_assignments_rotates_lane_without_blocking_current_proxy() {
        let config = PoolConfig::new(1).with_rotation(RotationPolicy::new().after_assignments(2));
        let pool = Pool::for_test(config, address()).unwrap();

        let first = pool.next().unwrap();
        let second = pool.next().unwrap();
        assert_eq!(first.epoch(), 1);
        assert_eq!(second.epoch(), 1);
        wait_for(&pool, |snapshot| snapshot.lanes()[0].epoch() == 2).await;

        let current = pool.next().unwrap();
        assert_eq!(current.epoch(), 2);
        assert_ne!(current.expose_password(), first.expose_password());
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn empty_ready_snapshot_returns_no_ready_lanes() {
        let pool = Pool::for_test(PoolConfig::new(1), address()).unwrap();
        *write_lock(&pool.inner.ready) = Arc::new(ReadySnapshot::empty());

        assert!(matches!(pool.next(), Err(Error::NoReadyLanes)));
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn sticky_session_does_not_fall_back_when_lane_is_unavailable() {
        let pool = Pool::for_test(PoolConfig::new(4), address()).unwrap();
        let session = "fixed-session";
        let lane = pool.for_key(session).unwrap().lane_id();
        pool.retire(lane).unwrap();

        assert!(matches!(
            pool.for_key(session),
            Err(Error::LaneUnavailable(unavailable)) if unavailable == lane
        ));
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_across_clones() {
        let pool = Pool::for_test(PoolConfig::new(2), address()).unwrap();
        let clone = pool.clone();

        let (first, second) = tokio::join!(pool.shutdown(), clone.shutdown());
        first.unwrap();
        second.unwrap();

        // A third, later call must also succeed without hanging.
        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn operations_after_shutdown_return_closed() {
        let pool = Pool::for_test(PoolConfig::new(2), address()).unwrap();
        pool.shutdown().await.unwrap();

        assert!(matches!(pool.next(), Err(Error::Closed)));
        assert!(matches!(pool.for_key("x"), Err(Error::Closed)));
        assert!(matches!(pool.rotate(LaneId(0)).await, Err(Error::Closed)));
        assert!(matches!(pool.restart().await, Err(Error::Closed)));
    }

    fn endpoints_by_lane(pool: &Pool) -> HashMap<LaneId, Arc<crate::pool::lane::LaneEndpoint>> {
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
