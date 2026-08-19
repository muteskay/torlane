use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pool::{Pool, PoolConfig};
use crate::tor::instance::{InstanceConfig, InstanceId, TorInstance, TorPolicy};
use crate::tor::process::TorConfigSource;
use crate::{Error, RotationPolicy};

/// Builds a [`Pool`].
///
/// Created with [`Pool::builder`]. Required parameters (the work directory)
/// are supplied up front; everything else has a documented default.
#[derive(Debug, Clone)]
pub struct PoolBuilder {
    tor_binary: PathBuf,
    work_dir: PathBuf,
    policy: TorPolicy,
    config_source: TorConfigSource,
    pool_config: PoolConfig,
}

impl PoolBuilder {
    pub(crate) fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            tor_binary: PathBuf::from("tor"),
            work_dir: work_dir.into(),
            policy: TorPolicy::default(),
            config_source: TorConfigSource::default(),
            pool_config: PoolConfig::default(),
        }
    }

    /// The Tor executable to run. Defaults to `tor` resolved from `PATH`.
    pub fn tor_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.tor_binary = path.into();
        self
    }

    /// The application-selectable Tor behavior (network, circuits, padding,
    /// bridges, node selection, system, and logging).
    pub fn policy(mut self, policy: TorPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Writes the generated configuration to `path` and starts Tor with
    /// that file, instead of the default in-memory stdin delivery.
    ///
    /// This does not load an existing arbitrary `torrc`; it only changes
    /// how `torlane`'s own generated configuration is delivered.
    pub fn torrc_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_source = TorConfigSource::File(path.into());
        self
    }

    /// The number of logical lanes. Defaults to 16.
    pub fn lanes(mut self, lanes: usize) -> Self {
        self.pool_config.lanes = lanes;
        self
    }

    /// The lane rotation policy. Defaults to manual rotation only.
    pub fn rotation(mut self, rotation: RotationPolicy) -> Self {
        self.pool_config = self.pool_config.with_rotation(rotation);
        self
    }

    /// Deprecated alias for `rotation(RotationPolicy::new().after(ttl))`.
    #[deprecated(
        since = "0.2.0",
        note = "use `PoolBuilder::rotation` and `RotationPolicy::after` instead"
    )]
    pub fn lane_ttl(mut self, ttl: Duration) -> Self {
        self.pool_config.rotation.set_duration(ttl);
        self
    }

    /// Deprecated alias for
    /// `rotation(RotationPolicy::new().after_assignments(n))`.
    #[deprecated(
        since = "0.2.0",
        note = "use `PoolBuilder::rotation` and `RotationPolicy::after_assignments` instead"
    )]
    pub fn lane_max_assignments(mut self, assignments: u64) -> Self {
        self.pool_config.rotation.set_assignment_limit(assignments);
        self
    }

    /// The upper bound on Tor bootstrap time. This is an upper bound, not a
    /// fixed startup delay: [`PoolBuilder::start`] returns as soon as Tor
    /// reports full bootstrap progress. Defaults to 90 seconds.
    pub fn bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.pool_config = self.pool_config.with_bootstrap_timeout(timeout);
        self
    }

    /// The configured Tor configuration delivery mode.
    pub fn config_source(&self) -> &TorConfigSource {
        &self.config_source
    }

    /// The configured [`TorPolicy`].
    pub fn tor_policy(&self) -> &TorPolicy {
        &self.policy
    }

    /// The configured [`PoolConfig`].
    pub fn pool_config(&self) -> &PoolConfig {
        &self.pool_config
    }

    /// The configured Tor executable path.
    pub fn tor_binary_path(&self) -> &Path {
        &self.tor_binary
    }

    /// Validates configuration, starts the managed Tor process, verifies
    /// its configuration, waits for bootstrap, and creates the lane pool.
    pub async fn start(self) -> Result<Pool, Error> {
        self.pool_config.validate()?;
        let instance_config = InstanceConfig::new(InstanceId(0), self.tor_binary, self.work_dir)
            .policy(self.policy)
            .config_source(self.config_source)
            .control_port_timeout(self.pool_config.bootstrap_timeout())
            .bootstrap_timeout(self.pool_config.bootstrap_timeout());
        let instance = TorInstance::start(instance_config.clone()).await?;
        Pool::from_instance(instance, instance_config, self.pool_config).await
    }

    /// Deprecated alias for [`PoolBuilder::start`].
    #[deprecated(since = "0.2.0", note = "use `PoolBuilder::start` instead")]
    pub async fn build(self) -> Result<Pool, Error> {
        self.start().await
    }
}
