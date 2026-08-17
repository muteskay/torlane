use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pool::{Pool, PoolConfig, PoolError};
use crate::tor::instance::{InstanceConfig, InstanceId, TorInstance, TorPolicy};
use crate::tor::process::TorConfigSource;

#[derive(Debug, Clone)]
pub struct PoolBuilder {
    tor_binary: PathBuf,
    work_dir: Option<PathBuf>,
    policy: TorPolicy,
    config_source: TorConfigSource,
    pool_config: PoolConfig,
}

impl PoolBuilder {
    pub fn tor_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.tor_binary = path.into();
        self
    }

    pub fn work_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(path.into());
        self
    }

    pub fn policy(mut self, policy: TorPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn torrc_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_source = TorConfigSource::File(path.into());
        self
    }

    pub fn lanes(mut self, lanes: usize) -> Self {
        self.pool_config.lanes = lanes;
        self
    }

    pub fn lane_ttl(mut self, ttl: Duration) -> Self {
        self.pool_config.lane_ttl = Some(ttl);
        self
    }

    pub fn lane_max_assignments(mut self, assignments: u64) -> Self {
        self.pool_config.lane_max_assignments = Some(assignments);
        self
    }

    pub fn bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.pool_config.bootstrap_timeout = timeout;
        self
    }

    pub fn config_source(&self) -> &TorConfigSource {
        &self.config_source
    }

    pub fn policy_ref(&self) -> &TorPolicy {
        &self.policy
    }

    pub fn pool_config(&self) -> &PoolConfig {
        &self.pool_config
    }

    pub fn tor_binary_path(&self) -> &Path {
        &self.tor_binary
    }

    pub async fn build(self) -> Result<Pool, PoolError> {
        self.pool_config.validate()?;
        let work_dir = self.work_dir.ok_or(PoolError::MissingWorkDir)?;
        let instance_config = InstanceConfig::new(InstanceId(0), self.tor_binary, work_dir)
            .policy(self.policy)
            .config_source(self.config_source)
            .control_port_timeout(self.pool_config.bootstrap_timeout)
            .bootstrap_timeout(self.pool_config.bootstrap_timeout);
        let instance = TorInstance::start(instance_config.clone()).await?;
        Pool::from_instance(instance, instance_config, self.pool_config).await
    }
}

impl Default for PoolBuilder {
    fn default() -> Self {
        Self {
            tor_binary: PathBuf::from("tor"),
            work_dir: None,
            policy: TorPolicy::default(),
            config_source: TorConfigSource::default(),
            pool_config: PoolConfig::default(),
        }
    }
}
