use std::path::PathBuf;

use crate::tor::instance::TorPolicy;
use crate::tor::process::TorConfigSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    policy: TorPolicy,
    config_source: TorConfigSource,
}

impl Pool {
    pub fn builder() -> PoolBuilder {
        PoolBuilder::default()
    }

    pub fn policy(&self) -> &TorPolicy {
        &self.policy
    }

    pub fn config_source(&self) -> &TorConfigSource {
        &self.config_source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBuilder {
    policy: TorPolicy,
    config_source: TorConfigSource,
}

impl Default for PoolBuilder {
    fn default() -> Self {
        Self {
            policy: TorPolicy::default(),
            config_source: TorConfigSource::default(),
        }
    }
}

impl PoolBuilder {
    pub fn policy(mut self, policy: TorPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn torrc_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_source = TorConfigSource::File(path.into());
        self
    }

    pub fn config_source(&self) -> &TorConfigSource {
        &self.config_source
    }

    pub fn build(self) -> Pool {
        Pool {
            policy: self.policy,
            config_source: self.config_source,
        }
    }
}
