use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::tor::controller::{ControlClient, TorControlError, wait_control_port_file};
use crate::tor::error::{TorProcessError, TorVerifyError, TorVersionError};
use crate::tor::instance::{InstanceLayout, TorPolicy, build_runtime_config};
use crate::tor::process::{TorConfigSource, TorProcess};
use crate::tor::torc::TorConfigError;
use crate::tor::verify::verify_config_source_with;
use crate::tor::version::detect_tor_version;

const DEFAULT_CONTROL_PORT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId(pub u32);

#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub id: InstanceId,
    pub tor_binary: PathBuf,
    pub root: PathBuf,
    pub policy: TorPolicy,
    pub config_source: TorConfigSource,
    pub control_port_timeout: Duration,
    pub bootstrap_timeout: Duration,
}

impl InstanceConfig {
    pub fn new(id: InstanceId, tor_binary: impl Into<PathBuf>, root: impl Into<PathBuf>) -> Self {
        Self {
            id,
            tor_binary: tor_binary.into(),
            root: root.into(),
            policy: TorPolicy::default(),
            config_source: TorConfigSource::default(),
            control_port_timeout: DEFAULT_CONTROL_PORT_TIMEOUT,
            bootstrap_timeout: DEFAULT_BOOTSTRAP_TIMEOUT,
        }
    }

    pub fn policy(mut self, policy: TorPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn config_source(mut self, source: TorConfigSource) -> Self {
        self.config_source = source;
        self
    }

    pub fn torrc_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_source = TorConfigSource::File(path.into());
        self
    }

    pub fn control_port_timeout(mut self, timeout: Duration) -> Self {
        self.control_port_timeout = timeout;
        self
    }

    pub fn bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.bootstrap_timeout = timeout;
        self
    }
}

pub struct TorInstance {
    pub id: InstanceId,
    pub layout: InstanceLayout,
    process: TorProcess,
    controller: ControlClient,
    socks_addr: SocketAddr,
}

impl TorInstance {
    pub async fn start(config: InstanceConfig) -> Result<Self, TorInstanceError> {
        let layout = InstanceLayout::prepare(&config.root)?;
        let parent_pid = std::process::id();
        let tor_config = build_runtime_config(&config.policy, &layout, parent_pid)?;
        let source = config.config_source.clone();

        detect_tor_version(&config.tor_binary).await?;
        let verification_config = tor_config.clone();
        let verification_source = source.clone();
        let verification_binary = config.tor_binary.clone();
        tokio::task::spawn_blocking(move || {
            verify_config_source_with(
                &verification_config,
                &verification_source,
                &verification_binary,
            )
        })
        .await
        .map_err(TorInstanceError::VerificationTask)??;

        let mut process = TorProcess::spawn(&config.tor_binary, &tor_config, &source).await?;
        let startup = Self::finish_startup(&config, &layout).await;

        match startup {
            Ok((controller, socks_addr)) => Ok(Self {
                id: config.id,
                layout,
                process,
                controller,
                socks_addr,
            }),
            Err(error) => {
                let _ = process.shutdown().await;
                Err(error)
            }
        }
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    pub fn controller(&self) -> &ControlClient {
        &self.controller
    }

    pub fn process_id(&self) -> Option<u32> {
        self.process.id()
    }

    pub async fn shutdown(&mut self) -> Result<(), TorInstanceError> {
        self.process.shutdown().await?;
        Ok(())
    }

    async fn finish_startup(
        config: &InstanceConfig,
        layout: &InstanceLayout,
    ) -> Result<(ControlClient, SocketAddr), TorInstanceError> {
        let control_addr =
            wait_control_port_file(&layout.control_port_file, config.control_port_timeout).await?;
        let controller = ControlClient::connect(control_addr).await?;
        let protocol = controller.protocol_info().await?;
        controller.authenticate(&protocol).await?;
        controller.take_ownership().await?;
        controller.enable_bootstrap_events().await?;
        controller.wait_bootstrap(config.bootstrap_timeout).await?;
        let socks_addr = controller.socks_listener().await?;
        Ok((controller, socks_addr))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TorInstanceError {
    #[error("failed to prepare Tor instance layout: {0}")]
    Layout(#[from] io::Error),

    #[error("failed to build Tor runtime configuration: {0}")]
    Config(#[from] TorConfigError),

    #[error("failed to detect Tor version: {0}")]
    Version(#[from] TorVersionError),

    #[error("Tor configuration verification failed: {0}")]
    Verify(#[from] TorVerifyError),

    #[error("Tor configuration verification task failed: {0}")]
    VerificationTask(tokio::task::JoinError),

    #[error("Tor process failed: {0}")]
    Process(#[from] TorProcessError),

    #[error("Tor control startup failed: {0}")]
    Control(#[from] TorControlError),
}
