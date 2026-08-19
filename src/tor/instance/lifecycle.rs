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

/// Identifies one [`TorInstance`] within a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId(pub u32);

/// Configuration for [`TorInstance::start`].
#[derive(Debug, Clone)]
pub struct InstanceConfig {
    /// This instance's identifier.
    pub id: InstanceId,
    /// The `tor` executable to run.
    pub tor_binary: PathBuf,
    /// The instance's root directory (holds the data directory and runtime
    /// files).
    pub root: PathBuf,
    /// The application-selectable Tor behavior.
    pub policy: TorPolicy,
    /// How the generated configuration is delivered to the process.
    pub config_source: TorConfigSource,
    /// The upper bound on waiting for the Control Port file to appear.
    pub control_port_timeout: Duration,
    /// The upper bound on waiting for Tor bootstrap to complete.
    pub bootstrap_timeout: Duration,
}

impl InstanceConfig {
    /// Creates a config with default policy, stdin delivery, and default
    /// timeouts.
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

    /// Sets the application-selectable Tor behavior.
    pub fn policy(mut self, policy: TorPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the configuration delivery mode.
    pub fn config_source(mut self, source: TorConfigSource) -> Self {
        self.config_source = source;
        self
    }

    /// Delivers configuration through a file at `path`.
    pub fn torrc_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_source = TorConfigSource::File(path.into());
        self
    }

    /// Sets the upper bound on waiting for the Control Port file.
    pub fn control_port_timeout(mut self, timeout: Duration) -> Self {
        self.control_port_timeout = timeout;
        self
    }

    /// Sets the upper bound on waiting for Tor bootstrap.
    pub fn bootstrap_timeout(mut self, timeout: Duration) -> Self {
        self.bootstrap_timeout = timeout;
        self
    }
}

/// A running Tor process with an authenticated Control Port connection and
/// a discovered SOCKS listener.
///
/// Unlike [`TorProcess`](crate::low_level::TorProcess), starting a
/// `TorInstance` verifies its configuration, authenticates a controller,
/// waits for bootstrap, and discovers the SOCKS address.
pub struct TorInstance {
    /// This instance's identifier.
    pub id: InstanceId,
    #[allow(dead_code, reason = "kept for future diagnostics; not read today")]
    pub(crate) layout: InstanceLayout,
    process: TorProcess,
    controller: ControlClient,
    socks_addr: SocketAddr,
}

impl TorInstance {
    /// Detects the Tor version, verifies the configuration, launches the
    /// process, authenticates the controller, waits for bootstrap, and
    /// discovers the SOCKS listener. On failure, any partially started
    /// process is shut down before returning the error.
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

    /// The discovered SOCKS listener address.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The authenticated Control Port connection.
    pub fn controller(&self) -> &ControlClient {
        &self.controller
    }

    /// The Tor process id, if it is still running.
    pub fn process_id(&self) -> Option<u32> {
        self.process.id()
    }

    /// Gracefully stops the Tor process.
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
        controller.authenticate_and_take_ownership().await?;
        controller.wait_bootstrap(config.bootstrap_timeout).await?;
        let socks_addr = controller.socks_listener().await?;
        Ok((controller, socks_addr))
    }
}

/// [`TorInstance::start`] or [`TorInstance::shutdown`] failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorInstanceError {
    /// Preparing the instance's data/runtime directories failed.
    #[error("failed to prepare Tor instance layout: {0}")]
    Layout(#[from] io::Error),

    /// Building the runtime `torrc` from the configured [`TorPolicy`]
    /// failed.
    #[error("failed to build Tor runtime configuration: {0}")]
    Config(#[from] TorConfigError),

    /// Detecting the installed Tor version failed.
    #[error("failed to detect Tor version: {0}")]
    Version(#[from] TorVersionError),

    /// `tor --verify-config` rejected the generated configuration.
    #[error("Tor configuration verification failed: {0}")]
    Verify(#[from] TorVerifyError),

    /// The background configuration-verification task panicked or was
    /// cancelled.
    #[error("Tor configuration verification task failed: {0}")]
    VerificationTask(tokio::task::JoinError),

    /// Launching or stopping the Tor process failed.
    #[error("Tor process failed: {0}")]
    Process(#[from] TorProcessError),

    /// Connecting to, authenticating, or querying the Control Port failed.
    #[error("Tor control startup failed: {0}")]
    Control(#[from] TorControlError),
}
