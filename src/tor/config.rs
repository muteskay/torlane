use std::path::{Path, PathBuf};

use crate::tor::bridges::BridgeConfig;
use crate::tor::circuits::CircuitConfig;
use crate::tor::control::ControlConfig;
use crate::tor::dormancy::DormancyConfig;
use crate::tor::error::TorWriteError;
use crate::tor::logging::LoggingConfig;
use crate::tor::metrics::MetricsConfig;
use crate::tor::network::NetworkConfig;
use crate::tor::nodes::NodeSelectionConfig;
use crate::tor::option::TorOption;
use crate::tor::padding::PaddingConfig;
use crate::tor::render;
use crate::tor::socks::SocksConfig;
use crate::tor::system::SystemConfig;
use crate::tor::verify::{TorRuntimeValidation, TorVerifyReport};
use crate::tor::{
    TorRuntimeValidationError, TorVerifyError, verify::validate_runtime_config,
    verify::verify_config_with,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorConfigWarning {
    UnauthenticatedLoopbackControlPort,
    AutoControlPortWithoutWriteFile,
    HighConnLimit(u32),
    ManySocksListeners(usize),
    UnsafeLoggingDisabled,
}

#[derive(Debug, Clone)]
pub struct TorConfig {
    pub(crate) data_directory: PathBuf,
    pub(crate) control: Option<ControlConfig>,
    pub(crate) socks: SocksConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) circuits: CircuitConfig,
    pub(crate) padding: PaddingConfig,
    pub(crate) dormancy: DormancyConfig,
    pub(crate) bridges: Option<BridgeConfig>,
    pub(crate) node_selection: NodeSelectionConfig,
    pub(crate) system: SystemConfig,
    pub(crate) logging: LoggingConfig,
    pub(crate) metrics: Option<MetricsConfig>,
    pub(crate) raw_options: Vec<TorOption>,
    pub(crate) warnings: Vec<TorConfigWarning>,
}

impl TorConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        data_directory: PathBuf,
        control: Option<ControlConfig>,
        socks: SocksConfig,
        network: NetworkConfig,
        circuits: CircuitConfig,
        padding: PaddingConfig,
        dormancy: DormancyConfig,
        bridges: Option<BridgeConfig>,
        node_selection: NodeSelectionConfig,
        system: SystemConfig,
        logging: LoggingConfig,
        metrics: Option<MetricsConfig>,
        raw_options: Vec<TorOption>,
        warnings: Vec<TorConfigWarning>,
    ) -> Self {
        Self {
            data_directory,
            control,
            socks,
            network,
            circuits,
            padding,
            dormancy,
            bridges,
            node_selection,
            system,
            logging,
            metrics,
            raw_options,
            warnings,
        }
    }

    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn control(&self) -> Option<&ControlConfig> {
        self.control.as_ref()
    }

    pub fn socks(&self) -> &SocksConfig {
        &self.socks
    }

    pub fn warnings(&self) -> &[TorConfigWarning] {
        &self.warnings
    }

    pub fn render(&self) -> String {
        render::render_config(self)
    }

    pub fn stdin_args() -> [&'static str; 2] {
        ["-f", "-"]
    }

    pub async fn write_to(&self, path: impl AsRef<Path>) -> Result<(), TorWriteError> {
        self.write_to_sync(path)
    }

    pub fn write_to_sync(&self, path: impl AsRef<Path>) -> Result<(), TorWriteError> {
        crate::tor::render::atomic_write(path.as_ref(), &self.render())
    }

    pub async fn write_to_stdin(
        &self,
        child_stdin: &mut std::process::ChildStdin,
    ) -> Result<(), TorWriteError> {
        use std::io::Write;

        child_stdin.write_all(self.render().as_bytes())?;
        child_stdin.flush()?;
        Ok(())
    }

    pub async fn verify_with(
        &self,
        tor_binary: impl AsRef<Path>,
    ) -> Result<TorVerifyReport, TorVerifyError> {
        verify_config_with(self, tor_binary.as_ref())
    }

    pub async fn validate_runtime(
        &self,
        tor_binary: impl AsRef<Path>,
    ) -> Result<TorRuntimeValidation, TorRuntimeValidationError> {
        validate_runtime_config(self, tor_binary.as_ref())
    }
}
