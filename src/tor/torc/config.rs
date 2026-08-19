use std::path::PathBuf;

use crate::tor::torc::bridges::BridgeConfig;
use crate::tor::torc::circuits::CircuitConfig;
use crate::tor::torc::control::ControlConfig;
use crate::tor::torc::logging::LoggingConfig;
use crate::tor::torc::network::NetworkConfig;
use crate::tor::torc::nodes::NodeSelectionConfig;
use crate::tor::torc::option::TorOption;
use crate::tor::torc::padding::PaddingConfig;
use crate::tor::torc::render;
use crate::tor::torc::socks::SocksConfig;
use crate::tor::torc::system::SystemConfig;

/// A non-fatal concern about a built [`TorConfig`], surfaced by
/// [`TorConfigBuilder::build`](crate::low_level::TorConfigBuilder::build).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorConfigWarning {
    /// The Control Port has no authentication, but is safely bound to
    /// loopback only.
    UnauthenticatedLoopbackControlPort,
    /// The Control Port uses an automatically chosen port with no
    /// `ControlPortWriteToFile` configured, so the resolved port cannot be
    /// discovered.
    AutoControlPortWithoutWriteFile,
    /// [`SystemConfig::conn_limit`](crate::config::SystemConfig::conn_limit)
    /// is unusually high.
    HighConnLimit(u32),
    /// More than 32 SOCKS listeners are configured.
    ManySocksListeners(usize),
    /// [`LoggingConfig::safe_logging`](crate::config::LoggingConfig::safe_logging)
    /// is explicitly disabled, which may log sensitive values.
    UnsafeLoggingDisabled,
}

/// A fully built, renderable Tor configuration.
///
/// Constructed by [`TorConfigBuilder::build`](crate::low_level::TorConfigBuilder::build).
#[derive(Debug, Clone)]
pub struct TorConfig {
    pub(crate) data_directory: PathBuf,
    pub(crate) control: Option<ControlConfig>,
    pub(crate) socks: SocksConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) circuits: CircuitConfig,
    pub(crate) padding: PaddingConfig,
    pub(crate) bridges: Option<BridgeConfig>,
    pub(crate) node_selection: NodeSelectionConfig,
    pub(crate) system: SystemConfig,
    pub(crate) logging: LoggingConfig,
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
        bridges: Option<BridgeConfig>,
        node_selection: NodeSelectionConfig,
        system: SystemConfig,
        logging: LoggingConfig,
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
            bridges,
            node_selection,
            system,
            logging,
            raw_options,
            warnings,
        }
    }

    /// The configured `DataDirectory`.
    pub fn data_directory(&self) -> &std::path::Path {
        &self.data_directory
    }

    /// The configured Control Port, if any.
    pub fn control(&self) -> Option<&ControlConfig> {
        self.control.as_ref()
    }

    /// The configured SOCKS listeners.
    pub fn socks(&self) -> &SocksConfig {
        &self.socks
    }

    /// Non-fatal concerns raised while building this configuration.
    pub fn warnings(&self) -> &[TorConfigWarning] {
        &self.warnings
    }

    /// Renders this configuration as a `torrc` file.
    pub fn render(&self) -> String {
        render::render_config(self)
    }
}
