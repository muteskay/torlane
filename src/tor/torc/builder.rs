use std::collections::HashSet;
use std::path::PathBuf;

use crate::tor::torc::bridges::BridgeConfig;
use crate::tor::torc::circuits::CircuitConfig;
use crate::tor::torc::config::{TorConfig, TorConfigWarning};
use crate::tor::torc::control::{ControlAuth, ControlConfig};
use crate::tor::torc::error::TorConfigError;
use crate::tor::torc::logging::LoggingConfig;
use crate::tor::torc::network::NetworkConfig;
use crate::tor::torc::nodes::NodeSelectionConfig;
use crate::tor::torc::option::TorOption;
use crate::tor::torc::padding::PaddingConfig;
use crate::tor::torc::socks::SocksConfig;
use crate::tor::torc::system::SystemConfig;

#[derive(Debug, Clone)]
pub struct TorConfigBuilder {
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
}

impl TorConfigBuilder {
    pub fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self {
            data_directory: data_directory.into(),
            control: None,
            socks: SocksConfig::none(),
            network: NetworkConfig::tor_default(),
            circuits: CircuitConfig::default(),
            padding: PaddingConfig::default(),
            bridges: None,
            node_selection: NodeSelectionConfig::default(),
            system: SystemConfig::default(),
            logging: LoggingConfig::default(),
            raw_options: Vec::new(),
        }
    }

    pub fn control(mut self, config: ControlConfig) -> Self {
        self.control = Some(config);
        self
    }

    pub fn socks(mut self, config: SocksConfig) -> Self {
        self.socks = config;
        self
    }

    pub fn network(mut self, config: NetworkConfig) -> Self {
        self.network = config;
        self
    }

    pub fn circuits(mut self, config: CircuitConfig) -> Self {
        self.circuits = config;
        self
    }

    pub fn padding(mut self, config: PaddingConfig) -> Self {
        self.padding = config;
        self
    }

    pub fn bridges(mut self, config: BridgeConfig) -> Self {
        self.bridges = Some(config);
        self
    }

    pub fn node_selection(mut self, config: NodeSelectionConfig) -> Self {
        self.node_selection = config;
        self
    }

    pub fn system(mut self, config: SystemConfig) -> Self {
        self.system = config;
        self
    }

    pub fn logging(mut self, config: LoggingConfig) -> Self {
        self.logging = config;
        self
    }

    pub fn raw_option(mut self, option: TorOption) -> Self {
        self.raw_options.push(option);
        self
    }

    pub fn build(self) -> Result<TorConfig, TorConfigError> {
        let mut warnings = Vec::new();

        if let Some(error) = self.socks.range_error() {
            return Err(error);
        }

        if self.control.is_none() && self.socks.is_empty() {
            return Err(TorConfigError::NoListeners);
        }

        if let Some(control) = &self.control {
            if matches!(control.auth, ControlAuth::None) {
                if !control.listen.is_loopback_tcp() {
                    return Err(TorConfigError::UnauthenticatedNonLoopbackControlPort);
                }
                warnings.push(TorConfigWarning::UnauthenticatedLoopbackControlPort);
            }

            if control.listen.uses_auto_port() && control.write_port_to_file.is_none() {
                warnings.push(TorConfigWarning::AutoControlPortWithoutWriteFile);
            }
        }

        self.validate_duplicate_ports()?;

        if let Some(bridges) = &self.bridges {
            bridges.validate()?;
        }

        if self.socks.listeners().len() > 32 {
            warnings.push(TorConfigWarning::ManySocksListeners(
                self.socks.listeners().len(),
            ));
        }

        if let Some(conn_limit) = self.system.conn_limit {
            if conn_limit > 10_000 {
                warnings.push(TorConfigWarning::HighConnLimit(conn_limit));
            }
        }

        if self.logging.safe_logging == Some(false) {
            warnings.push(TorConfigWarning::UnsafeLoggingDisabled);
        }

        Ok(TorConfig::new(
            self.data_directory,
            self.control,
            self.socks,
            self.network,
            self.circuits,
            self.padding,
            self.bridges,
            self.node_selection,
            self.system,
            self.logging,
            self.raw_options,
            warnings,
        ))
    }

    fn validate_duplicate_ports(&self) -> Result<(), TorConfigError> {
        let mut seen = HashSet::new();

        if let Some(port) = self
            .control
            .as_ref()
            .and_then(|control| control.listen.tcp_port())
        {
            if !seen.insert(port) {
                return Err(TorConfigError::DuplicatePort(port));
            }
        }

        for listener in self.socks.listeners() {
            if let Some(port) = listener.port.tcp_port() {
                if !seen.insert(port) {
                    return Err(TorConfigError::DuplicatePort(port));
                }
            }
        }

        Ok(())
    }
}
