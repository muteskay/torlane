use crate::tor::torc::{
    BridgeConfig, CircuitConfig, LoggingConfig, NetworkConfig, NodeSelectionConfig, PaddingConfig,
    SystemConfig,
};

/// Application-selectable Tor behavior for a managed [`Pool`](crate::Pool).
///
/// `TorPolicy` deliberately does not expose `ControlConfig`, `SocksConfig`,
/// or raw Tor options: the managed runtime owns the Control Port, SOCKS
/// listener, and data directory required for pool startup, isolation,
/// restart, and shutdown. Use [`crate::low_level`] to configure those
/// directly outside a managed pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorPolicy {
    network: NetworkConfig,
    circuits: CircuitConfig,
    padding: PaddingConfig,
    bridges: Option<BridgeConfig>,
    node_selection: NodeSelectionConfig,
    system: SystemConfig,
    logging: LoggingConfig,
}

impl TorPolicy {
    /// Sets the client address-family policy.
    pub fn with_network(mut self, network: NetworkConfig) -> Self {
        self.network = network;
        self
    }

    /// Sets circuit build and timeout behavior.
    pub fn with_circuits(mut self, circuits: CircuitConfig) -> Self {
        self.circuits = circuits;
        self
    }

    /// Sets traffic-analysis-resistance padding behavior.
    pub fn with_padding(mut self, padding: PaddingConfig) -> Self {
        self.padding = padding;
        self
    }

    /// Configures bridges and their transport plugins.
    pub fn with_bridges(mut self, bridges: BridgeConfig) -> Self {
        self.bridges = Some(bridges);
        self
    }

    /// Sets exit node selection constraints.
    pub fn with_node_selection(mut self, node_selection: NodeSelectionConfig) -> Self {
        self.node_selection = node_selection;
        self
    }

    /// Sets system-level resource behavior.
    pub fn with_system(mut self, system: SystemConfig) -> Self {
        self.system = system;
        self
    }

    /// Sets logging behavior.
    pub fn with_logging(mut self, logging: LoggingConfig) -> Self {
        self.logging = logging;
        self
    }

    /// The client address-family policy.
    pub fn network(&self) -> &NetworkConfig {
        &self.network
    }

    /// Circuit build and timeout behavior.
    pub fn circuits(&self) -> &CircuitConfig {
        &self.circuits
    }

    /// Traffic-analysis-resistance padding behavior.
    pub fn padding(&self) -> &PaddingConfig {
        &self.padding
    }

    /// Bridge and transport plugin configuration, if any.
    pub fn bridges(&self) -> Option<&BridgeConfig> {
        self.bridges.as_ref()
    }

    /// Exit node selection constraints.
    pub fn node_selection(&self) -> &NodeSelectionConfig {
        &self.node_selection
    }

    /// System-level resource behavior.
    pub fn system(&self) -> &SystemConfig {
        &self.system
    }

    /// Logging behavior.
    pub fn logging(&self) -> &LoggingConfig {
        &self.logging
    }
}

impl Default for TorPolicy {
    fn default() -> Self {
        Self {
            network: NetworkConfig::tor_default(),
            circuits: CircuitConfig::default(),
            padding: PaddingConfig::default(),
            bridges: None,
            node_selection: NodeSelectionConfig::default(),
            system: SystemConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}
