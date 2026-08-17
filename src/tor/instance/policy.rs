use crate::tor::torc::{
    BridgeConfig, CircuitConfig, DormancyConfig, LoggingConfig, MetricsConfig, NetworkConfig,
    NodeSelectionConfig, PaddingConfig, SystemConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorPolicy {
    pub network: NetworkConfig,
    pub circuits: CircuitConfig,
    pub padding: PaddingConfig,
    pub dormancy: DormancyConfig,
    pub bridges: Option<BridgeConfig>,
    pub node_selection: NodeSelectionConfig,
    pub system: SystemConfig,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
}

impl Default for TorPolicy {
    fn default() -> Self {
        Self {
            network: NetworkConfig::tor_default(),
            circuits: CircuitConfig::default(),
            padding: PaddingConfig::default(),
            dormancy: DormancyConfig::tor_default(),
            bridges: None,
            node_selection: NodeSelectionConfig::default(),
            system: SystemConfig::default(),
            logging: LoggingConfig::default(),
            metrics: None,
        }
    }
}
