use std::time::Duration;

use crate::tor::torc::value::Tristate;

/// Traffic-analysis-resistance padding behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaddingConfig {
    /// Whether Tor sends padding cells on client/relay connections.
    pub connection_padding: Option<Tristate>,
    /// If `true`, uses a lighter connection padding profile suited to
    /// mobile/metered connections.
    pub reduced_connection_padding: Option<bool>,
    /// Whether Tor sends padding cells on circuits to resist traffic
    /// analysis.
    pub circuit_padding: Option<bool>,
    /// If `true`, uses a lighter circuit padding profile suited to
    /// mobile/metered connections.
    pub reduced_circuit_padding: Option<bool>,
    /// How often Tor sends keepalive padding on idle OR connections.
    pub keepalive_period: Option<Duration>,
}

impl PaddingConfig {
    /// Sets whether connection padding is sent.
    pub fn connection_padding(mut self, value: Tristate) -> Self {
        self.connection_padding = Some(value);
        self
    }

    /// Sets whether a reduced connection padding profile is used.
    pub fn reduced_connection_padding(mut self, value: bool) -> Self {
        self.reduced_connection_padding = Some(value);
        self
    }

    /// Sets whether circuit padding is sent.
    pub fn circuit_padding(mut self, value: bool) -> Self {
        self.circuit_padding = Some(value);
        self
    }

    /// Sets whether a reduced circuit padding profile is used.
    pub fn reduced_circuit_padding(mut self, value: bool) -> Self {
        self.reduced_circuit_padding = Some(value);
        self
    }

    /// Sets the keepalive padding interval.
    pub fn keepalive_period(mut self, value: Duration) -> Self {
        self.keepalive_period = Some(value);
        self
    }
}
