use std::time::Duration;

use crate::tor::torc::value::Tristate;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaddingConfig {
    pub connection_padding: Option<Tristate>,
    pub reduced_connection_padding: Option<bool>,
    pub circuit_padding: Option<bool>,
    pub reduced_circuit_padding: Option<bool>,
    pub keepalive_period: Option<Duration>,
}

impl PaddingConfig {
    pub fn connection_padding(mut self, value: Tristate) -> Self {
        self.connection_padding = Some(value);
        self
    }

    pub fn reduced_connection_padding(mut self, value: bool) -> Self {
        self.reduced_connection_padding = Some(value);
        self
    }

    pub fn circuit_padding(mut self, value: bool) -> Self {
        self.circuit_padding = Some(value);
        self
    }

    pub fn reduced_circuit_padding(mut self, value: bool) -> Self {
        self.reduced_circuit_padding = Some(value);
        self
    }

    pub fn keepalive_period(mut self, value: Duration) -> Self {
        self.keepalive_period = Some(value);
        self
    }
}
