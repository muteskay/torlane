use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CircuitConfig {
    pub max_circuit_dirtiness: Option<Duration>,
    pub new_circuit_period: Option<Duration>,
    pub circuits_available_timeout: Option<Duration>,
    pub socks_timeout: Option<Duration>,
    pub circuit_build_timeout: Option<Duration>,
    pub learn_circuit_build_timeout: Option<bool>,
    pub circuit_stream_timeout: Option<Duration>,
    pub max_client_circuits_pending: Option<u32>,
    pub num_entry_guards: Option<u32>,
    pub use_entry_guards: Option<bool>,
}

impl CircuitConfig {
    pub fn max_dirtiness(mut self, value: Duration) -> Self {
        self.max_circuit_dirtiness = Some(value);
        self
    }

    pub fn new_circuit_period(mut self, value: Duration) -> Self {
        self.new_circuit_period = Some(value);
        self
    }

    pub fn circuits_available_timeout(mut self, value: Duration) -> Self {
        self.circuits_available_timeout = Some(value);
        self
    }

    pub fn socks_timeout(mut self, value: Duration) -> Self {
        self.socks_timeout = Some(value);
        self
    }

    pub fn circuit_build_timeout(mut self, value: Duration) -> Self {
        self.circuit_build_timeout = Some(value);
        self
    }

    pub fn learn_circuit_build_timeout(mut self, value: bool) -> Self {
        self.learn_circuit_build_timeout = Some(value);
        self
    }

    pub fn circuit_stream_timeout(mut self, value: Duration) -> Self {
        self.circuit_stream_timeout = Some(value);
        self
    }

    pub fn max_client_circuits_pending(mut self, value: u32) -> Self {
        self.max_client_circuits_pending = Some(value);
        self
    }

    pub fn num_entry_guards(mut self, value: u32) -> Self {
        self.num_entry_guards = Some(value);
        self
    }

    pub fn use_entry_guards(mut self, value: bool) -> Self {
        self.use_entry_guards = Some(value);
        self
    }
}
