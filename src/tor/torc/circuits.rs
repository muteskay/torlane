use std::time::Duration;

/// Circuit build and timeout behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CircuitConfig {
    /// The maximum age of a circuit before it is no longer used for new
    /// streams.
    pub max_circuit_dirtiness: Option<Duration>,
    /// The minimum interval between new circuit builds.
    pub new_circuit_period: Option<Duration>,
    /// How long Tor waits for a circuit to become available before giving
    /// up on a pending request.
    pub circuits_available_timeout: Option<Duration>,
    /// How long a SOCKS connection may wait for a circuit before Tor gives
    /// up.
    pub socks_timeout: Option<Duration>,
    /// The maximum time allowed to build a circuit before giving up.
    pub circuit_build_timeout: Option<Duration>,
    /// If `true`, Tor adapts `circuit_build_timeout` from observed network
    /// performance instead of using a fixed value.
    pub learn_circuit_build_timeout: Option<bool>,
    /// How long Tor waits for a stream to be attached to a circuit before
    /// giving up.
    pub circuit_stream_timeout: Option<Duration>,
    /// The maximum number of circuits pending for one client at a time.
    pub max_client_circuits_pending: Option<u32>,
    /// The number of entry guards Tor selects and reuses.
    pub num_entry_guards: Option<u32>,
    /// Whether Tor uses a persistent set of entry guards.
    pub use_entry_guards: Option<bool>,
}

impl CircuitConfig {
    /// Sets the maximum circuit age before it stops being reused.
    pub fn max_dirtiness(mut self, value: Duration) -> Self {
        self.max_circuit_dirtiness = Some(value);
        self
    }

    /// Sets the minimum interval between new circuit builds.
    pub fn new_circuit_period(mut self, value: Duration) -> Self {
        self.new_circuit_period = Some(value);
        self
    }

    /// Sets how long Tor waits for a circuit to become available.
    pub fn circuits_available_timeout(mut self, value: Duration) -> Self {
        self.circuits_available_timeout = Some(value);
        self
    }

    /// Sets how long a SOCKS connection may wait for a circuit.
    pub fn socks_timeout(mut self, value: Duration) -> Self {
        self.socks_timeout = Some(value);
        self
    }

    /// Sets the maximum time allowed to build a circuit.
    pub fn circuit_build_timeout(mut self, value: Duration) -> Self {
        self.circuit_build_timeout = Some(value);
        self
    }

    /// Sets whether the circuit build timeout is learned adaptively.
    pub fn learn_circuit_build_timeout(mut self, value: bool) -> Self {
        self.learn_circuit_build_timeout = Some(value);
        self
    }

    /// Sets how long Tor waits to attach a stream to a circuit.
    pub fn circuit_stream_timeout(mut self, value: Duration) -> Self {
        self.circuit_stream_timeout = Some(value);
        self
    }

    /// Sets the maximum number of pending circuits per client.
    pub fn max_client_circuits_pending(mut self, value: u32) -> Self {
        self.max_client_circuits_pending = Some(value);
        self
    }

    /// Sets the number of entry guards Tor selects and reuses.
    pub fn num_entry_guards(mut self, value: u32) -> Self {
        self.num_entry_guards = Some(value);
        self
    }

    /// Sets whether Tor uses a persistent set of entry guards.
    pub fn use_entry_guards(mut self, value: bool) -> Self {
        self.use_entry_guards = Some(value);
        self
    }
}
