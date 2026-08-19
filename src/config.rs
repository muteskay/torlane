//! Managed pool and typed Tor policy configuration.
//!
//! [`PoolConfig`] configures the managed pool's topology (lane count,
//! rotation, bootstrap timeout). The rest of this module holds the typed
//! policy configuration used by [`TorPolicy`](crate::TorPolicy) to describe
//! application-selectable Tor behavior (network, circuits, padding,
//! bridges, node selection, system, and logging).

pub use crate::pool::{ConfigError, MAX_LANES, PoolConfig};
pub use crate::tor::torc::{
    Bridge, BridgeConfig, CircuitConfig, LogDest, LogLine, LoggingConfig, NetworkConfig,
    NodeSelectionConfig, Obfs4Bridge, PaddingConfig, Severity, SystemConfig, TransportPlugin,
};
