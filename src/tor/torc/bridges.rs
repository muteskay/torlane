use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::tor::torc::error::TorConfigError;

/// One `Bridge` line: a bridge relay address, optional pluggable transport,
/// fingerprint, and transport-specific arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    /// The pluggable transport name used to reach this bridge, if any. Must
    /// match a name registered in [`BridgeConfig::transport_plugins`].
    pub transport: Option<String>,
    /// The bridge's network address.
    pub addr: SocketAddr,
    /// The bridge relay's identity fingerprint.
    pub fingerprint: Option<String>,
    /// Transport-specific `key=value` arguments appended to the `Bridge`
    /// line.
    pub args: Vec<(String, String)>,
}

impl Bridge {
    /// Creates a bridge with no transport, fingerprint, or arguments.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            transport: None,
            addr,
            fingerprint: None,
            args: Vec::new(),
        }
    }

    /// Sets the pluggable transport name.
    pub fn transport(mut self, transport: impl Into<String>) -> Self {
        self.transport = Some(transport.into());
        self
    }

    /// Sets the bridge relay's identity fingerprint.
    pub fn fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// Adds a transport-specific `key=value` argument.
    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push((key.into(), value.into()));
        self
    }
}

/// A `ClientTransportPlugin` line registering a pluggable transport
/// executable for one or more transport names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPlugin {
    /// The transport name(s) this executable handles (e.g. `["obfs4"]`).
    pub names: Vec<String>,
    /// The path to the pluggable transport executable.
    pub executable: PathBuf,
    /// Extra command-line arguments passed to the executable.
    pub args: Vec<String>,
}

impl TransportPlugin {
    /// Registers `executable` to handle the given transport `names`.
    pub fn exec<I, S>(names: I, executable: impl Into<PathBuf>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
            executable: executable.into(),
            args: Vec::new(),
        }
    }

    /// Adds a command-line argument for the transport executable.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }
}

/// A typed obfs4 bridge, convertible into a [`Bridge`] via `Into`/`From`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obfs4Bridge {
    /// The bridge's network address.
    pub addr: SocketAddr,
    /// The bridge relay's identity fingerprint.
    pub fingerprint: String,
    /// The obfs4 `cert` parameter published by the bridge.
    pub cert: String,
    /// The obfs4 `iat-mode` parameter (must be 0, 1, or 2).
    pub iat_mode: u8,
}

impl Obfs4Bridge {
    /// Creates an obfs4 bridge description.
    pub fn new(
        addr: SocketAddr,
        fingerprint: impl Into<String>,
        cert: impl Into<String>,
        iat_mode: u8,
    ) -> Self {
        Self {
            addr,
            fingerprint: fingerprint.into(),
            cert: cert.into(),
            iat_mode,
        }
    }
}

impl From<Obfs4Bridge> for Bridge {
    fn from(value: Obfs4Bridge) -> Self {
        Bridge::new(value.addr)
            .transport("obfs4")
            .fingerprint(value.fingerprint)
            .arg("cert", value.cert)
            .arg("iat-mode", value.iat_mode.to_string())
    }
}

/// Bridge relays and their pluggable transports (`UseBridges`,
/// `ClientTransportPlugin`, and `Bridge` lines).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeConfig {
    /// Whether Tor connects to the network exclusively through bridges.
    pub use_bridges: bool,
    /// The configured bridge relays.
    pub bridges: Vec<Bridge>,
    /// The registered pluggable transport executables.
    pub transport_plugins: Vec<TransportPlugin>,
}

impl BridgeConfig {
    /// Enables bridge usage with no bridges or transports configured yet.
    pub fn new() -> Self {
        Self {
            use_bridges: true,
            bridges: Vec::new(),
            transport_plugins: Vec::new(),
        }
    }

    /// Enables bridge usage and registers `lyrebird` as the `obfs4`
    /// transport executable.
    pub fn obfs4(lyrebird: impl Into<PathBuf>) -> Self {
        Self::new().transport_plugin(TransportPlugin::exec(["obfs4"], lyrebird))
    }

    /// Adds one bridge.
    pub fn bridge(mut self, bridge: impl Into<Bridge>) -> Self {
        self.bridges.push(bridge.into());
        self
    }

    /// Registers one pluggable transport executable.
    pub fn transport_plugin(mut self, plugin: TransportPlugin) -> Self {
        self.transport_plugins.push(plugin);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), TorConfigError> {
        let transports: HashSet<&str> = self
            .transport_plugins
            .iter()
            .flat_map(|plugin| plugin.names.iter().map(String::as_str))
            .collect();

        for bridge in &self.bridges {
            if let Some(transport) = &bridge.transport {
                if !transports.contains(transport.as_str()) {
                    return Err(TorConfigError::MissingTransportPlugin(transport.clone()));
                }
            }

            if bridge.transport.as_deref() == Some("obfs4") {
                let fingerprint = bridge.fingerprint.as_deref().unwrap_or_default();
                if fingerprint.is_empty() {
                    return Err(TorConfigError::InvalidObfs4Bridge("empty fingerprint"));
                }

                let cert = bridge
                    .args
                    .iter()
                    .find(|(key, _)| key == "cert")
                    .map(|(_, value)| value.as_str())
                    .unwrap_or_default();
                if cert.is_empty() {
                    return Err(TorConfigError::InvalidObfs4Bridge("empty cert"));
                }

                let iat_mode = bridge
                    .args
                    .iter()
                    .find(|(key, _)| key == "iat-mode")
                    .and_then(|(_, value)| value.parse::<u8>().ok());
                if !matches!(iat_mode, Some(0..=2)) {
                    return Err(TorConfigError::InvalidObfs4Bridge("invalid iat-mode"));
                }
            }
        }

        Ok(())
    }
}
