use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::tor::torc::error::TorConfigError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    pub transport: Option<String>,
    pub addr: SocketAddr,
    pub fingerprint: Option<String>,
    pub args: Vec<(String, String)>,
}

impl Bridge {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            transport: None,
            addr,
            fingerprint: None,
            args: Vec::new(),
        }
    }

    pub fn transport(mut self, transport: impl Into<String>) -> Self {
        self.transport = Some(transport.into());
        self
    }

    pub fn fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push((key.into(), value.into()));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPlugin {
    pub names: Vec<String>,
    pub executable: PathBuf,
    pub args: Vec<String>,
}

impl TransportPlugin {
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

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obfs4Bridge {
    pub addr: SocketAddr,
    pub fingerprint: String,
    pub cert: String,
    pub iat_mode: u8,
}

impl Obfs4Bridge {
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeConfig {
    pub use_bridges: bool,
    pub bridges: Vec<Bridge>,
    pub transport_plugins: Vec<TransportPlugin>,
}

impl BridgeConfig {
    pub fn new() -> Self {
        Self {
            use_bridges: true,
            bridges: Vec::new(),
            transport_plugins: Vec::new(),
        }
    }

    pub fn obfs4(lyrebird: impl Into<PathBuf>) -> Self {
        Self::new().transport_plugin(TransportPlugin::exec(["obfs4"], lyrebird))
    }

    pub fn bridge(mut self, bridge: impl Into<Bridge>) -> Self {
        self.bridges.push(bridge.into());
        self
    }

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
