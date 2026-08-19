use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crate::tor::torc::value::PortSpec;

/// Control Port authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAuth {
    /// Cookie authentication (`CookieAuthentication 1`).
    Cookie,
    /// Password authentication using a pre-hashed password
    /// (`HashedControlPassword`).
    HashedPassword(String),
    /// No authentication. Only permitted on a loopback listener.
    None,
}

/// Where the Control Port listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlListen {
    /// Listen on a TCP address and port.
    Tcp {
        /// The bind address.
        addr: IpAddr,
        /// The bind port, or an automatically chosen one.
        port: PortSpec,
    },
    /// Listen on a Unix domain socket at this path.
    Unix(PathBuf),
}

impl ControlListen {
    /// The fixed TCP port, if this listens on a fixed TCP port.
    pub fn tcp_port(&self) -> Option<u16> {
        match self {
            Self::Tcp { port, .. } => port.tcp_port(),
            Self::Unix(_) => None,
        }
    }

    /// Whether this listener is a loopback TCP address or a Unix socket
    /// (both are considered safe to leave unauthenticated).
    pub fn is_loopback_tcp(&self) -> bool {
        match self {
            Self::Tcp { addr, .. } => addr.is_loopback(),
            Self::Unix(_) => true,
        }
    }

    /// Whether this listener uses an automatically chosen TCP port.
    pub fn uses_auto_port(&self) -> bool {
        matches!(
            self,
            Self::Tcp {
                port: PortSpec::Auto,
                ..
            }
        )
    }
}

/// Control Port configuration: listener, authentication, and ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlConfig {
    /// Where the Control Port listens.
    pub listen: ControlListen,
    /// The authentication method required to connect.
    pub auth: ControlAuth,
    /// If set, Tor writes the resolved listener endpoint to this file (used
    /// to discover an automatically chosen port).
    pub write_port_to_file: Option<PathBuf>,
    /// If set, Tor exits when the process with this PID exits.
    pub owning_controller_process: Option<u32>,
}

impl ControlConfig {
    /// A loopback TCP listener on a fixed `port`, with cookie
    /// authentication.
    pub fn tcp(port: u16) -> Self {
        Self {
            listen: ControlListen::Tcp {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: PortSpec::Num(port),
            },
            auth: ControlAuth::Cookie,
            write_port_to_file: None,
            owning_controller_process: None,
        }
    }

    /// A loopback TCP listener on an automatically chosen port, with cookie
    /// authentication.
    pub fn auto_tcp() -> Self {
        Self {
            listen: ControlListen::Tcp {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: PortSpec::Auto,
            },
            auth: ControlAuth::Cookie,
            write_port_to_file: None,
            owning_controller_process: None,
        }
    }

    /// A Unix domain socket listener at `path`, with cookie authentication.
    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Self {
            listen: ControlListen::Unix(path.into()),
            auth: ControlAuth::Cookie,
            write_port_to_file: None,
            owning_controller_process: None,
        }
    }

    /// Binds a TCP listener to `127.0.0.1`.
    pub fn bind_localhost(mut self) -> Self {
        self = self.bind(IpAddr::V4(Ipv4Addr::LOCALHOST));
        self
    }

    /// Binds a TCP listener to `addr`. No-op for a Unix socket listener.
    pub fn bind(mut self, addr: IpAddr) -> Self {
        if let ControlListen::Tcp {
            addr: listen_addr, ..
        } = &mut self.listen
        {
            *listen_addr = addr;
        }
        self
    }

    /// Requires cookie authentication.
    pub fn cookie_authentication(mut self) -> Self {
        self.auth = ControlAuth::Cookie;
        self
    }

    /// Requires password authentication against a pre-hashed password.
    pub fn hashed_password(mut self, hash: impl Into<String>) -> Self {
        self.auth = ControlAuth::HashedPassword(hash.into());
        self
    }

    /// Disables authentication. Only valid on a loopback listener.
    pub fn no_authentication(mut self) -> Self {
        self.auth = ControlAuth::None;
        self
    }

    /// Writes the resolved listener endpoint to `path`.
    pub fn write_port_to_file(mut self, path: impl AsRef<Path>) -> Self {
        self.write_port_to_file = Some(path.as_ref().to_path_buf());
        self
    }

    /// Makes Tor exit when the process with `pid` exits.
    pub fn owning_controller_process(mut self, pid: u32) -> Self {
        self.owning_controller_process = Some(pid);
        self
    }
}
