use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crate::tor::torc::value::PortSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAuth {
    Cookie,
    HashedPassword(String),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlListen {
    Tcp { addr: IpAddr, port: PortSpec },
    Unix(PathBuf),
}

impl ControlListen {
    pub fn tcp_port(&self) -> Option<u16> {
        match self {
            Self::Tcp { port, .. } => port.tcp_port(),
            Self::Unix(_) => None,
        }
    }

    pub fn is_loopback_tcp(&self) -> bool {
        match self {
            Self::Tcp { addr, .. } => addr.is_loopback(),
            Self::Unix(_) => true,
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlConfig {
    pub listen: ControlListen,
    pub auth: ControlAuth,
    pub write_port_to_file: Option<PathBuf>,
    pub owning_controller_process: Option<u32>,
}

impl ControlConfig {
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

    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Self {
            listen: ControlListen::Unix(path.into()),
            auth: ControlAuth::Cookie,
            write_port_to_file: None,
            owning_controller_process: None,
        }
    }

    pub fn bind_localhost(mut self) -> Self {
        self = self.bind(IpAddr::V4(Ipv4Addr::LOCALHOST));
        self
    }

    pub fn bind(mut self, addr: IpAddr) -> Self {
        if let ControlListen::Tcp {
            addr: listen_addr, ..
        } = &mut self.listen
        {
            *listen_addr = addr;
        }
        self
    }

    pub fn cookie_authentication(mut self) -> Self {
        self.auth = ControlAuth::Cookie;
        self
    }

    pub fn hashed_password(mut self, hash: impl Into<String>) -> Self {
        self.auth = ControlAuth::HashedPassword(hash.into());
        self
    }

    pub fn no_authentication(mut self) -> Self {
        self.auth = ControlAuth::None;
        self
    }

    pub fn write_port_to_file(mut self, path: impl AsRef<Path>) -> Self {
        self.write_port_to_file = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn owning_controller_process(mut self, pid: u32) -> Self {
        self.owning_controller_process = Some(pid);
        self
    }
}
