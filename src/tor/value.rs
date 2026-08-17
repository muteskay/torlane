use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag(pub bool);

impl From<bool> for Flag {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "1" } else { "0" })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tristate {
    Off,
    On,
    Auto,
}

impl fmt::Display for Tristate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("0"),
            Self::On => f.write_str("1"),
            Self::Auto => f.write_str("auto"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    Num(u16),
    Auto,
    Unix(PathBuf),
}

impl PortSpec {
    pub fn tcp_port(&self) -> Option<u16> {
        match self {
            Self::Num(port) => Some(*port),
            Self::Auto | Self::Unix(_) => None,
        }
    }
}

impl From<u16> for PortSpec {
    fn from(value: u16) -> Self {
        Self::Num(value)
    }
}

impl From<PathBuf> for PortSpec {
    fn from(value: PathBuf) -> Self {
        Self::Unix(value)
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(port) => write!(f, "{port}"),
            Self::Auto => f.write_str("auto"),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}
