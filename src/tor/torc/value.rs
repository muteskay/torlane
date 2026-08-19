use std::fmt;
use std::path::PathBuf;

/// A torrc boolean flag, rendered as `1` or `0`.
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

/// A torrc three-way switch: explicitly off, explicitly on, or left to
/// Tor's own default (`auto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tristate {
    /// Explicitly disabled.
    Off,
    /// Explicitly enabled.
    On,
    /// Left to Tor's own default behavior.
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

/// A listener port: a fixed TCP port, an automatically chosen TCP port, or a
/// Unix domain socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// A fixed TCP port number.
    Num(u16),
    /// Let Tor choose an available TCP port automatically.
    Auto,
    /// Listen on a Unix domain socket at this path.
    Unix(PathBuf),
}

impl PortSpec {
    /// The fixed TCP port number, if this is [`PortSpec::Num`].
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
