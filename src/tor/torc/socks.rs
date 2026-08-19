use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use crate::tor::torc::error::TorConfigError;
use crate::tor::torc::value::PortSpec;

/// A SOCKS stream isolation flag (`IsolateSOCKSAuth`, `SessionGroup`, etc.),
/// controlling which streams Tor may share a circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// Isolate streams by client source address.
    IsolateClientAddr,
    /// Do not isolate streams by client source address.
    NoIsolateClientAddr,
    /// Isolate streams by SOCKS username/password.
    IsolateSocksAuth,
    /// Do not isolate streams by SOCKS username/password.
    NoIsolateSocksAuth,
    /// Isolate streams by the client protocol used (SOCKS4 vs SOCKS5).
    IsolateClientProtocol,
    /// Isolate streams by destination port.
    IsolateDestPort,
    /// Isolate streams by destination address.
    IsolateDestAddr,
    /// Keep reusing the same circuit for streams with the same SOCKS
    /// credentials, instead of rotating on every new stream.
    KeepAliveIsolateSocksAuth,
    /// Isolate streams into an explicit numbered isolation group.
    SessionGroup(i32),
}

impl fmt::Display for Isolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsolateClientAddr => f.write_str("IsolateClientAddr"),
            Self::NoIsolateClientAddr => f.write_str("NoIsolateClientAddr"),
            Self::IsolateSocksAuth => f.write_str("IsolateSOCKSAuth"),
            Self::NoIsolateSocksAuth => f.write_str("NoIsolateSOCKSAuth"),
            Self::IsolateClientProtocol => f.write_str("IsolateClientProtocol"),
            Self::IsolateDestPort => f.write_str("IsolateDestPort"),
            Self::IsolateDestAddr => f.write_str("IsolateDestAddr"),
            Self::KeepAliveIsolateSocksAuth => f.write_str("KeepAliveIsolateSOCKSAuth"),
            Self::SessionGroup(group) => write!(f, "SessionGroup={group}"),
        }
    }
}

/// A per-listener SOCKS behavior flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksFlag {
    /// Refuse to connect to IPv4 addresses on this listener.
    NoIPv4Traffic,
    /// Allow connecting to IPv6 addresses on this listener.
    IPv6Traffic,
    /// Prefer IPv6 over IPv4 when both are available.
    PreferIPv6,
    /// Refuse SOCKS4 requests that specify a hostname to resolve remotely.
    NoDNSRequest,
    /// Refuse connections to onion services on this listener.
    NoOnionTraffic,
    /// Only allow connections to onion services on this listener.
    OnionTrafficOnly,
    /// Cache DNS answers seen on this listener for reuse.
    CacheDNS,
    /// Use the DNS cache for lookups on this listener.
    UseDNSCache,
    /// Prefer no authentication over username/password when both are
    /// offered by the client.
    PreferSocksNoAuth,
    /// Return extended SOCKS5 error codes instead of a generic failure.
    ExtendedErrors,
}

impl fmt::Display for SocksFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIPv4Traffic => f.write_str("NoIPv4Traffic"),
            Self::IPv6Traffic => f.write_str("IPv6Traffic"),
            Self::PreferIPv6 => f.write_str("PreferIPv6"),
            Self::NoDNSRequest => f.write_str("NoDNSRequest"),
            Self::NoOnionTraffic => f.write_str("NoOnionTraffic"),
            Self::OnionTrafficOnly => f.write_str("OnionTrafficOnly"),
            Self::CacheDNS => f.write_str("CacheDNS"),
            Self::UseDNSCache => f.write_str("UseDNSCache"),
            Self::PreferSocksNoAuth => f.write_str("PreferSOCKSNoAuth"),
            Self::ExtendedErrors => f.write_str("ExtendedErrors"),
        }
    }
}

/// One `SocksPort` listener: address, port, flags, and isolation settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksPort {
    /// The address this listener binds to.
    pub addr: IpAddr,
    /// The port (or automatic/Unix socket) this listener binds to.
    pub port: PortSpec,
    /// Listener-level SOCKS behavior flags.
    pub flags: Vec<SocksFlag>,
    /// Stream isolation settings applied to this listener.
    pub isolation: Vec<Isolation>,
}

impl SocksPort {
    /// Creates a listener bound to localhost at `port`.
    pub fn new(port: impl Into<PortSpec>) -> Self {
        Self::localhost(port)
    }

    /// Creates a listener bound to `127.0.0.1` at `port`, with no flags or
    /// isolation settings.
    pub fn localhost(port: impl Into<PortSpec>) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: port.into(),
            flags: Vec::new(),
            isolation: Vec::new(),
        }
    }

    /// A localhost listener with extended errors and SOCKS-auth-based
    /// stream isolation, the configuration `torlane`'s managed pool uses
    /// for its lanes.
    pub fn isolated_auth(port: impl Into<PortSpec>) -> Self {
        Self::localhost(port)
            .with_flag(SocksFlag::ExtendedErrors)
            .with_isolation(Isolation::IsolateSocksAuth)
            .with_isolation(Isolation::KeepAliveIsolateSocksAuth)
    }

    /// [`SocksPort::isolated_auth`] with an automatically chosen port.
    pub fn isolated_auth_auto() -> Self {
        Self::isolated_auth(PortSpec::Auto)
    }

    /// Sets the bind address.
    pub fn bind(mut self, addr: IpAddr) -> Self {
        self.addr = addr;
        self
    }

    /// Adds a listener behavior flag.
    pub fn with_flag(mut self, flag: SocksFlag) -> Self {
        self.flags.push(flag);
        self
    }

    /// Adds a stream isolation setting.
    pub fn with_isolation(mut self, isolation: Isolation) -> Self {
        self.isolation.push(isolation);
        self
    }
}

/// The set of `SocksPort` listeners for a [`TorConfig`](crate::low_level::TorConfig).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksConfig {
    listeners: Vec<SocksPort>,
    range_error: Option<TorConfigError>,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self::none()
    }
}

impl SocksConfig {
    /// No SOCKS listeners.
    pub fn none() -> Self {
        Self {
            listeners: Vec::new(),
            range_error: None,
        }
    }

    /// Alias for [`SocksConfig::none`].
    pub fn new() -> Self {
        Self::none()
    }

    /// One listener at `port` with SOCKS-auth-based stream isolation.
    pub fn isolated_auth(port: impl Into<PortSpec>) -> Self {
        Self::new().listener(SocksPort::isolated_auth(port))
    }

    /// One listener at an automatically chosen port with SOCKS-auth-based
    /// stream isolation.
    pub fn isolated_auth_auto() -> Self {
        Self::new().listener(SocksPort::isolated_auth_auto())
    }

    /// `count` localhost listeners starting at `start_port`. Fails
    /// (recorded and surfaced by [`TorConfigBuilder::build`](crate::low_level::TorConfigBuilder::build))
    /// if `count` is zero or the range overflows `u16`.
    pub fn port_range(start_port: u16, count: u16) -> Self {
        if count == 0 {
            return Self {
                listeners: Vec::new(),
                range_error: Some(TorConfigError::EmptySocksPortRange),
            };
        }

        let Some(last) = start_port.checked_add(count - 1) else {
            return Self {
                listeners: Vec::new(),
                range_error: Some(TorConfigError::PortRangeOverflow),
            };
        };

        let listeners = (start_port..=last).map(SocksPort::localhost).collect();

        Self {
            listeners,
            range_error: None,
        }
    }

    /// Adds one listener.
    pub fn listener(mut self, listener: SocksPort) -> Self {
        self.listeners.push(listener);
        self
    }

    /// The configured listeners.
    pub fn listeners(&self) -> &[SocksPort] {
        &self.listeners
    }

    pub(crate) fn range_error(&self) -> Option<TorConfigError> {
        self.range_error.clone()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}
