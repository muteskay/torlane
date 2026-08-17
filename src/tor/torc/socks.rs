use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use crate::tor::torc::error::TorConfigError;
use crate::tor::torc::value::PortSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    IsolateClientAddr,
    NoIsolateClientAddr,
    IsolateSocksAuth,
    NoIsolateSocksAuth,
    IsolateClientProtocol,
    IsolateDestPort,
    IsolateDestAddr,
    KeepAliveIsolateSocksAuth,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksFlag {
    NoIPv4Traffic,
    IPv6Traffic,
    PreferIPv6,
    NoDNSRequest,
    NoOnionTraffic,
    OnionTrafficOnly,
    CacheDNS,
    UseDNSCache,
    PreferSocksNoAuth,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksPort {
    pub addr: IpAddr,
    pub port: PortSpec,
    pub flags: Vec<SocksFlag>,
    pub isolation: Vec<Isolation>,
}

impl SocksPort {
    pub fn new(port: impl Into<PortSpec>) -> Self {
        Self::localhost(port)
    }

    pub fn localhost(port: impl Into<PortSpec>) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: port.into(),
            flags: Vec::new(),
            isolation: Vec::new(),
        }
    }

    pub fn isolated_auth(port: u16) -> Self {
        Self::localhost(port)
            .with_flag(SocksFlag::ExtendedErrors)
            .with_isolation(Isolation::IsolateSocksAuth)
            .with_isolation(Isolation::KeepAliveIsolateSocksAuth)
    }

    pub fn bind(mut self, addr: IpAddr) -> Self {
        self.addr = addr;
        self
    }

    pub fn with_flag(mut self, flag: SocksFlag) -> Self {
        self.flags.push(flag);
        self
    }

    pub fn with_isolation(mut self, isolation: Isolation) -> Self {
        self.isolation.push(isolation);
        self
    }
}

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
    pub fn none() -> Self {
        Self {
            listeners: Vec::new(),
            range_error: None,
        }
    }

    pub fn new() -> Self {
        Self::none()
    }

    pub fn isolated_auth(port: u16) -> Self {
        Self::new().listener(SocksPort::isolated_auth(port))
    }

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

    pub fn listener(mut self, listener: SocksPort) -> Self {
        self.listeners.push(listener);
        self
    }

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
