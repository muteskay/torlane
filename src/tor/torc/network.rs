/// Client-side IP address family policy (`ClientUseIPv4`/`ClientUseIPv6`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Whether the client may connect to IPv4 addresses. Unset defers to
    /// Tor's own default.
    pub client_use_ipv4: Option<bool>,
    /// Whether the client may connect to IPv6 addresses. Unset defers to
    /// Tor's own default.
    pub client_use_ipv6: Option<bool>,
}

impl NetworkConfig {
    /// Leaves both address families unset, deferring to Tor's own default.
    pub fn tor_default() -> Self {
        Self::default()
    }

    /// Restricts connections to IPv4 only.
    pub fn ipv4_only() -> Self {
        Self {
            client_use_ipv4: Some(true),
            client_use_ipv6: Some(false),
        }
    }

    /// Allows both IPv4 and IPv6 connections.
    pub fn dual_stack() -> Self {
        Self {
            client_use_ipv4: Some(true),
            client_use_ipv6: Some(true),
        }
    }
}
