use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::pool::{LaneEndpoint, LaneId};

/// A selected SOCKS5 lane, returned by [`Pool::next`](crate::Pool::next) and
/// [`Pool::for_key`](crate::Pool::for_key).
///
/// A `Proxy` is an immutable snapshot of one lane epoch: rotating the lane
/// afterward (TTL, assignment limit, or [`Pool::rotate`](crate::Pool::rotate))
/// does not change or invalidate an already returned `Proxy`.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub(crate) inner: Arc<LaneEndpoint>,
}

impl Proxy {
    /// The lane's canonical identifier.
    pub fn lane_id(&self) -> LaneId {
        self.inner.lane
    }

    /// Deprecated alias for [`Proxy::lane_id`].
    #[deprecated(since = "0.2.0", note = "use `Proxy::lane_id` instead")]
    pub fn lane(&self) -> LaneId {
        self.lane_id()
    }

    /// The lane's rotation epoch at the time this `Proxy` was selected.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    /// The shared Tor SOCKS5 listener address for this lane.
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// This lane's SOCKS5 username. Safe to log.
    pub fn username(&self) -> &str {
        self.inner.auth.username()
    }

    /// This lane's SOCKS5 password. The caller must not log this value.
    pub fn expose_password(&self) -> &str {
        self.inner.auth.expose_password()
    }

    /// A `socks5h://` URL carrying this lane's address and credentials.
    ///
    /// The `socks5h` scheme instructs compatible HTTP clients to resolve
    /// hostnames through Tor instead of using local DNS.
    pub fn socks5h_url(&self) -> SocksUrl {
        SocksUrl(format!(
            "socks5h://{}:{}@{}",
            self.inner.auth.username(),
            self.inner.auth.expose_password(),
            self.inner.addr
        ))
    }
}

/// A `socks5h://` proxy URL carrying lane credentials.
///
/// `Debug` and `Display` never print the credentials; call
/// [`SocksUrl::expose`] to obtain the raw URL, and keep the result out of
/// logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SocksUrl(String);

impl SocksUrl {
    /// The raw URL, including credentials. The caller must not log this
    /// value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SocksUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocksUrl(<redacted>)")
    }
}

impl fmt::Display for SocksUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("socks5h://<redacted>")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReadySnapshot {
    pub(crate) lanes: Arc<[Arc<LaneEndpoint>]>,
}

impl ReadySnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            lanes: Arc::from([]),
        }
    }
}

pub(crate) fn stable_lane_index(key: &[u8], lane_count: usize) -> usize {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let hash = key.iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    });
    (hash % lane_count as u64) as usize
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::pool::SocksAuth;
    use crate::tor::instance::InstanceId;

    fn proxy() -> Proxy {
        Proxy {
            inner: Arc::new(LaneEndpoint {
                lane: LaneId(3),
                epoch: 7,
                instance: InstanceId(0),
                addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 19050)),
                auth: SocksAuth {
                    username: Arc::from("lane-000003-00000007"),
                    password: Arc::from("f00dcafe"),
                },
            }),
        }
    }

    #[test]
    fn proxy_debug_hides_password() {
        let debug = format!("{:?}", proxy());

        assert!(!debug.contains("f00dcafe"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("lane-000003-00000007"), "{debug}");
    }

    #[test]
    fn socks_url_debug_and_display_hide_password() {
        let url = proxy().socks5h_url();
        let debug = format!("{url:?}");
        let display = format!("{url}");

        assert!(!debug.contains("f00dcafe"), "{debug}");
        assert!(!display.contains("f00dcafe"), "{display}");
        assert!(url.expose().contains("f00dcafe"));
    }

    #[test]
    fn socks5h_url_carries_the_credentials() {
        assert_eq!(
            proxy().socks5h_url().expose(),
            "socks5h://lane-000003-00000007:f00dcafe@127.0.0.1:19050"
        );
    }
}
