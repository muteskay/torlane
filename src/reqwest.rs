use crate::Proxy;

impl Proxy {
    pub fn reqwest_proxy(&self) -> Result<::reqwest::Proxy, ::reqwest::Error> {
        ::reqwest::Proxy::all(self.socks5h_url())
    }

    pub fn configure_reqwest(
        &self,
        builder: ::reqwest::ClientBuilder,
    ) -> Result<::reqwest::ClientBuilder, ::reqwest::Error> {
        Ok(builder.proxy(self.reqwest_proxy()?))
    }

    pub fn reqwest_client(&self) -> Result<::reqwest::Client, ::reqwest::Error> {
        self.configure_reqwest(::reqwest::Client::builder())?
            .build()
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::Pool;
    use crate::pool::{LaneEndpoint, LaneId, LaneState, PoolConfig, SocksAuth};
    use crate::tor::instance::InstanceId;

    enum FakeMode {
        RespondHttp,
        CloseAfterConnect,
    }

    struct SocksSession {
        username: String,
        password: String,
        domain: String,
        port: u16,
        http_request: Option<String>,
    }

    fn proxy_at(addr: SocketAddr, username: &str, password: &str) -> Proxy {
        Proxy {
            inner: Arc::new(LaneEndpoint {
                lane: LaneId(0),
                epoch: 1,
                instance: InstanceId(0),
                addr,
                auth: SocksAuth {
                    username: Arc::from(username),
                    password: Arc::from(password),
                },
            }),
        }
    }

    async fn spawn_fake_socks(
        mode: FakeMode,
    ) -> (SocketAddr, oneshot::Receiver<io::Result<SocksSession>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake SOCKS listener");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(accept_one(listener, mode).await);
        });
        (addr, rx)
    }

    async fn accept_one(listener: TcpListener, mode: FakeMode) -> io::Result<SocksSession> {
        let (mut stream, _) = listener.accept().await?;

        // Greeting: VER, NMETHODS, METHODS[]. Always select username/password
        // authentication (0x02), which is what a credential-bearing proxy URL
        // makes `reqwest` offer.
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = vec![0_u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[0x05, 0x02]).await?;

        // Username/password subnegotiation (RFC 1929).
        let mut auth_header = [0_u8; 2];
        stream.read_exact(&mut auth_header).await?;
        let mut username = vec![0_u8; auth_header[1] as usize];
        stream.read_exact(&mut username).await?;
        let mut password_len = [0_u8; 1];
        stream.read_exact(&mut password_len).await?;
        let mut password = vec![0_u8; password_len[0] as usize];
        stream.read_exact(&mut password).await?;
        stream.write_all(&[0x01, 0x00]).await?;

        // CONNECT request: VER, CMD, RSV, ATYP, ADDR, PORT.
        let mut connect_header = [0_u8; 4];
        stream.read_exact(&mut connect_header).await?;
        let domain = match connect_header[3] {
            0x03 => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0_u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                String::from_utf8_lossy(&domain).into_owned()
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected ATYP=0x03 (domain name), got 0x{other:02x}"),
                ));
            }
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);

        // Success reply with an unused bound address.
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let http_request = match mode {
            FakeMode::CloseAfterConnect => None,
            FakeMode::RespondHttp => {
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).await?;
                    if read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await?;
                Some(String::from_utf8_lossy(&buf).into_owned())
            }
        };

        Ok(SocksSession {
            username: String::from_utf8_lossy(&username).into_owned(),
            password: String::from_utf8_lossy(&password).into_owned(),
            domain,
            port,
            http_request,
        })
    }

    #[test]
    fn reqwest_proxy_accepts_generated_socks5h_url() {
        let proxy = proxy_at(
            "127.0.0.1:9050".parse().unwrap(),
            "lane-000000-00000001",
            "sample-secret",
        );

        let rule = proxy.reqwest_proxy().expect("valid socks5h proxy rule");
        assert!(::reqwest::Client::builder().proxy(rule).build().is_ok());
    }

    #[tokio::test]
    async fn reqwest_client_authenticates_with_username_and_password() {
        let (addr, session) = spawn_fake_socks(FakeMode::RespondHttp).await;
        let proxy = proxy_at(addr, "lane-000006-00000001", "auth-secret");
        let client = proxy.reqwest_client().expect("client");

        let response = client
            .get("http://auth-check.torlane.test/")
            .send()
            .await
            .expect("request through fake SOCKS server");
        assert_eq!(response.status(), ::reqwest::StatusCode::OK);

        let session = session.await.expect("server task").expect("socks session");
        assert_eq!(session.username, "lane-000006-00000001");
        assert_eq!(session.password, "auth-secret");
    }

    #[tokio::test]
    async fn hostname_is_not_resolved_locally() {
        let (addr, session) = spawn_fake_socks(FakeMode::RespondHttp).await;
        let proxy = proxy_at(addr, "lane-000005-00000001", "dns-secret");
        let client = proxy.reqwest_client().expect("client");

        // `.invalid` is reserved by RFC 2606 and is guaranteed to never
        // resolve through real DNS, so a successful round trip proves the
        // hostname reached the proxy unresolved instead of failing local
        // resolution first.
        let response = client
            .get("http://never-resolves.invalid/")
            .send()
            .await
            .expect("request through fake SOCKS server");
        assert_eq!(response.status(), ::reqwest::StatusCode::OK);

        let session = session.await.expect("server task").expect("socks session");
        assert_eq!(session.domain, "never-resolves.invalid");
    }

    #[tokio::test]
    async fn http_and_https_targets_use_the_socks_proxy() {
        let (http_addr, http_session) = spawn_fake_socks(FakeMode::RespondHttp).await;
        let http_proxy = proxy_at(http_addr, "lane-000004-00000001", "http-secret");
        let response = http_proxy
            .reqwest_client()
            .expect("client")
            .get("http://torlane-test.invalid/")
            .send()
            .await
            .expect("http request through fake SOCKS server");
        assert_eq!(response.status(), ::reqwest::StatusCode::OK);
        let http_session = http_session
            .await
            .expect("server task")
            .expect("socks session");
        assert_eq!(http_session.domain, "torlane-test.invalid");
        assert_eq!(http_session.port, 80);

        // The TLS handshake past the CONNECT tunnel is out of scope here: it
        // is enough to confirm the SOCKS handshake and the CONNECT target,
        // and that a closed tunnel surfaces as an error, not a panic.
        let (https_addr, https_session) = spawn_fake_socks(FakeMode::CloseAfterConnect).await;
        let https_proxy = proxy_at(https_addr, "lane-000004-00000002", "https-secret");
        let result = https_proxy
            .reqwest_client()
            .expect("client")
            .get("https://torlane-test.invalid/")
            .send()
            .await;
        assert!(result.is_err(), "closed tunnel must not panic the client");
        let https_session = https_session
            .await
            .expect("server task")
            .expect("socks session");
        assert_eq!(https_session.domain, "torlane-test.invalid");
        assert_eq!(https_session.port, 443);
    }

    #[tokio::test]
    async fn custom_header_from_builder_reaches_the_proxied_request() {
        let (addr, session) = spawn_fake_socks(FakeMode::RespondHttp).await;
        let proxy = proxy_at(addr, "lane-000002-00000001", "another-secret");

        let mut headers = ::reqwest::header::HeaderMap::new();
        headers.insert(
            "x-torlane-test",
            ::reqwest::header::HeaderValue::from_static("marker-value"),
        );
        let builder = ::reqwest::Client::builder().default_headers(headers);
        let client = proxy
            .configure_reqwest(builder)
            .expect("configured builder")
            .build()
            .expect("client");

        let response = client
            .get("http://header-check.torlane.test/")
            .send()
            .await
            .expect("request through fake SOCKS server");
        assert_eq!(response.status(), ::reqwest::StatusCode::OK);

        let session = session.await.expect("server task").expect("socks session");
        let request = session.http_request.expect("http request recorded");
        assert!(
            request
                .to_lowercase()
                .contains("x-torlane-test: marker-value"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn closed_socks_endpoint_returns_error_without_panicking() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener); // nothing is listening at `addr` anymore

        let proxy = proxy_at(addr, "lane-000003-00000001", "unused-secret");
        let client = proxy.reqwest_client().expect("client");

        let result = client.get("http://unreachable.torlane.test/").send().await;
        assert!(result.is_err());
    }

    // --- Stage 5: pool semantics --------------------------------------
    //
    // These tests exercise `Pool`'s public API against a lane address that
    // has nothing listening on it (`pool_test_addr()`). None of them send
    // network traffic: `reqwest_proxy`/`reqwest_client` only translate the
    // already selected `Proxy` into `reqwest` configuration, so they can be
    // asserted without a working SOCKS server.

    fn pool_test_addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19050))
    }

    async fn wait_for_lane(pool: &Pool, lane: LaneId, predicate: impl Fn(u64, LaneState) -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let snapshot = pool.snapshot();
                if let Some(found) = snapshot.lanes.iter().find(|entry| entry.id == lane) {
                    if predicate(found.epoch, found.state) {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("pool state did not converge");
    }

    #[tokio::test]
    async fn round_robin_selection_builds_a_client_per_lane_with_matching_credentials() {
        let pool = Pool::for_test(PoolConfig::new(3), pool_test_addr()).unwrap();

        let mut rules = Vec::new();
        for _ in 0..3 {
            let proxy = pool.next_proxy().unwrap();
            let rule_debug = format!("{:?}", proxy.reqwest_proxy().expect("proxy rule"));
            assert!(rule_debug.contains(&*proxy.auth().username), "{rule_debug}");
            assert!(rule_debug.contains(&*proxy.auth().password), "{rule_debug}");
            // Building the client itself must succeed too, not just the rule.
            proxy.reqwest_client().expect("client");
            rules.push(rule_debug);
        }
        assert_eq!(
            rules.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "each lane must carry its own credentials: {rules:?}"
        );

        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn sticky_session_reuses_the_same_lane_credentials() {
        let pool = Pool::for_test(PoolConfig::new(4), pool_test_addr()).unwrap();
        let session = "customer-42";

        let first = pool.proxy_for(session).unwrap();
        let second = pool.proxy_for(session).unwrap();
        assert_eq!(first.lane(), second.lane());
        assert_eq!(first.epoch(), second.epoch());

        let first_rule = format!("{:?}", first.reqwest_proxy().unwrap());
        let second_rule = format!("{:?}", second.reqwest_proxy().unwrap());
        assert_eq!(first_rule, second_rule);

        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn retire_rotates_credentials_without_mutating_the_old_proxy() {
        let pool = Pool::for_test(PoolConfig::new(2), pool_test_addr()).unwrap();
        let session = "rotation-semantics";

        let before = pool.proxy_for(session).unwrap();
        let before_rule = format!("{:?}", before.reqwest_proxy().unwrap());
        let lane = before.lane();
        let next_epoch = before.epoch() + 1;

        pool.retire(lane).unwrap();
        wait_for_lane(&pool, lane, |epoch, state| {
            epoch == next_epoch && state == LaneState::Ready
        })
        .await;

        // The already handed out `Proxy` — and everything built from it — must
        // stay bound to the pre-rotation epoch and credentials.
        assert_eq!(before.epoch(), next_epoch - 1);
        assert_eq!(
            format!("{:?}", before.reqwest_proxy().unwrap()),
            before_rule
        );

        // A fresh selection for the same session now carries the new epoch
        // and different credentials.
        let after = pool.proxy_for(session).unwrap();
        assert_eq!(after.lane(), lane);
        assert_eq!(after.epoch(), next_epoch);
        assert_ne!(format!("{:?}", after.reqwest_proxy().unwrap()), before_rule);

        pool.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn building_a_client_does_not_add_another_assignment() {
        let pool = Pool::for_test(PoolConfig::new(1), pool_test_addr()).unwrap();
        let proxy = pool.next_proxy().unwrap();

        wait_for_lane(&pool, proxy.lane(), |_epoch, _state| {
            pool.snapshot()
                .lanes
                .iter()
                .any(|entry| entry.id == proxy.lane() && entry.assignments == 1)
        })
        .await;

        // None of these read the pool; they only translate the `Proxy`
        // already in hand, so the assignment count must not move.
        let _rule = proxy.reqwest_proxy().unwrap();
        let _client = proxy.reqwest_client().unwrap();
        let _configured = proxy
            .configure_reqwest(::reqwest::Client::builder())
            .unwrap()
            .build()
            .unwrap();

        // Give any incorrect background bookkeeping a chance to run before
        // asserting the count is still exactly the one pool selection above.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = pool.snapshot();
        let lane = snapshot
            .lanes
            .iter()
            .find(|entry| entry.id == proxy.lane())
            .unwrap();
        assert_eq!(lane.assignments, 1);

        pool.shutdown().await.unwrap();
    }
}
