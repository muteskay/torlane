use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use torlane::{
    AuthMethod, ControlClient, ControlLine, TorControlError, TorEvent, wait_control_port_file,
};

const SERVER_HASH_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_HASH_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

#[tokio::test]
async fn routes_events_separately_from_command_replies() {
    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(read_command(&mut reader).await, "GETINFO example");
        writer
            .write_all(
                b"650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=80 TAG=conn SUMMARY=\"Connecting\"\r\n\
                  250-example=value\r\n\
                  250 OK\r\n",
            )
            .await
            .unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    let mut events = client.subscribe();
    let reply = client.command("GETINFO example").await.unwrap();
    assert_eq!(reply.code, 250);
    assert!(reply.lines.contains(&ControlLine::KeyValue {
        key: "example".to_string(),
        value: "value".to_string(),
    }));
    assert!(matches!(
        events.recv().await.unwrap(),
        TorEvent::Bootstrap(event) if event.progress == 80
            && event.tag.as_deref() == Some("conn")
            && event.summary.as_deref() == Some("Connecting")
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn protocol_info_safecookie_and_ownership_handshake_succeed() {
    let root = temp_root("safecookie");
    fs::create_dir_all(&root).unwrap();
    let cookie_path = root.join("control_auth_cookie");
    let cookie = [0x11_u8; 32];
    fs::write(&cookie_path, cookie).unwrap();
    let server_cookie_path = cookie_path.clone();

    let (endpoint, server) = mock_server(move |stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        assert_eq!(read_command(&mut reader).await, "PROTOCOLINFO 1");
        writer
            .write_all(
                format!(
                    "250-PROTOCOLINFO 1\r\n\
                     250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"{}\"\r\n\
                     250-VERSION Tor=\"0.4.8.10\"\r\n\
                     250 OK\r\n",
                    server_cookie_path.display()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let challenge = read_command(&mut reader).await;
        let nonce_hex = challenge.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap();
        let client_nonce = decode_hex(nonce_hex);
        let server_nonce = [0x33_u8; 32];
        let server_hash = hmac(SERVER_HASH_KEY, &cookie, &client_nonce, &server_nonce);
        writer
            .write_all(
                format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    encode_hex(&server_hash),
                    encode_hex(&server_nonce)
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let authenticate = read_command(&mut reader).await;
        let expected_client_hash = hmac(CLIENT_HASH_KEY, &cookie, &client_nonce, &server_nonce);
        assert_eq!(
            authenticate,
            format!("AUTHENTICATE {}", encode_hex(&expected_client_hash))
        );
        writer.write_all(b"250 OK\r\n").await.unwrap();

        assert_eq!(read_command(&mut reader).await, "TAKEOWNERSHIP");
        writer.write_all(b"250 OK\r\n").await.unwrap();
        assert_eq!(
            read_command(&mut reader).await,
            "RESETCONF __OwningControllerProcess"
        );
        writer.write_all(b"250 OK\r\n").await.unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    let protocol = client.authenticate_and_take_ownership().await.unwrap();
    assert_eq!(
        protocol.auth_methods,
        vec![AuthMethod::Cookie, AuthMethod::SafeCookie]
    );
    assert_eq!(protocol.cookie_file.as_deref(), Some(cookie_path.as_path()));
    assert_eq!(protocol.tor_version.as_deref(), Some("0.4.8.10"));

    server.await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn safecookie_rejects_invalid_server_hash() {
    let root = temp_root("bad-hash");
    fs::create_dir_all(&root).unwrap();
    let cookie_path = root.join("cookie");
    fs::write(&cookie_path, [0x11_u8; 32]).unwrap();

    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert!(
            read_command(&mut reader)
                .await
                .starts_with("AUTHCHALLENGE SAFECOOKIE ")
        );
        writer
            .write_all(
                format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    "00".repeat(32),
                    "33".repeat(32)
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    assert!(matches!(
        client.authenticate_safecookie(&cookie_path).await,
        Err(TorControlError::InvalidServerHash)
    ));
    server.await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn waits_for_bootstrap_event_with_getinfo_fallback() {
    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(
            read_command(&mut reader).await,
            "SETEVENTS STATUS_CLIENT"
        );
        writer.write_all(b"250 OK\r\n").await.unwrap();
        assert_eq!(
            read_command(&mut reader).await,
            "GETINFO status/bootstrap-phase"
        );
        writer
            .write_all(
                b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=55 TAG=loading SUMMARY=\"Loading\"\r\n\
                  250 OK\r\n\
                  650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n",
            )
            .await
            .unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    client.enable_bootstrap_events().await.unwrap();
    client.wait_bootstrap(Duration::from_secs(1)).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn bootstrap_wait_times_out() {
    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(
            read_command(&mut reader).await,
            "GETINFO status/bootstrap-phase"
        );
        writer
            .write_all(
                b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=10 TAG=conn\r\n250 OK\r\n",
            )
            .await
            .unwrap();
        sleep(Duration::from_millis(200)).await;
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    assert!(matches!(
        client.wait_bootstrap(Duration::from_millis(50)).await,
        Err(TorControlError::BootstrapTimeout)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn discovers_exactly_one_tcp_socks_listener() {
    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(
            read_command(&mut reader).await,
            "GETINFO net/listeners/socks"
        );
        writer
            .write_all(b"250-net/listeners/socks=\"127.0.0.1:19050\"\r\n250 OK\r\n")
            .await
            .unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    assert_eq!(
        client.socks_listener().await.unwrap(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19050))
    );
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_multiple_tcp_socks_listeners() {
    let (endpoint, server) = mock_server(|stream| async move {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        assert_eq!(
            read_command(&mut reader).await,
            "GETINFO net/listeners/socks"
        );
        writer
            .write_all(
                b"250-net/listeners/socks=\"127.0.0.1:19050\" \"127.0.0.1:19051\"\r\n250 OK\r\n",
            )
            .await
            .unwrap();
    })
    .await;

    let client = ControlClient::connect(endpoint).await.unwrap();
    assert!(matches!(
        client.socks_listener().await,
        Err(TorControlError::SocksListenerCount { count: 2 })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn waits_for_auto_control_port_file() {
    let root = temp_root("control-port");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("runtime/control.port");
    let writer_path = path.clone();
    let writer = tokio::spawn(async move {
        sleep(Duration::from_millis(30)).await;
        tokio::fs::create_dir_all(writer_path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&writer_path, b"PORT=127.0.0.1:29051\n")
            .await
            .unwrap();
    });

    assert_eq!(
        wait_control_port_file(&path, Duration::from_secs(1))
            .await
            .unwrap(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 29051))
    );
    writer.await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

async fn mock_server<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler(stream).await;
    });
    (endpoint, task)
}

async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut command = String::new();
    reader.read_line(&mut command).await.unwrap();
    command.trim_end_matches(['\r', '\n']).to_string()
}

fn hmac(key: &[u8], cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().to_vec()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "torlane-controller-{label}-{}-{nanos}",
        std::process::id()
    ))
}
