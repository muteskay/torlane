#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use torlane::{InstanceConfig, InstanceId, Pool, TorControlError, TorInstance, TorInstanceError};

#[tokio::test]
async fn pool_builder_starts_instance_and_creates_requested_lanes() {
    if !python_available() {
        return;
    }

    let root = temp_root("pool");
    fs::create_dir_all(&root).unwrap();
    let pid_file = root.join("fake-tor.pid");
    let captured_config = root.join("captured.torrc");
    let tor_binary = fake_tor(&root, &pid_file, &captured_config, "success");

    let pool = Pool::builder()
        .tor_binary(&tor_binary)
        .work_dir(root.join("instance"))
        .lanes(4)
        .bootstrap_timeout(Duration::from_secs(2))
        .build()
        .await
        .unwrap();

    let snapshot = pool.snapshot();
    assert_eq!(snapshot.lanes.len(), 4);
    assert_eq!(snapshot.ready_lane_count, 4);
    assert_eq!(snapshot.instance.generation, 1);
    assert_eq!(snapshot.instance.restart_count, 0);
    assert_eq!(
        (0..6)
            .map(|_| pool.next_proxy().unwrap().lane())
            .collect::<Vec<_>>(),
        vec![
            torlane::LaneId(0),
            torlane::LaneId(1),
            torlane::LaneId(2),
            torlane::LaneId(3),
            torlane::LaneId(0),
            torlane::LaneId(1),
        ]
    );

    pool.restart().await.unwrap();
    let restarted = pool.snapshot();
    assert_eq!(restarted.instance.generation, 2);
    assert_eq!(restarted.instance.restart_count, 1);
    assert!(restarted.lanes.iter().all(|lane| lane.epoch == 2));
    assert_eq!(restarted.ready_lane_count, 4);

    let pid = read_pid(&pid_file).await;
    pool.shutdown().await.unwrap();
    wait_for_process_exit(pid).await;
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn instance_starts_with_auto_ports_and_exposes_working_socks_endpoint() {
    if !python_available() {
        return;
    }

    let root = temp_root("start");
    fs::create_dir_all(&root).unwrap();
    let pid_file = root.join("fake-tor.pid");
    let captured_config = root.join("captured.torrc");
    let tor_binary = fake_tor(&root, &pid_file, &captured_config, "success");
    let config = InstanceConfig::new(InstanceId(7), &tor_binary, root.join("instance"))
        .control_port_timeout(Duration::from_secs(2))
        .bootstrap_timeout(Duration::from_secs(2));

    let mut instance = TorInstance::start(config).await.unwrap();

    assert_eq!(instance.id, InstanceId(7));
    assert_eq!(instance.layout.root, root.join("instance"));
    assert_ne!(instance.socks_addr().port(), 0);
    assert!(instance.process_id().is_some());
    assert!(
        instance
            .controller()
            .command("GETINFO status/bootstrap-phase")
            .await
            .unwrap()
            .is_success()
    );

    let rendered = fs::read_to_string(&captured_config).unwrap();
    assert!(rendered.contains("SocksPort 127.0.0.1:auto "));
    assert!(rendered.contains("ControlPort 127.0.0.1:auto\n"));
    assert!(!rendered.contains("SocksPort 127.0.0.1:9050"));
    assert!(!rendered.contains("ControlPort 127.0.0.1:9051"));

    let mut stream = TcpStream::connect(instance.socks_addr()).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);

    let host = b"example.test";
    let mut connect = vec![5, 1, 0, 3, host.len() as u8];
    connect.extend_from_slice(host);
    connect.extend_from_slice(&80_u16.to_be_bytes());
    stream.write_all(&connect).await.unwrap();
    let mut connected = [0_u8; 10];
    stream.read_exact(&mut connected).await.unwrap();
    assert_eq!(&connected[..2], &[5, 0]);

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"));

    let pid = read_pid(&pid_file).await;
    instance.shutdown().await.unwrap();
    wait_for_process_exit(pid).await;
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn startup_error_does_not_leave_orphan_process() {
    if !python_available() {
        return;
    }

    let root = temp_root("startup-error");
    fs::create_dir_all(&root).unwrap();
    let pid_file = root.join("fake-tor.pid");
    let captured_config = root.join("captured.torrc");
    let tor_binary = fake_tor(&root, &pid_file, &captured_config, "bad-port");
    let config = InstanceConfig::new(InstanceId(8), &tor_binary, root.join("instance"))
        .control_port_timeout(Duration::from_secs(1))
        .bootstrap_timeout(Duration::from_secs(1));

    let error = match TorInstance::start(config).await {
        Ok(_) => panic!("startup unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        TorInstanceError::Control(TorControlError::InvalidControlEndpoint { .. })
    ));

    let pid = read_pid(&pid_file).await;
    wait_for_process_exit(pid).await;
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn dropping_instance_closes_ownership_and_terminates_process() {
    if !python_available() {
        return;
    }

    let root = temp_root("ownership");
    fs::create_dir_all(&root).unwrap();
    let pid_file = root.join("fake-tor.pid");
    let captured_config = root.join("captured.torrc");
    let tor_binary = fake_tor(&root, &pid_file, &captured_config, "success");
    let config = InstanceConfig::new(InstanceId(9), &tor_binary, root.join("instance"))
        .control_port_timeout(Duration::from_secs(2))
        .bootstrap_timeout(Duration::from_secs(2));

    let instance = TorInstance::start(config).await.unwrap();
    let pid = read_pid(&pid_file).await;
    drop(instance);

    wait_for_process_exit(pid).await;
    fs::remove_dir_all(root).unwrap();
}

fn fake_tor(root: &Path, pid_file: &Path, captured_config: &Path, mode: &str) -> PathBuf {
    let script = root.join("fake-tor");
    let source = FAKE_TOR
        .replace("__PID_FILE__", &pid_file.display().to_string())
        .replace(
            "__CAPTURED_CONFIG__",
            &captured_config.display().to_string(),
        )
        .replace("__MODE__", mode);
    fs::write(&script, source).unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    fs::File::open(&script).unwrap().sync_all().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    script
}

fn python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

async fn read_pid(path: &Path) -> u32 {
    timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(value) = tokio::fs::read_to_string(path).await
                && let Ok(pid) = value.trim().parse()
            {
                return pid;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

async fn wait_for_process_exit(pid: u32) {
    timeout(Duration::from_secs(5), async {
        while Path::new(&format!("/proc/{pid}")).exists() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process {pid} was not reaped"));
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "torlane-instance-{label}-{}-{nanos}",
        std::process::id()
    ))
}

const FAKE_TOR: &str = r#"#!/usr/bin/env python3
import os
import socket
import sys
import threading
import time

PID_FILE = '__PID_FILE__'
CAPTURED_CONFIG = '__CAPTURED_CONFIG__'
MODE = '__MODE__'

args = sys.argv[1:]
if '--version' in args:
    print('Tor version 0.4.9.11.')
    sys.exit(0)

def read_config():
    source = args[args.index('-f') + 1]
    if source == '-':
        return sys.stdin.read()
    with open(source, 'r', encoding='utf-8') as handle:
        return handle.read()

if '--verify-config' in args:
    read_config()
    print('Configuration was valid')
    sys.exit(0)

config = read_config()
with open(CAPTURED_CONFIG, 'w', encoding='utf-8') as handle:
    handle.write(config)
with open(PID_FILE, 'w', encoding='ascii') as handle:
    handle.write(str(os.getpid()))

def option(name):
    prefix = name + ' '
    for line in config.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise RuntimeError('missing option ' + name)

control_file = option('ControlPortWriteToFile')
os.makedirs(os.path.dirname(control_file), exist_ok=True)

if MODE == 'bad-port':
    with open(control_file, 'w', encoding='ascii') as handle:
        handle.write('PORT=not-an-endpoint\n')
    while True:
        time.sleep(1)

control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
control.bind(('127.0.0.1', 0))
control.listen(1)
socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
socks.bind(('127.0.0.1', 0))
socks.listen(8)

with open(control_file, 'w', encoding='ascii') as handle:
    handle.write('PORT=127.0.0.1:' + str(control.getsockname()[1]) + '\n')

def exact(conn, length):
    value = b''
    while len(value) < length:
        part = conn.recv(length - len(value))
        if not part:
            raise EOFError()
        value += part
    return value

def serve_socks(conn):
    try:
        version, methods = exact(conn, 2)
        exact(conn, methods)
        conn.sendall(b'\x05\x00')
        version, command, reserved, address_type = exact(conn, 4)
        if address_type == 1:
            exact(conn, 4)
        elif address_type == 3:
            exact(conn, exact(conn, 1)[0])
        elif address_type == 4:
            exact(conn, 16)
        exact(conn, 2)
        conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
        request = conn.recv(65536)
        if request:
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
    finally:
        conn.close()

def socks_loop():
    while True:
        conn, _ = socks.accept()
        threading.Thread(target=serve_socks, args=(conn,), daemon=True).start()

threading.Thread(target=socks_loop, daemon=True).start()
conn, _ = control.accept()
buffer = b''
while True:
    part = conn.recv(4096)
    if not part:
        break
    buffer += part
    while b'\n' in buffer:
        raw, buffer = buffer.split(b'\n', 1)
        command = raw.rstrip(b'\r').decode('ascii')
        if command == 'PROTOCOLINFO 1':
            reply = ('250-PROTOCOLINFO 1\r\n'
                     '250-AUTH METHODS=NULL\r\n'
                     '250-VERSION Tor="0.4.9.11"\r\n'
                     '250 OK\r\n')
        elif command in ('AUTHENTICATE', 'TAKEOWNERSHIP',
                         'RESETCONF __OwningControllerProcess'):
            reply = '250 OK\r\n'
        elif command == 'GETINFO status/bootstrap-phase':
            reply = ('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n'
                     '250 OK\r\n')
        elif command == 'GETINFO net/listeners/socks':
            reply = ('250-net/listeners/socks="127.0.0.1:' + str(socks.getsockname()[1]) + '"\r\n'
                     '250 OK\r\n')
        else:
            reply = '510 Unrecognized command\r\n'
        conn.sendall(reply.encode('ascii'))

conn.close()
control.close()
socks.close()
"#;
