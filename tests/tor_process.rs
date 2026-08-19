#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{sleep, timeout};
use torlane::low_level::{SocksConfig, TorConfig, TorConfigBuilder, TorConfigSource, TorProcess};

#[tokio::test]
async fn stdin_mode_delivers_config_and_drains_both_output_streams() {
    let root = temp_root("stdin");
    fs::create_dir_all(&root).unwrap();
    let received = root.join("received.torrc");
    let arguments = root.join("arguments");
    let drained = root.join("drained");
    let script = root.join("fake-tor");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{}'\n\
             cat > '{}'\n\
             i=0\n\
             while [ \"$i\" -lt 5000 ]; do\n\
               printf 'a sufficiently long stdout line to fill the operating system pipe %s\\n' \"$i\"\n\
               printf 'a sufficiently long stderr line to fill the operating system pipe %s\\n' \"$i\" >&2\n\
               i=$((i + 1))\n\
             done\n\
             touch '{}'\n\
             while :; do sleep 1; done\n",
            arguments.display(),
            received.display(),
            drained.display(),
        ),
    );

    let config = test_config(&root);
    let mut process = TorProcess::spawn(&script, &config, &TorConfigSource::Stdin)
        .await
        .unwrap();

    wait_for_file(&drained).await;
    assert_eq!(fs::read_to_string(&received).unwrap(), config.render());
    assert_eq!(fs::read_to_string(&arguments).unwrap(), "-f\n-\n");

    process.shutdown().await.unwrap();
    assert!(process.try_wait().unwrap().is_some());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn file_mode_writes_torrc_before_launch_and_uses_null_stdin() {
    let root = temp_root("file");
    fs::create_dir_all(&root).unwrap();
    let torrc = root.join("nested/torrc");
    let received = root.join("received.torrc");
    let arguments = root.join("arguments");
    let script = root.join("fake-tor");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{}'\n\
             cp \"$2\" '{}'\n\
             while :; do sleep 1; done\n",
            arguments.display(),
            received.display(),
        ),
    );

    let config = test_config(&root);
    let mut process = TorProcess::spawn(&script, &config, &TorConfigSource::file(&torrc))
        .await
        .unwrap();

    wait_for_file(&received).await;
    assert_eq!(fs::read_to_string(&torrc).unwrap(), config.render());
    assert_eq!(fs::read_to_string(&received).unwrap(), config.render());
    assert_eq!(
        fs::read_to_string(&arguments).unwrap(),
        format!("-f\n{}\n", torrc.display())
    );

    process.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn default_spawn_uses_stdin_and_does_not_create_torrc() {
    let root = temp_root("default");
    fs::create_dir_all(&root).unwrap();
    let received = root.join("received.torrc");
    let script = root.join("fake-tor");
    write_executable(
        &script,
        &format!("#!/bin/sh\ncat > '{}'\n", received.display()),
    );

    let config = test_config(&root);
    let mut process = TorProcess::spawn_default(&script, &config).await.unwrap();
    assert!(process.wait().await.unwrap().success());

    assert_eq!(fs::read_to_string(received).unwrap(), config.render());
    assert!(!root.join("torrc").exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn child_config_failure_is_observable_through_wait() {
    let root = temp_root("invalid");
    fs::create_dir_all(&root).unwrap();
    let script = root.join("fake-tor");
    write_executable(&script, "#!/bin/sh\ncat >/dev/null\nexit 42\n");

    let config = test_config(&root);
    let mut process = TorProcess::spawn(&script, &config, &TorConfigSource::Stdin)
        .await
        .unwrap();
    let status = process.wait().await.unwrap();

    assert_eq!(status.code(), Some(42));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dropping_process_terminates_child() {
    let root = temp_root("drop");
    fs::create_dir_all(&root).unwrap();
    let ready = root.join("ready");
    let survived = root.join("survived");
    let script = root.join("fake-tor");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\ncat >/dev/null\ntouch '{}'\nsleep 1\ntouch '{}'\nwhile :; do sleep 1; done\n",
            ready.display(),
            survived.display(),
        ),
    );

    let config = test_config(&root);
    let process = TorProcess::spawn(&script, &config, &TorConfigSource::Stdin)
        .await
        .unwrap();
    assert!(process.id().is_some());
    wait_for_file(&ready).await;
    drop(process);

    sleep(Duration::from_millis(1_500)).await;
    assert!(!survived.exists(), "dropped child continued running");

    fs::remove_dir_all(root).unwrap();
}

fn test_config(root: &Path) -> TorConfig {
    TorConfigBuilder::new(root.join("data"))
        .socks(SocksConfig::isolated_auth_auto())
        .build()
        .unwrap()
}

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
    fs::File::open(path).unwrap().sync_all().unwrap();

    // Some overlay filesystems briefly report ETXTBSY for a file executed in
    // the same instant that its metadata is persisted.
    std::thread::sleep(Duration::from_millis(20));
}

async fn wait_for_file(path: &Path) {
    timeout(Duration::from_secs(10), async {
        while !path.exists() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {}", path.display()));
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "torlane-process-{label}-{}-{nanos}",
        std::process::id()
    ))
}
