use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::tor::error::{TorRuntimeValidationError, TorVerifyError};
use crate::tor::process::{TorConfigSource, write_config_to_file};
use crate::tor::torc::config::TorConfig;
use crate::tor::torc::logging::LogDest;

/// The captured output of a successful `tor --verify-config` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorVerifyReport {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// The paths checked by [`validate_runtime_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorRuntimeValidation {
    /// The Tor binary path that was checked.
    pub tor_binary: PathBuf,
    /// The data directory path that was checked.
    pub data_directory: PathBuf,
    /// Every path that was checked, including transport plugin executables
    /// and log file parent directories.
    pub checked_paths: Vec<PathBuf>,
}

/// Renders `config` with the default (stdin) delivery mode and runs `tor
/// --verify-config` against it.
pub fn verify_config_with(
    config: &TorConfig,
    tor_binary: &Path,
) -> Result<TorVerifyReport, TorVerifyError> {
    verify_config_source_with(config, &TorConfigSource::default(), tor_binary)
}

/// Renders `config` with the given delivery `source` and runs `tor
/// --verify-config` against it.
pub fn verify_config_source_with(
    config: &TorConfig,
    source: &TorConfigSource,
    tor_binary: &Path,
) -> Result<TorVerifyReport, TorVerifyError> {
    match source {
        TorConfigSource::Stdin => verify_rendered_config_with_stdin(config, tor_binary),
        TorConfigSource::File(path) => {
            write_config_to_file(config, path)?;
            verify_torrc_file_with(path, tor_binary)
        }
    }
}

/// Runs `tor --verify-config -f torrc_file` against an already written
/// `torrc` file.
pub fn verify_torrc_file_with(
    torrc_file: &Path,
    tor_binary: &Path,
) -> Result<TorVerifyReport, TorVerifyError> {
    let output = Command::new(tor_binary)
        .arg("--verify-config")
        .arg("-f")
        .arg(torrc_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    report_from_output(output)
}

fn verify_rendered_config_with_stdin(
    config: &TorConfig,
    tor_binary: &Path,
) -> Result<TorVerifyReport, TorVerifyError> {
    let mut child = Command::new(tor_binary)
        .arg("--verify-config")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let Some(mut stdin) = child.stdin.take() else {
        return Err(TorVerifyError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "tor stdin was not available",
        )));
    };
    let write_result = stdin
        .write_all(config.render().as_bytes())
        .and_then(|()| stdin.flush());
    drop(stdin);

    let output = child.wait_with_output()?;

    if let Err(error) = write_result {
        if output.status.success() {
            return Err(TorVerifyError::Io(error));
        }
    }

    report_from_output(output)
}

fn report_from_output(output: std::process::Output) -> Result<TorVerifyReport, TorVerifyError> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Err(TorVerifyError::Failed {
            status: output.status.code(),
            stdout,
            stderr,
        });
    }

    Ok(TorVerifyReport { stdout, stderr })
}

/// Checks that `tor_binary` and the paths `config` depends on (data
/// directory, transport plugin executables, log file directories) exist and
/// are usable, without running `tor` itself.
pub fn validate_runtime_config(
    config: &TorConfig,
    tor_binary: &Path,
) -> Result<TorRuntimeValidation, TorRuntimeValidationError> {
    ensure_exists(tor_binary)?;
    ensure_executable(tor_binary)?;

    fs::create_dir_all(config.data_directory())?;
    let probe = config.data_directory().join(".torlane-write-probe");
    fs::write(&probe, b"ok")?;
    fs::remove_file(&probe)?;

    let mut checked_paths = vec![
        tor_binary.to_path_buf(),
        config.data_directory().to_path_buf(),
    ];

    if let Some(bridges) = &config.bridges {
        for plugin in &bridges.transport_plugins {
            ensure_exists(&plugin.executable)?;
            ensure_executable(&plugin.executable)?;
            checked_paths.push(plugin.executable.clone());
        }
    }

    for log in &config.logging.logs {
        if let LogDest::File(path) = &log.destination {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                checked_paths.push(parent.to_path_buf());
            }
        }
    }

    Ok(TorRuntimeValidation {
        tor_binary: tor_binary.to_path_buf(),
        data_directory: config.data_directory().to_path_buf(),
        checked_paths,
    })
}

fn ensure_exists(path: &Path) -> Result<(), TorRuntimeValidationError> {
    if !path.exists() {
        return Err(TorRuntimeValidationError::MissingPath(
            path.display().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<(), TorRuntimeValidationError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(TorRuntimeValidationError::NotExecutable(
            path.display().to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> Result<(), TorRuntimeValidationError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::tor::process::TorConfigSource;
    use crate::tor::torc::{SocksConfig, TorConfigBuilder, TorOption};

    use super::{verify_config_source_with, verify_config_with};

    #[cfg(unix)]
    #[test]
    fn verify_config_with_passes_rendered_config_through_stdin() {
        let root = temp_root("stdin");
        let capture = root.join("captured.torrc");
        let tor = fake_tor(&root, &capture);
        let config = TorConfigBuilder::new(root.join("data"))
            .socks(SocksConfig::isolated_auth_auto())
            .build()
            .unwrap();

        let report = verify_config_with(&config, &tor).unwrap();

        assert_eq!(report.stdout, "ok\n");
        assert_eq!(fs::read_to_string(capture).unwrap(), config.render());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn verify_config_with_returns_failed_for_invalid_config() {
        let root = temp_root("invalid");
        let capture = root.join("captured.torrc");
        let tor = fake_tor(&root, &capture);
        let config = TorConfigBuilder::new(root.join("data"))
            .socks(SocksConfig::isolated_auth_auto())
            .raw_option(TorOption::new("InvalidTorLaneOption", "1").unwrap())
            .build()
            .unwrap();

        let error = verify_config_with(&config, &tor).unwrap_err();

        match error {
            crate::tor::error::TorVerifyError::Failed {
                status,
                stdout,
                stderr,
            } => {
                assert_eq!(status, Some(2));
                assert!(stdout.is_empty());
                assert_eq!(stderr, "invalid config\n");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn verify_config_source_with_verifies_valid_file_mode() {
        let root = temp_root("file-valid");
        let capture = root.join("captured.torrc");
        let torrc = root.join("runtime").join("torrc");
        let tor = fake_tor(&root, &capture);
        let config = TorConfigBuilder::new(root.join("data"))
            .socks(SocksConfig::isolated_auth_auto())
            .build()
            .unwrap();

        let report =
            verify_config_source_with(&config, &TorConfigSource::File(torrc.clone()), &tor)
                .unwrap();

        assert_eq!(report.stdout, "ok\n");
        assert_eq!(fs::read_to_string(&torrc).unwrap(), config.render());
        assert_eq!(fs::read_to_string(capture).unwrap(), config.render());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn verify_config_source_with_returns_failed_for_invalid_file_mode() {
        let root = temp_root("file-invalid");
        let capture = root.join("captured.torrc");
        let torrc = root.join("runtime").join("torrc");
        let tor = fake_tor(&root, &capture);
        let config = TorConfigBuilder::new(root.join("data"))
            .socks(SocksConfig::isolated_auth_auto())
            .raw_option(TorOption::new("InvalidTorLaneOption", "1").unwrap())
            .build()
            .unwrap();

        let error = verify_config_source_with(&config, &TorConfigSource::File(torrc.clone()), &tor)
            .unwrap_err();

        assert_eq!(fs::read_to_string(&torrc).unwrap(), config.render());
        match error {
            crate::tor::error::TorVerifyError::Failed {
                status,
                stdout,
                stderr,
            } => {
                assert_eq!(status, Some(2));
                assert!(stdout.is_empty());
                assert_eq!(stderr, "invalid config\n");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn fake_tor(root: &std::path::Path, capture: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(root).unwrap();
        let script = root.join("tor");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
	if [ \"$1\" != \"--verify-config\" ] || [ \"$2\" != \"-f\" ]; then\n\
  	  echo \"unexpected args: $@\" >&2\n\
  	  exit 9\n\
  	fi\n\
	if [ \"$3\" = \"-\" ]; then\n\
	  cat > '{}'\n\
	else\n\
	  cp \"$3\" '{}'\n\
	fi\n\
  	if grep -q InvalidTorLaneOption '{}'; then\n\
  	  echo \"invalid config\" >&2\n\
  	  exit 2\n\
  	fi\n\
  	echo \"ok\"\n",
                capture.display(),
                capture.display(),
                capture.display()
            ),
        )
        .unwrap();

        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script, permissions).unwrap();
        fs::File::open(&script).unwrap().sync_all().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        script
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "torlane-verify-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ))
    }
}
