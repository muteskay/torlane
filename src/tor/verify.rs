use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::tor::config::TorConfig;
use crate::tor::error::{TorRuntimeValidationError, TorVerifyError};
use crate::tor::logging::LogDest;
use crate::tor::render::atomic_write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorVerifyReport {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorRuntimeValidation {
    pub tor_binary: PathBuf,
    pub data_directory: PathBuf,
    pub checked_paths: Vec<PathBuf>,
}

pub(crate) fn verify_config_with(
    config: &TorConfig,
    tor_binary: &Path,
) -> Result<TorVerifyReport, TorVerifyError> {
    let temp = std::env::temp_dir().join(format!(
        "torlane-verify-{}-{}.torrc",
        std::process::id(),
        monotonic_nanos()
    ));
    atomic_write(&temp, &config.render())?;

    let output = Command::new(tor_binary)
        .arg("-f")
        .arg(&temp)
        .arg("--verify-config")
        .output();

    let remove_result = fs::remove_file(&temp);
    if let Err(error) = remove_result {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(TorVerifyError::Io(error));
        }
    }

    let output = output?;
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

pub(crate) fn validate_runtime_config(
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

fn monotonic_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}
