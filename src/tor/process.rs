use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tor::error::TorProcessError;
use crate::tor::torc::config::TorConfig;
use crate::tor::torc::error::TorWriteError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorConfigSource {
    Stdin,
    File(PathBuf),
}

impl Default for TorConfigSource {
    fn default() -> Self {
        Self::Stdin
    }
}

impl TorConfigSource {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }
}

#[derive(Debug)]
pub struct TorProcess {
    child: Child,
}

impl TorProcess {
    pub async fn spawn(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
    ) -> Result<Self, TorProcessError> {
        Self::spawn_with_source(tor_binary, config, &TorConfigSource::default()).await
    }

    pub async fn spawn_with_source(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
        source: &TorConfigSource,
    ) -> Result<Self, TorProcessError> {
        remove_stale_control_port_file(config)?;

        let mut command = Command::new(tor_binary.as_ref());
        command.arg("-f");

        match source {
            TorConfigSource::Stdin => {
                command.arg("-").stdin(Stdio::piped());
            }
            TorConfigSource::File(path) => {
                write_config_to_file(config, path)?;
                command.arg(path).stdin(Stdio::null());
            }
        }

        let mut child = command.spawn()?;

        if matches!(source, TorConfigSource::File(_)) {
            return Ok(Self { child });
        }

        let Some(stdin) = &mut child.stdin else {
            return Err(TorProcessError::MissingStdin);
        };

        if let Err(error) = write_config_to_stdin(config, stdin) {
            let _ = child.kill();
            return Err(TorProcessError::Io(error));
        }

        drop(child.stdin.take());
        Ok(Self { child })
    }

    pub fn id(&self) -> Option<u32> {
        Some(self.child.id())
    }

    pub fn shutdown(&mut self) -> Result<(), TorProcessError> {
        self.child.kill()?;
        Ok(())
    }

    pub fn kill(&mut self) -> Result<(), TorProcessError> {
        self.child.kill()?;
        Ok(())
    }

    pub fn wait(&mut self) -> Result<std::process::ExitStatus, TorProcessError> {
        Ok(self.child.wait()?)
    }
}

fn remove_stale_control_port_file(config: &TorConfig) -> Result<(), TorProcessError> {
    let Some(path) = config
        .control()
        .and_then(|control| control.write_port_to_file.as_ref())
    else {
        return Ok(());
    };

    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TorProcessError::Io(error)),
    }
}

pub fn write_config_to_file(
    config: &TorConfig,
    path: impl AsRef<Path>,
) -> Result<(), TorWriteError> {
    atomic_write(path.as_ref(), &config.render())
}

fn write_config_to_stdin(config: &TorConfig, child_stdin: &mut ChildStdin) -> io::Result<()> {
    child_stdin.write_all(config.render().as_bytes())?;
    child_stdin.flush()
}

fn atomic_write(path: &Path, content: &str) -> Result<(), TorWriteError> {
    if path.as_os_str().is_empty() {
        return Err(TorWriteError::MissingParentDirectory);
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let temp_path = temp_path(parent, path);
    let mut file = create_private_file(&temp_path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    fs::rename(&temp_path, path)?;
    Ok(())
}

fn temp_path(parent: &Path, destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("torrc");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    parent.join(format!(".{name}.{pid}.{nanos}.tmp"))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}
