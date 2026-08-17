use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

use crate::tor::error::TorProcessError;
use crate::tor::torc::config::TorConfig;
use crate::tor::torc::error::TorWriteError;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TorConfigSource {
    #[default]
    Stdin,
    File(PathBuf),
}

impl TorConfigSource {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }
}

#[derive(Debug)]
pub struct TorProcess {
    child: Child,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
}

impl TorProcess {
    pub async fn spawn(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
        source: &TorConfigSource,
    ) -> Result<Self, TorProcessError> {
        remove_stale_control_port_file(config)?;

        let mut command = Command::new(tor_binary.as_ref());
        command
            .arg("-f")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

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
        let stdout_task = child
            .stdout
            .take()
            .map(|stdout| tokio::spawn(drain_output(stdout, OutputStream::Stdout)));
        let stderr_task = child
            .stderr
            .take()
            .map(|stderr| tokio::spawn(drain_output(stderr, OutputStream::Stderr)));

        let mut process = Self {
            child,
            stdout_task,
            stderr_task,
        };

        if matches!(source, TorConfigSource::Stdin) {
            if let Err(error) = process.write_config_to_stdin(config).await {
                let _ = process.child.start_kill();
                let _ = process.child.wait().await;
                process.finish_output_tasks().await;
                return Err(error);
            }
        }

        Ok(process)
    }

    /// Convenience wrapper for the default in-memory configuration delivery.
    pub async fn spawn_default(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
    ) -> Result<Self, TorProcessError> {
        Self::spawn(tor_binary, config, &TorConfigSource::default()).await
    }

    /// Backwards-compatible explicit-source alias.
    pub async fn spawn_with_source(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
        source: &TorConfigSource,
    ) -> Result<Self, TorProcessError> {
        Self::spawn(tor_binary, config, source).await
    }

    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, TorProcessError> {
        Ok(self.child.try_wait()?)
    }

    pub async fn wait(&mut self) -> Result<ExitStatus, TorProcessError> {
        let status = self.child.wait().await?;
        self.finish_output_tasks().await;
        Ok(status)
    }

    pub fn start_kill(&mut self) -> Result<(), TorProcessError> {
        self.child.start_kill()?;
        Ok(())
    }

    /// Compatibility alias for callers that previously used `kill()`.
    pub fn kill(&mut self) -> Result<(), TorProcessError> {
        self.start_kill()
    }

    pub async fn shutdown(&mut self) -> Result<(), TorProcessError> {
        if self.child.try_wait()?.is_none() {
            self.start_graceful_shutdown()?;
        }

        match timeout(SHUTDOWN_TIMEOUT, self.child.wait()).await {
            Ok(result) => {
                result?;
            }
            Err(_) => {
                self.child.start_kill()?;
                self.child.wait().await?;
            }
        }

        self.finish_output_tasks().await;
        Ok(())
    }

    #[cfg(unix)]
    fn start_graceful_shutdown(&mut self) -> Result<(), TorProcessError> {
        let Some(pid) = self.child.id() else {
            return Ok(());
        };
        let pid = i32::try_from(pid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "child PID does not fit i32")
        })?;

        // SAFETY: `kill` only reads the PID and signal values supplied here.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            return Ok(());
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error.into())
        }
    }

    #[cfg(not(unix))]
    fn start_graceful_shutdown(&mut self) -> Result<(), TorProcessError> {
        self.start_kill()
    }

    async fn write_config_to_stdin(&mut self, config: &TorConfig) -> Result<(), TorProcessError> {
        let Some(mut stdin) = self.child.stdin.take() else {
            return Err(TorProcessError::MissingStdin);
        };

        stdin.write_all(config.render().as_bytes()).await?;
        stdin.flush().await?;
        stdin.shutdown().await?;
        Ok(())
    }

    async fn finish_output_tasks(&mut self) {
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        if let Some(task) = self.stdout_task.take() {
            task.abort();
        }
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

async fn drain_output(output: impl AsyncRead + Unpin, stream: OutputStream) {
    let mut lines = BufReader::new(output).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match stream {
                OutputStream::Stdout => {
                    tracing::debug!(target: "torlane::tor", %line, "tor stdout")
                }
                OutputStream::Stderr => tracing::warn!(target: "torlane::tor", %line, "tor stderr"),
            },
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(target: "torlane::tor", %error, "failed to read tor output");
                break;
            }
        }
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
