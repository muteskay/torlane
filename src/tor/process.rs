use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::tor::config::TorConfig;
use crate::tor::error::TorProcessError;

#[derive(Debug)]
pub struct TorProcess {
    child: Child,
}

impl TorProcess {
    pub async fn spawn(
        tor_binary: impl AsRef<Path>,
        config: &TorConfig,
    ) -> Result<Self, TorProcessError> {
        let mut child = Command::new(tor_binary.as_ref())
            .args(TorConfig::stdin_args())
            .stdin(Stdio::piped())
            .spawn()?;

        let Some(stdin) = &mut child.stdin else {
            return Err(TorProcessError::MissingStdin);
        };

        config
            .write_to_stdin(stdin)
            .await
            .map_err(|error| match error {
                crate::tor::error::TorWriteError::Io(error) => TorProcessError::Io(error),
                crate::tor::error::TorWriteError::MissingParentDirectory => {
                    TorProcessError::MissingStdin
                }
            })?;

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
