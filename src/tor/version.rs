use std::path::Path;
use std::process::Command;

use crate::tor::error::TorVersionError;

/// A parsed `tor --version` output, e.g. `0.4.9.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorVersion {
    /// Major version component.
    pub major: u32,
    /// Minor version component.
    pub minor: u32,
    /// Patch version component.
    pub patch: u32,
    /// Optional fourth (revision) version component.
    pub revision: Option<u32>,
}

/// Runs `tor_binary --version` and parses the reported version.
pub async fn detect_tor_version(
    tor_binary: impl AsRef<Path>,
) -> Result<TorVersion, TorVersionError> {
    let output = tokio::process::Command::new(tor_binary.as_ref())
        .arg("--version")
        .output()
        .await?;
    version_from_output(output)
}

/// Blocking equivalent of [`detect_tor_version`].
pub fn detect_tor_version_sync(tor_binary: &Path) -> Result<TorVersion, TorVersionError> {
    let output = Command::new(tor_binary).arg("--version").output()?;
    version_from_output(output)
}

fn version_from_output(output: std::process::Output) -> Result<TorVersion, TorVersionError> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Err(TorVersionError::Failed {
            status: output.status.code(),
            stderr,
        });
    }

    parse_tor_version(&stdout).ok_or(TorVersionError::Parse(stdout))
}

fn parse_tor_version(output: &str) -> Option<TorVersion> {
    let version = output
        .split_whitespace()
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let version = version.trim_end_matches('.');
    let mut parts = version.split('.');

    Some(TorVersion {
        major: parts.next()?.parse().ok()?,
        minor: parts.next()?.parse().ok()?,
        patch: parts.next()?.parse().ok()?,
        revision: parts.next().and_then(|value| value.parse().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tor_version() {
        assert_eq!(
            parse_tor_version("Tor version 0.4.9.2.\n"),
            Some(TorVersion {
                major: 0,
                minor: 4,
                patch: 9,
                revision: Some(2),
            })
        );
    }
}
