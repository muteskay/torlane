mod auth;
mod client;
mod codec;

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use auth::AuthMethod;
pub use client::{ControlClient, ProtocolInfo};
pub use codec::{ControlLine, ControlReply};

#[derive(Debug, thiserror::Error)]
pub enum TorControlError {
    #[error("control protocol I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid control protocol reply: {0}")]
    Protocol(String),

    #[error("control command channel is closed")]
    ChannelClosed,

    #[error("control command contains a line break")]
    InvalidCommand,

    #[error("control command failed with status {code}: {message}")]
    CommandFailed { code: u16, message: String },

    #[error("timed out waiting for control port file {path}")]
    ControlPortTimeout { path: PathBuf },

    #[error("invalid control endpoint in {path}: {value}")]
    InvalidControlEndpoint { path: PathBuf, value: String },

    #[error("PROTOCOLINFO did not advertise a cookie file")]
    MissingCookieFile,

    #[error("unsupported control authentication methods: {0:?}")]
    UnsupportedAuthentication(Vec<AuthMethod>),

    #[error("control authentication cookie must contain 32 bytes, got {0}")]
    InvalidCookieLength(usize),

    #[error("AUTHCHALLENGE reply is missing {0}")]
    MissingChallengeField(&'static str),

    #[error("invalid hexadecimal value for {field}: {value}")]
    InvalidHex { field: &'static str, value: String },

    #[error("SAFECOOKIE server hash verification failed")]
    InvalidServerHash,

    #[error("failed to generate SAFECOOKIE nonce: {0}")]
    Random(#[from] rand::Error),

    #[error("timed out waiting for Tor bootstrap")]
    BootstrapTimeout,

    #[error("expected exactly one TCP SOCKS listener, got {count}")]
    SocksListenerCount { count: usize },
}

pub async fn wait_control_port_file(
    path: impl AsRef<Path>,
    wait_for: Duration,
) -> Result<SocketAddr, TorControlError> {
    let path = path.as_ref().to_path_buf();
    let read_endpoint = async {
        loop {
            match tokio::fs::read_to_string(&path).await {
                Ok(content) if !content.trim().is_empty() => {
                    return parse_control_endpoint(&path, &content);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };

    match tokio::time::timeout(wait_for, read_endpoint).await {
        Ok(result) => result,
        Err(_) => Err(TorControlError::ControlPortTimeout { path }),
    }
}

fn parse_control_endpoint(path: &Path, content: &str) -> Result<SocketAddr, TorControlError> {
    let value = content
        .lines()
        .find_map(|line| line.trim().strip_prefix("PORT="))
        .unwrap_or_else(|| content.trim());

    value
        .parse()
        .map_err(|_| TorControlError::InvalidControlEndpoint {
            path: path.to_path_buf(),
            value: value.to_string(),
        })
}
