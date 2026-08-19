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

/// A Tor Control Port protocol or connection error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TorControlError {
    /// The underlying TCP connection failed.
    #[error("control protocol I/O error: {0}")]
    Io(#[from] io::Error),

    /// A control reply could not be parsed.
    #[error("invalid control protocol reply: {0}")]
    Protocol(String),

    /// The background connection actor has stopped, so no further commands
    /// can be sent.
    #[error("control command channel is closed")]
    ChannelClosed,

    /// The command text contains a `\r` or `\n`, which would corrupt the
    /// control protocol framing.
    #[error("control command contains a line break")]
    InvalidCommand,

    /// The control command returned a non-success status.
    #[error("control command failed with status {code}: {message}")]
    CommandFailed {
        /// The control protocol status code.
        code: u16,
        /// The reply's message text.
        message: String,
    },

    /// Timed out waiting for the control port file at `path` to appear.
    #[error("timed out waiting for control port file {path}")]
    ControlPortTimeout {
        /// The control port file path being watched.
        path: PathBuf,
    },

    /// The control port file at `path` did not contain a valid `PORT=`
    /// endpoint.
    #[error("invalid control endpoint in {path}: {value}")]
    InvalidControlEndpoint {
        /// The control port file path.
        path: PathBuf,
        /// The unparseable value read from the file.
        value: String,
    },

    /// `PROTOCOLINFO` advertised cookie authentication but no cookie file
    /// path.
    #[error("PROTOCOLINFO did not advertise a cookie file")]
    MissingCookieFile,

    /// None of Tor's advertised authentication methods are supported by
    /// this client.
    #[error("unsupported control authentication methods: {0:?}")]
    UnsupportedAuthentication(Vec<AuthMethod>),

    /// The authentication cookie file did not contain exactly 32 bytes.
    #[error("control authentication cookie must contain 32 bytes, got {0}")]
    InvalidCookieLength(usize),

    /// The `AUTHCHALLENGE` reply is missing a required field.
    #[error("AUTHCHALLENGE reply is missing {0}")]
    MissingChallengeField(&'static str),

    /// A hexadecimal field in a control reply could not be decoded.
    #[error("invalid hexadecimal value for {field}: {value}")]
    InvalidHex {
        /// The field name.
        field: &'static str,
        /// The unparseable value.
        value: String,
    },

    /// The server's SAFECOOKIE hash did not match the expected value,
    /// indicating the cookie or nonce exchange failed.
    #[error("SAFECOOKIE server hash verification failed")]
    InvalidServerHash,

    /// Generating a random SAFECOOKIE nonce failed.
    #[error("failed to generate SAFECOOKIE nonce: {0}")]
    Random(#[from] rand::rngs::SysError),

    /// Tor did not report full bootstrap progress within the configured
    /// timeout.
    #[error("timed out waiting for Tor bootstrap")]
    BootstrapTimeout,

    /// Tor reported a number of TCP SOCKS listeners other than exactly one.
    #[error("expected exactly one TCP SOCKS listener, got {count}")]
    SocksListenerCount {
        /// The number of TCP SOCKS listeners actually reported.
        count: usize,
    },
}

/// Polls `path` until it contains a `PORT=host:port` line, or `wait_for`
/// elapses.
///
/// Used to discover an automatically chosen Control Port after Tor starts.
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
