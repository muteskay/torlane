use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

use super::auth::AuthMethod;
use super::codec::read_reply;
use super::{ControlLine, ControlReply, TorControlError};

const COMMAND_BUFFER: usize = 32;
const BOOTSTRAP_POLL_INTERVAL: Duration = Duration::from_millis(50);

struct ControlCommand {
    command: String,
    response: oneshot::Sender<Result<ControlReply, TorControlError>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub auth_methods: Vec<AuthMethod>,
    pub cookie_file: Option<PathBuf>,
    pub tor_version: Option<String>,
}

#[derive(Clone)]
pub struct ControlClient {
    tx: mpsc::Sender<ControlCommand>,
}

impl ControlClient {
    pub async fn connect(endpoint: SocketAddr) -> Result<Self, TorControlError> {
        let stream = TcpStream::connect(endpoint).await?;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        let (tx, commands) = mpsc::channel(COMMAND_BUFFER);
        tokio::spawn(async move {
            run_actor(BufReader::new(read_half), write_half, commands).await;
        });
        Self { tx }
    }

    pub async fn command(
        &self,
        command: impl Into<String>,
    ) -> Result<ControlReply, TorControlError> {
        let command = command.into();
        if command.contains(['\r', '\n']) {
            return Err(TorControlError::InvalidCommand);
        }
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(ControlCommand { command, response })
            .await
            .map_err(|_| TorControlError::ChannelClosed)?;
        receiver.await.map_err(|_| TorControlError::ChannelClosed)?
    }

    pub async fn protocol_info(&self) -> Result<ProtocolInfo, TorControlError> {
        let reply = self.command_success("PROTOCOLINFO 1").await?;
        parse_protocol_info(&reply)
    }

    pub async fn authenticate_and_take_ownership(&self) -> Result<ProtocolInfo, TorControlError> {
        let protocol = self.protocol_info().await?;
        self.authenticate(&protocol).await?;
        self.take_ownership().await?;
        Ok(protocol)
    }

    pub async fn take_ownership(&self) -> Result<(), TorControlError> {
        self.command_success("TAKEOWNERSHIP").await?;
        self.command_success("RESETCONF __OwningControllerProcess")
            .await?;
        Ok(())
    }

    pub async fn wait_bootstrap(&self, wait_for: Duration) -> Result<(), TorControlError> {
        let wait = async {
            loop {
                let current = self
                    .command_success("GETINFO status/bootstrap-phase")
                    .await?;
                if bootstrap_progress(&current) == Some(100) {
                    return Ok(());
                }
                tokio::time::sleep(BOOTSTRAP_POLL_INTERVAL).await;
            }
        };

        tokio::time::timeout(wait_for, wait)
            .await
            .map_err(|_| TorControlError::BootstrapTimeout)?
    }

    pub async fn socks_listeners(&self) -> Result<Vec<SocketAddr>, TorControlError> {
        let reply = self.command_success("GETINFO net/listeners/socks").await?;
        let value = reply.lines.iter().find_map(|line| match line {
            ControlLine::KeyValue { key, value } if key == "net/listeners/socks" => Some(value),
            _ => None,
        });
        Ok(value
            .map(|value| {
                control_words(value)
                    .into_iter()
                    .filter_map(|listener| listener.parse().ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn socks_listener(&self) -> Result<SocketAddr, TorControlError> {
        let listeners = self.socks_listeners().await?;
        if listeners.len() != 1 {
            return Err(TorControlError::SocksListenerCount {
                count: listeners.len(),
            });
        }
        Ok(listeners[0])
    }

    pub(crate) async fn command_success(
        &self,
        command: impl Into<String>,
    ) -> Result<ControlReply, TorControlError> {
        let reply = self.command(command).await?;
        if reply.is_success() {
            Ok(reply)
        } else {
            Err(TorControlError::CommandFailed {
                code: reply.code,
                message: reply.message(),
            })
        }
    }
}

async fn run_actor<R>(
    mut reader: R,
    mut writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<ControlCommand>,
) where
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
{
    while let Some(command) = commands.recv().await {
        let result = async {
            writer.write_all(command.command.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
            writer.flush().await?;
            read_reply(&mut reader)
                .await?
                .ok_or(TorControlError::ChannelClosed)
        }
        .await;
        let connection_closed = result.is_err();
        let _ = command.response.send(result);
        if connection_closed {
            break;
        }
    }
}

fn bootstrap_progress(reply: &ControlReply) -> Option<u8> {
    reply.lines.iter().find_map(|line| {
        let value = match line {
            ControlLine::Text(value) => value.as_str(),
            ControlLine::KeyValue { key, value } if key == "status/bootstrap-phase" => value,
            _ => return None,
        };
        let marker = value.find("BOOTSTRAP")?;
        let words = control_words(&value[marker + "BOOTSTRAP".len()..]);
        field(&words, "PROGRESS")?.parse().ok()
    })
}

fn parse_protocol_info(reply: &ControlReply) -> Result<ProtocolInfo, TorControlError> {
    let mut auth_methods = Vec::new();
    let mut cookie_file = None;
    let mut tor_version = None;

    for line in &reply.lines {
        let ControlLine::Text(text) = line else {
            continue;
        };
        let words = control_words(text);
        match words.first().map(String::as_str) {
            Some("AUTH") => {
                if let Some(methods) = field(&words, "METHODS") {
                    auth_methods = methods.split(',').map(AuthMethod::parse).collect();
                }
                cookie_file = field(&words, "COOKIEFILE").map(PathBuf::from);
            }
            Some("VERSION") => {
                tor_version = field(&words, "Tor").map(ToOwned::to_owned);
            }
            _ => {}
        }
    }

    if auth_methods.is_empty() {
        return Err(TorControlError::Protocol(
            "PROTOCOLINFO reply did not contain AUTH methods".to_string(),
        ));
    }
    Ok(ProtocolInfo {
        auth_methods,
        cookie_file,
        tor_version,
    })
}

pub(crate) fn control_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.trim().chars();
    let mut quoted = false;

    while let Some(character) = chars.next() {
        match character {
            '"' => quoted = !quoted,
            '\\' if quoted => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub(crate) fn field<'a>(words: &'a [String], name: &str) -> Option<&'a str> {
    words
        .iter()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('='))
}
