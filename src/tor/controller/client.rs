use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::{broadcast, mpsc, oneshot};

use super::auth::AuthMethod;
use super::codec::read_reply;
use super::command::ControlCommand;
use super::events::{control_words, field, parse_bootstrap_reply, parse_event};
use super::{ControlLine, ControlReply, TorControlError, TorEvent};

const COMMAND_BUFFER: usize = 32;
const EVENT_BUFFER: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub auth_methods: Vec<AuthMethod>,
    pub cookie_file: Option<PathBuf>,
    pub tor_version: Option<String>,
}

#[derive(Clone)]
pub struct ControlClient {
    tx: mpsc::Sender<ControlCommand>,
    events: broadcast::Sender<TorEvent>,
}

impl ControlClient {
    pub async fn connect(endpoint: SocketAddr) -> Result<Self, TorControlError> {
        let stream = TcpStream::connect(endpoint).await?;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        let (tx, commands) = mpsc::channel(COMMAND_BUFFER);
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let actor_events = events.clone();
        tokio::spawn(async move {
            run_actor(
                BufReader::new(read_half),
                write_half,
                commands,
                actor_events,
            )
            .await;
        });
        Self { tx, events }
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

    pub fn subscribe(&self) -> broadcast::Receiver<TorEvent> {
        self.events.subscribe()
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

    pub async fn enable_bootstrap_events(&self) -> Result<(), TorControlError> {
        self.command_success("SETEVENTS STATUS_CLIENT").await?;
        Ok(())
    }

    pub async fn wait_bootstrap(&self, wait_for: Duration) -> Result<(), TorControlError> {
        let mut events = self.subscribe();
        let wait = async {
            let current = self
                .command_success("GETINFO status/bootstrap-phase")
                .await?;
            if parse_bootstrap_reply(&current).is_some_and(|event| event.progress == 100) {
                return Ok(());
            }

            loop {
                match events.recv().await {
                    Ok(TorEvent::Bootstrap(event)) if event.progress == 100 => return Ok(()),
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(TorControlError::ChannelClosed);
                    }
                }
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
    reader: R,
    mut writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<ControlCommand>,
    events: broadcast::Sender<TorEvent>,
) where
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
{
    let (replies_tx, mut replies) = mpsc::channel(16);
    let reader_task = tokio::spawn(async move {
        let mut reader = reader;
        loop {
            let result = read_reply(&mut reader).await;
            let finished = result.as_ref().is_err() || matches!(result, Ok(None));
            if replies_tx.send(result).await.is_err() || finished {
                break;
            }
        }
    });

    let mut pending: Option<oneshot::Sender<Result<ControlReply, TorControlError>>> = None;
    loop {
        tokio::select! {
            command = commands.recv(), if pending.is_none() => {
                let Some(command) = command else { break };
                if let Err(error) = writer.write_all(command.command.as_bytes()).await {
                    let _ = command.response.send(Err(error.into()));
                    break;
                }
                if let Err(error) = writer.write_all(b"\r\n").await {
                    let _ = command.response.send(Err(error.into()));
                    break;
                }
                if let Err(error) = writer.flush().await {
                    let _ = command.response.send(Err(error.into()));
                    break;
                }
                pending = Some(command.response);
            }
            reply = replies.recv() => {
                match reply {
                    Some(Ok(Some(reply))) if reply.code == 650 => {
                        let _ = events.send(parse_event(reply));
                    }
                    Some(Ok(Some(reply))) => {
                        if let Some(response) = pending.take() {
                            let _ = response.send(Ok(reply));
                        }
                    }
                    Some(Ok(None)) => {
                        if let Some(response) = pending.take() {
                            let _ = response.send(Err(TorControlError::ChannelClosed));
                        }
                        break;
                    }
                    Some(Err(error)) => {
                        if let Some(response) = pending.take() {
                            let _ = response.send(Err(error));
                        }
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    reader_task.abort();
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
