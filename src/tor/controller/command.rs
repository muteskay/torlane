use tokio::sync::oneshot;

use super::{ControlReply, TorControlError};

pub(crate) struct ControlCommand {
    pub(crate) command: String,
    pub(crate) response: oneshot::Sender<Result<ControlReply, TorControlError>>,
}
