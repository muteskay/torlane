#[derive(Debug, thiserror::Error)]
pub(crate) enum LaneError {
    #[error("lane epoch overflow for lane {0}")]
    EpochOverflow(u32),

    #[error("failed to generate lane credentials: {0}")]
    Random(#[from] rand::Error),
}
