mod builder;
mod config;
mod error;
mod lane;
mod manager;
mod select;
mod snapshot;

pub use builder::PoolBuilder;
pub use config::{ConfigError, MAX_LANES, PoolConfig};
pub(crate) use error::LaneError;
pub(crate) use lane::{Lane, LaneEndpoint, SocksAuth, rotate_lane};
pub use lane::{LaneId, LaneState};
pub use manager::Pool;
pub(crate) use select::ReadySnapshot;
pub use select::{Proxy, SocksUrl};
pub use snapshot::{InstanceSnapshot, LaneSnapshot, PoolSnapshot};
