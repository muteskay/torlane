mod builder;
mod config;
mod error;
mod lane;
mod manager;
mod select;

pub use builder::PoolBuilder;
pub use config::{ConfigError, MAX_LANES, PoolConfig};
pub(crate) use error::LaneError;
pub use lane::LaneId;
pub(crate) use lane::{Lane, LaneEndpoint, LaneState, SocksAuth, rotate_lane};
pub use manager::Pool;
pub(crate) use select::ReadyLanes;
pub use select::{Proxy, SocksUrl};
