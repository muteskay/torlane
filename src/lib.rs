//! `torlane` runs one Tor process and hands out a pool of isolated logical
//! SOCKS5 lanes.
//!
//! Every lane uses the same Tor SOCKS5 listener with a unique username and
//! password. Tor's `IsolateSOCKSAuth` option treats different credentials
//! as separate isolation contexts, so an application can distribute
//! traffic across logical identities without starting one Tor process per
//! identity. `torlane` provides isolation inputs to Tor; it does not
//! guarantee that every lane receives a different circuit or exit relay at
//! all times.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use std::time::Duration;
//!
//! use torlane::{Pool, RotationPolicy};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = Pool::builder("./.torlane")
//!     .tor_binary("/usr/bin/tor")
//!     .lanes(8)
//!     .rotation(
//!         RotationPolicy::new()
//!             .after(Duration::from_secs(10 * 60))
//!             .after_assignments(100),
//!     )
//!     .start()
//!     .await?;
//!
//! let proxy = pool.next()?;
//! let sticky = pool.for_key(b"customer-42")?;
//!
//! pool.rotate(proxy.lane_id()).await?;
//! pool.shutdown().await?;
//! # let _ = sticky;
//! # Ok(())
//! # }
//! ```
//!
//! # Module layout
//!
//! The crate root exposes only the common managed-pool API: [`Pool`],
//! [`PoolBuilder`], [`Proxy`], [`SocksUrl`], [`LaneId`], [`Error`],
//! [`TorPolicy`], and [`RotationPolicy`]. Everything else lives in an
//! explicitly named namespace:
//!
//! - [`config`] — managed pool and typed Tor policy configuration;
//! - [`snapshot`] — read-only pool and lane state;
//! - [`low_level`] — process management, raw Tor configuration, Control
//!   Port access, verification, and Tor version detection, for
//!   applications that need direct control over a piece [`Pool`] normally
//!   owns.

mod error;
mod pool;
#[cfg(feature = "reqwest")]
mod reqwest;
mod rotation;
mod tor;

pub mod config;
pub mod low_level;
pub mod snapshot;

pub use error::Error;
pub use pool::{LaneId, Pool, PoolBuilder, Proxy, SocksUrl};
pub use rotation::RotationPolicy;
pub use tor::instance::TorPolicy;
