//! Low-level Tor process management, raw configuration, Control Port
//! access, verification, and version detection.
//!
//! `torlane`'s primary API is [`Pool`](crate::Pool): it owns the Tor
//! process, controller connection, SOCKS endpoint, and lane pool. This
//! module is the escape hatch for applications that need direct control
//! over one of those pieces instead, for example to run Tor without a lane
//! pool, or to choose a custom set of listeners.
//!
//! Unlike [`Pool`](crate::Pool), the types here do not automatically verify
//! configuration, authenticate a controller, wait for bootstrap, or provide
//! restart semantics; callers are responsible for wiring those steps
//! themselves.

pub use crate::tor::controller::{
    AuthMethod, ControlClient, ControlLine, ControlReply, ProtocolInfo, TorControlError,
    wait_control_port_file,
};
pub use crate::tor::error::{
    TorIdentityError, TorProcessError, TorRuntimeValidationError, TorVerifyError, TorVersionError,
};
pub use crate::tor::identity::{TorIdentity, TorIdentityPool};
pub use crate::tor::instance::{InstanceConfig, InstanceId, TorInstance, TorInstanceError};
pub use crate::tor::process::{TorConfigSource, TorProcess, write_config_to_file};
pub use crate::tor::torc::{
    ControlAuth, ControlConfig, ControlListen, Flag, Isolation, PortSpec, SocksConfig, SocksFlag,
    SocksPort, TorConfig, TorConfigBuilder, TorConfigError, TorConfigWarning, TorOption,
    TorWriteError, Tristate,
};
pub use crate::tor::verify::{
    TorRuntimeValidation, TorVerifyReport, validate_runtime_config, verify_config_source_with,
    verify_config_with, verify_torrc_file_with,
};
pub use crate::tor::version::{TorVersion, detect_tor_version, detect_tor_version_sync};
