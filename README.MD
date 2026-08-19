# torlane

`torlane` is an asynchronous Rust library for running one Tor process and
exposing a pool of isolated logical SOCKS5 lanes.

Every lane uses the same Tor SOCKS5 listener with a unique username and
password. Tor's `IsolateSOCKSAuth` option treats different credentials as
separate isolation contexts, so an application can distribute traffic across
logical identities without starting one Tor process per identity.

> `torlane` provides isolation inputs to Tor; it does not guarantee that every
> lane receives a different circuit or exit relay at all times.

## Features

- asynchronous Tor process startup and shutdown;
- generated runtime configuration, delivered through stdin by default;
- automatic Control Port and SOCKS listener discovery;
- SAFECOOKIE authentication and controller ownership;
- bootstrap readiness checks;
- configurable number of logical lanes;
- lock-light round-robin proxy selection;
- deterministic sticky-session selection;
- explicit, TTL-based, and assignment-based lane rotation with an awaited
  completion guarantee;
- manual Tor process restart;
- immutable pool state snapshots;
- credentials that are private by default and redacted in `Debug`/`Display`.

## Requirements

- Rust 1.85 or newer;
- a Tor executable available as `tor`, or an explicit path passed to
  `PoolBuilder::tor_binary`;
- a Tokio runtime.

## Installation from Git

`torlane` is not published on crates.io yet. Add the Git repository directly:

```toml
[dependencies]
torlane = { git = "https://github.com/muteskay/torlane.git" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust,no_run
use std::time::Duration;

use torlane::{Pool, RotationPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::builder("./.torlane")
        .tor_binary("/usr/bin/tor")
        .lanes(8)
        .rotation(
            RotationPolicy::new()
                .after(Duration::from_secs(10 * 60))
                .after_assignments(100),
        )
        .bootstrap_timeout(Duration::from_secs(90))
        .start()
        .await?;

    let proxy = pool.next()?;
    println!(
        "lane={} epoch={} SOCKS={}",
        proxy.lane_id().0,
        proxy.epoch(),
        proxy.addr(),
    );

    let sticky = pool.for_key(b"customer-42")?;
    assert_eq!(sticky.lane_id(), pool.for_key(b"customer-42")?.lane_id());

    pool.rotate(proxy.lane_id()).await?;

    let snapshot = pool.snapshot();
    println!(
        "Tor PID: {:?}, ready lanes: {}",
        snapshot.instance().pid(),
        snapshot.ready_lane_count(),
    );

    pool.shutdown().await?;
    Ok(())
}
```

`Proxy::socks5h_url()` returns a `SocksUrl`, a redacted-by-default wrapper
around a URL such as:

```text
socks5h://lane-000003-00000001:<password>@127.0.0.1:19050
```

The `socks5h` scheme instructs compatible HTTP clients to resolve hostnames
through Tor instead of using local DNS. `SocksUrl`'s `Debug` and `Display`
never print the embedded password; call `SocksUrl::expose()` to get the raw
URL, and keep that value out of logs. `Proxy::username()` and
`Proxy::expose_password()` give the same credentials individually.

`bootstrap_timeout` is an upper bound, not a fixed startup delay. `start()`
returns as soon as Tor reports `PROGRESS=100`. The configured duration is
applied separately to Control Port discovery and to Tor bootstrap, so total
startup time can exceed one timeout interval.

Unless overridden, a pool uses 16 lanes, a 90-second bootstrap timeout, no
lane rotation limits, the `tor` executable from `PATH`, and in-memory
configuration delivery through stdin. `work_dir` is required and supplied to
`Pool::builder`.

## Runnable example

The repository includes a complete example that demonstrates round-robin and
sticky selection, snapshots, lane rotation, and orderly shutdown:

```text
cargo run --example basic_pool
```

By default it runs `tor` from `PATH` and stores instance data in
`.torlane-example`. Both paths can be overridden:

```text
TOR_BINARY=/usr/bin/tor \
TORLANE_WORK_DIR=/tmp/torlane-example \
cargo run --example basic_pool
```

The example intentionally does not print SOCKS credentials. Treat the values
returned by `Proxy::username()`/`Proxy::expose_password()`, or embedded in
`Proxy::socks5h_url()`, as secrets. All lanes intentionally show the same
SOCKS address: they are logical isolation contexts distinguished by
credentials, not separate listeners or Tor processes.

## Proxy selection

`Pool::next()` and `Pool::for_key(key)` both return an immutable `Proxy`, but
they solve different selection problems. Neither method performs network I/O.

Use `next()` for independent or stateless work. It selects the next ready
lane in round-robin order, so consecutive calls normally use different lanes:

```rust,no_run
# use torlane::Pool;
# fn example(pool: &Pool) -> Result<(), torlane::Error> {
let first = pool.next()?;
let second = pool.next()?;
// With at least two ready lanes, these normally have different LaneIds.
# let _ = (first, second);
# Ok(())
# }
```

Use `for_key(key)` when related requests should have session affinity. The
key is hashed to a stable logical `LaneId`, so the same key is mapped to the
same lane. `key` accepts anything that implements `AsRef<[u8]>`, so callers
are not forced to go through a `&str`:

```rust,no_run
# use torlane::Pool;
# fn example(pool: &Pool) -> Result<(), torlane::Error> {
let first = pool.for_key(b"customer-42")?;
let second = pool.for_key(b"customer-42")?;
assert_eq!(first.lane_id(), second.lane_id());
# Ok(())
# }
```

This is useful for keeping one account or browser-like session on one Tor
isolation context while other sessions use other lanes. The HTTP client or the
application owns the cookies: `for_key()` does not store cookies itself. A
caller that needs cookies should keep a cookie jar and reuse the same
configured HTTP client for that logical session.

Session affinity does **not** pin an exit IP. Tor may replace circuits because
of age, failures, destination, or its own circuit-management policy, so
requests on the same lane can observe different exit IPs. Conversely,
different lanes can use the same exit relay. A lane supplies an isolation
input to Tor, not a fixed circuit or dedicated exit.

The mapping is also not exclusive: two different keys can hash to the same
lane. If the selected sticky lane is temporarily unavailable, `for_key()`
returns `Error::LaneUnavailable` instead of silently moving the session to a
different identity. After lane rotation the key still selects the same
`LaneId`, but a later `for_key()` call returns the new epoch and new SOCKS
credentials; an already returned `Proxy` or built HTTP client is not updated
automatically.

In short:

- choose `next()` to distribute unrelated work across ready lanes;
- choose `for_key(key)` to keep related work associated with one logical Tor
  identity.

## Lane rotation

A lane is rotated when any configured condition is met:

- `Pool::rotate(lane)` is called and awaited;
- its `RotationPolicy` duration limit expires;
- it reaches its `RotationPolicy` assignment limit.

Rotation increments the lane epoch and creates new SOCKS credentials. Existing
`Proxy` values remain immutable, but their old credentials are no longer
returned by subsequent pool selections.

`Pool::rotate(lane).await` returns only after the new lane epoch has been
published and the lane is ready again, or returns an error if rotation
failed. Until rotation finishes, `next()` skips that lane and `for_key()`
returns `Error::LaneUnavailable` if its session maps to the lane. Rotating a
lane does not revoke already returned `Proxy` values or clients built from
them.

An assignment means that the pool returned a `Proxy`; it does not prove that
an HTTP request was sent.

## Tor restart and shutdown

`Pool::restart()` manually stops and starts the managed Tor process, refreshes
the SOCKS address, and rotates every lane. The pool does not automatically
restart Tor after an unexpected process failure.

`Pool` is cheaply cloneable; every clone shares the same background manager
task and Tor instance. Call `Pool::shutdown()` (an `&self` method — no need to
consume the last clone) for an orderly shutdown. Shutdown is global across
every clone and idempotent: calling it more than once, from one or many
clones, is safe. After shutdown, `next()`, `for_key()`, `rotate()`, and
`restart()` return `Error::Closed`. Controller ownership and process drop
handling also reduce the risk of leaving an orphan Tor process.

## Snapshots

`Pool::snapshot()` returns an immutable point-in-time view. Its accessors
give:

- `instance()` — Tor PID, SOCKS address, generation, and manual restart count;
- `lanes()` — every lane's ID, epoch, state, assignment count, and age;
- `ready_lane_count()` / `unavailable_lane_count()`.

Call `snapshot()` again to observe newer state.

## Module layout

The crate root exposes only the common managed-pool API: `Pool`,
`PoolBuilder`, `Proxy`, `SocksUrl`, `LaneId`, `Error`, `TorPolicy`, and
`RotationPolicy`. Everything else lives in an explicitly named namespace:

- `torlane::config` — `PoolConfig`, and the typed Tor policy configuration
  used by `TorPolicy` (`NetworkConfig`, `CircuitConfig`, `PaddingConfig`,
  `BridgeConfig`, `NodeSelectionConfig`, `SystemConfig`, `LoggingConfig`);
- `torlane::snapshot` — `PoolSnapshot`, `InstanceSnapshot`, `LaneSnapshot`,
  `LaneState`;
- `torlane::low_level` — process management, raw Tor configuration, Control
  Port access, verification, and Tor version detection.

Every public type has one documented canonical import path; the crate does
not re-export whole namespaces with `pub use ...::*`.

## Configuration levels and delivery

`torlane` provides a managed pool API and a lower-level Tor configuration API.
Both paths produce a `low_level::TorConfig`, but they assign responsibility
for runtime topology and final validation differently. The managed path
automatically runs `tor --verify-config`; the low-level path requires an
explicit verification call if validation before process startup is desired.

### Managed pool with `TorPolicy`

Use `PoolBuilder` and `TorPolicy` when the application wants `torlane` to own
the Tor process, controller connection, SOCKS endpoint, and logical lanes:

```rust,no_run
use torlane::config::NetworkConfig;
use torlane::{Pool, TorPolicy};

# async fn example() -> Result<(), torlane::Error> {
let policy = TorPolicy::default().with_network(NetworkConfig::dual_stack());

let pool = Pool::builder("./.torlane").policy(policy).lanes(8).start().await?;

// `torlane` has started Tor, authenticated the controller, waited for
// bootstrap, discovered the SOCKS listener, and created the lane pool.
let proxy = pool.next()?;
# let _ = proxy;
pool.shutdown().await?;
# Ok(())
# }
```

`TorPolicy` contains the application-selectable network, circuit, padding,
bridge, node-selection, system, and logging policy, read and written through
`with_*` setters and matching getters. The managed runtime deliberately owns
the settings required by the pool topology:

- `DataDirectory` under the configured work directory;
- one loopback Control Port with cookie authentication and controller
  ownership;
- one loopback, automatically allocated SOCKS listener with
  `IsolateSOCKSAuth` and `KeepAliveIsolateSOCKSAuth`;
- the files used to discover automatically allocated endpoints.

Consequently, `TorPolicy` does not expose `ControlConfig`, `SocksConfig`, or
raw Tor options. This prevents a policy from replacing settings on which pool
startup, isolation, restart, and shutdown depend.

Most individual settings inside the typed policy configs are optional. Values
left unset are omitted from the generated configuration, so the selected Tor
binary applies its own defaults. Explicit helpers such as
`NetworkConfig::ipv4_only()` pin behavior instead of deferring it to the
installed Tor version.

The managed construction path is:

```text
TorPolicy + PoolBuilder
        +
torlane-owned runtime topology
        |
        v
TorConfigBuilder -> TorConfig -> tor --verify-config -> TorInstance -> Pool
```

### Low-level configuration with `low_level::TorConfigBuilder`

Use `torlane::low_level` when the application needs to choose the listeners
or construct a Tor process without the lane pool:

```rust,no_run
use std::path::Path;

use torlane::low_level::{SocksConfig, TorConfigBuilder, TorOption, TorProcess, verify_config_with};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = TorConfigBuilder::new("./tor-data")
    .socks(SocksConfig::isolated_auth(9050))
    .raw_option(TorOption::new("DormantTimeoutEnabled", "0")?)
    .build()?;

verify_config_with(&config, Path::new("tor"))?;
let mut process = TorProcess::spawn_default("tor", &config).await?;

# process.shutdown().await?;
# Ok(())
# }
```

`TorConfigBuilder::build()` checks the invariants known to `torlane` and
returns the final renderable `TorConfig`. `TorOption` is an escape hatch for
valid one-line Tor options that do not have a typed API. It prevents newline
injection, but it does not know whether Tor supports the option, whether its
value is valid, or whether it conflicts with a typed setting. Call
`verify_config_with()` before a low-level launch to let the selected Tor binary
validate the result.

Unlike `low_level::TorInstance`, `TorProcess::spawn()` does not automatically
verify the configuration, authenticate a controller, wait for bootstrap,
discover the SOCKS address, create lanes, or provide pool restart semantics.
Those concerns belong to the caller in the low-level path.

### Configuration delivery

Generated configuration is sent through stdin by default, so no physical
`torrc` is required. Managed file delivery can be enabled explicitly:

```rust,no_run
# use torlane::Pool;
# async fn example() -> Result<(), torlane::Error> {
let pool = Pool::builder("./.torlane")
    .torrc_file("./.torlane/torrc")
    .start()
    .await?;
# pool.shutdown().await?;
# Ok(())
# }
```

`PoolBuilder::torrc_file(path)` does not load an existing arbitrary `torrc`.
It changes only the delivery mode: `torlane` writes its generated `TorConfig`
to `path` and starts Tor with that file instead of passing the same generated
configuration through stdin.

## Reqwest integration

An opt-in `reqwest` feature adds inherent methods on `Proxy` that turn an
already selected lane into `reqwest` configuration:

```toml
[dependencies]
torlane = { git = "https://github.com/muteskay/torlane.git", features = ["reqwest"] }
```

```rust,no_run
# #[cfg(feature = "reqwest")]
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
use torlane::Pool;

let pool = Pool::builder("./.torlane").lanes(4).start().await?;

// Round-robin: a fresh client per selected lane.
let proxy = pool.next()?;
let client = proxy.reqwest_client()?;
let response = client.get("https://api.ipify.org").send().await?;
let status = response.status();
let exit_ip = response.text().await?;
println!(
    "lane={} epoch={} status={} exit_ip={}",
    proxy.lane_id().0,
    proxy.epoch(),
    status,
    exit_ip.trim(),
);

// Sticky session with a caller-supplied builder.
let sticky = pool.for_key(b"customer-42")?;
let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
let sticky_client = sticky.configure_reqwest(builder)?.build()?;
# let _ = sticky_client;
# Ok(())
# }
```

- `Proxy::reqwest_proxy()` builds a standalone `reqwest::Proxy` rule;
- `Proxy::configure_reqwest(builder)` adds that rule to a caller-supplied
  `reqwest::ClientBuilder`, keeping its other settings;
- `Proxy::reqwest_client()` constructs a client for an already selected
  `Proxy`; proxy selection itself still happens through `next()` or
  `for_key()`.

The adapter uses the `socks5h` scheme, so hostnames are resolved by Tor, not
locally, and it passes the lane's username/password as SOCKS5 credentials
(not HTTP `Proxy-Authorization`). Credentials are applied internally: callers
never need to call `Proxy::expose_password()` themselves to use `reqwest`.

Every built `reqwest::Client` is bound to the `Proxy` snapshot it came from:
rotation (TTL, assignment limit, `Pool::rotate()`) only affects lanes handed
out by later `next()`/`for_key()` calls, an already built client keeps
using its old lane credentials and open connections, and building a client
does not itself count as an assignment. Reuse one client for the HTTP session
that should share a lane identity, and get a new `Proxy`/client when the
application is ready to accept a new epoch.

`reqwest::Proxy`'s own `Debug` output prints the lane password in clear text,
unlike `torlane`'s types. Keep the value returned by `reqwest_proxy()` out of
logs; log `Proxy::lane_id()` and `Proxy::epoch()` instead.

A runnable example is included:

```text
cargo run --example reqwest --features reqwest
```

## Current scope

The project intentionally implements a basic pool. It does not currently
include:

- automatic process supervision and restart backoff;
- STREAM/CIRC observability;
- active circuit warmup;
- private fields on the individual typed `TorPolicy` configs (`NetworkConfig`,
  `CircuitConfig`, `PaddingConfig`, `BridgeConfig`, `NodeSelectionConfig`,
  `SystemConfig`, `LoggingConfig`) or on low-level `torc`/`controller` types —
  `TorPolicy` itself and the managed pool/snapshot types are closed, but
  these nested and low-level types still use public fields for this
  iteration.

Applications can use `Proxy::addr()`, `Proxy::username()`, and
`Proxy::expose_password()` to configure any SOCKS5 client that supports
username/password authentication and remote DNS.

See `MIGRATION.md` for the `0.1` to `0.2` upgrade path.

## Development

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps --all-features
```

The integration tests use local mock Control Port and SOCKS servers. Some
Tor-instance tests use `python3` to run a lightweight fake Tor executable; the
production library has no Python dependency.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option.
