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
- explicit, TTL-based, and assignment-based lane rotation;
- manual Tor process restart;
- immutable pool state snapshots.

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

use torlane::Pool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::builder()
        .tor_binary("/usr/bin/tor")
        .work_dir("./.torlane")
        .lanes(8)
        .lane_ttl(Duration::from_secs(10 * 60))
        .lane_max_assignments(100)
        .bootstrap_timeout(Duration::from_secs(90))
        .build()
        .await?;

    let proxy = pool.next_proxy()?;
    println!(
        "lane={} epoch={} SOCKS={}",
        proxy.lane().0,
        proxy.epoch(),
        proxy.addr(),
    );

    let sticky = pool.proxy_for("customer-42")?;
    assert_eq!(sticky.lane(), pool.proxy_for("customer-42")?.lane());

    pool.retire(proxy.lane())?;

    let snapshot = pool.snapshot();
    println!(
        "Tor PID: {:?}, ready lanes: {}",
        snapshot.instance.pid,
        snapshot.ready_lane_count,
    );

    pool.shutdown().await?;
    Ok(())
}
```

`Proxy::socks5h_url()` returns a URL such as:

```text
socks5h://lane-000003-00000001:<password>@127.0.0.1:19050
```

The `socks5h` scheme instructs compatible HTTP clients to resolve hostnames
through Tor instead of using local DNS. The URL contains the lane password and
must not be written to logs.

`bootstrap_timeout` is an upper bound, not a fixed startup delay. `build()`
returns as soon as Tor reports `PROGRESS=100`. In the managed pool path, the
configured duration is applied separately to Control Port discovery and to Tor
bootstrap, so total startup time can exceed one timeout interval.

Unless overridden, a pool uses 16 lanes, a 90-second bootstrap timeout, no lane
TTL, no assignment limit, the `tor` executable from `PATH`, and in-memory
configuration delivery through stdin. `work_dir` has no default and is required.

## Runnable example

The repository includes a complete example that demonstrates round-robin and
sticky selection, snapshots, lane retirement, and orderly shutdown:

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

The example intentionally does not print SOCKS credentials. Treat the username
and password returned by `Proxy::auth()` or embedded in `socks5h_url()` as
secrets. All lanes intentionally show the same SOCKS address: they are logical
isolation contexts distinguished by credentials, not separate listeners or Tor
processes.

## Proxy selection

`Pool::next_proxy()` and `Pool::proxy_for(session)` both return an immutable
`Proxy`, but they solve different selection problems. Neither method performs
network I/O.

Use `next_proxy()` for independent or stateless work. It selects the next ready
lane in round-robin order, so consecutive calls normally use different lanes:

```rust,no_run
# use torlane::Pool;
# fn example(pool: &Pool) -> Result<(), torlane::PoolError> {
let first = pool.next_proxy()?;
let second = pool.next_proxy()?;
// With at least two ready lanes, these normally have different LaneIds.
# let _ = (first, second);
# Ok(())
# }
```

Use `proxy_for(session)` when related requests should have session affinity.
The session string is hashed to a stable logical `LaneId`, so the same key is
mapped to the same lane:

```rust,no_run
# use torlane::Pool;
# fn example(pool: &Pool) -> Result<(), torlane::PoolError> {
let first = pool.proxy_for("customer-42")?;
let second = pool.proxy_for("customer-42")?;
assert_eq!(first.lane(), second.lane());
# Ok(())
# }
```

This is useful for keeping one account or browser-like session on one Tor
isolation context while other sessions use other lanes. The HTTP client or the
application owns the cookies: `proxy_for()` does not store cookies itself. A
caller that needs cookies should keep a cookie jar and reuse the same configured
HTTP client for that logical session.

Session affinity does **not** pin an exit IP. Tor may replace circuits because
of age, failures, destination, or its own circuit-management policy, so requests
on the same lane can observe different exit IPs. Conversely, different lanes
can use the same exit relay. A lane supplies an isolation input to Tor, not a
fixed circuit or dedicated exit.

The mapping is also not exclusive: two different session keys can hash to the
same lane. If the selected sticky lane is temporarily unavailable,
`proxy_for()` returns `PoolError::LaneUnavailable` instead of silently moving
the session to a different identity. After lane rotation the key still selects
the same `LaneId`, but a later `proxy_for()` call returns the new epoch and new
SOCKS credentials; an already returned `Proxy` or built HTTP client is not
updated automatically.

In short:

- choose `next_proxy()` to distribute unrelated work across ready lanes;
- choose `proxy_for(session)` to keep related work associated with one logical
  Tor identity.

## Lane rotation

A lane is rotated when any configured condition is met:

- `Pool::retire(lane)` is called;
- its `lane_ttl` expires;
- it reaches `lane_max_assignments` proxy selections.

Rotation increments the lane epoch and creates new SOCKS credentials. Existing
`Proxy` values remain immutable, but their old credentials are no longer
returned by subsequent pool selections.

`Pool::retire(lane)` immediately removes the lane from the ready set and queues
its rotation on the pool manager. Until rotation finishes, `next_proxy()` skips
that lane and `proxy_for()` returns `PoolError::LaneUnavailable` if its session
maps to the lane. The call does not revoke already returned `Proxy` values or
clients built from them.

An assignment means that the pool returned a `Proxy`; it does not prove that an
HTTP request was sent.

## Tor restart and shutdown

`Pool::restart()` manually stops and starts the managed Tor process, refreshes
the SOCKS address, and rotates every lane. The pool does not automatically
restart Tor after an unexpected process failure.

Call `Pool::shutdown()` for an orderly shutdown. Controller ownership and
process drop handling also reduce the risk of leaving an orphan Tor process.

## Snapshots

`Pool::snapshot()` returns an immutable point-in-time view containing:

- Tor PID, SOCKS address, generation, and manual restart count;
- every lane's ID, epoch, state, assignment count, and age;
- ready and unavailable lane counts.

Call `snapshot()` again to observe newer state.

## Configuration levels and delivery

`torlane` provides a managed pool API and a lower-level Tor configuration API.
Both paths produce a `TorConfig`, but they assign responsibility for runtime
topology and final validation differently. The managed path automatically runs
`tor --verify-config`; the low-level path requires an explicit verification
call if validation before process startup is desired.

### Managed pool with `TorPolicy`

Use `PoolBuilder` and `TorPolicy` when the application wants `torlane` to own
the Tor process, controller connection, SOCKS endpoint, and logical lanes:

```rust,no_run
use torlane::{NetworkConfig, Pool, TorPolicy};

# async fn example() -> Result<(), torlane::PoolError> {
let policy = TorPolicy {
    network: NetworkConfig::dual_stack(),
    ..TorPolicy::default()
};

let pool = Pool::builder()
    .work_dir("./.torlane")
    .policy(policy)
    .lanes(8)
    .build()
    .await?;

// `torlane` has started Tor, authenticated the controller, waited for
// bootstrap, discovered the SOCKS listener, and created the lane pool.
let proxy = pool.next_proxy()?;
# let _ = proxy;
pool.shutdown().await?;
# Ok(())
# }
```

`TorPolicy` contains the application-selectable network, circuit, padding,
bridge, node-selection, system, and logging policy. The managed runtime
deliberately owns the settings required by the pool topology:

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

### Low-level configuration with `TorConfigBuilder`

Use `TorConfigBuilder` when the application needs to choose the listeners or
construct a Tor process without the lane pool:

```rust,no_run
use std::path::Path;

use torlane::{
    SocksConfig, TorConfigBuilder, TorOption, TorProcess, verify_config_with,
};

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

Unlike `TorInstance`, `TorProcess::spawn()` does not automatically verify the
configuration, authenticate a controller, wait for bootstrap, discover the
SOCKS address, create lanes, or provide pool restart semantics. Those concerns
belong to the caller in the low-level path.

### Configuration delivery

Generated configuration is sent through stdin by default, so no physical
`torrc` is required. Managed file delivery can be enabled explicitly:

```rust,no_run
# use torlane::Pool;
# async fn example() -> Result<(), torlane::PoolError> {
let pool = Pool::builder()
    .work_dir("./.torlane")
    .torrc_file("./.torlane/torrc")
    .build()
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

let pool = Pool::builder().work_dir("./.torlane").lanes(4).build().await?;

// Round-robin: a fresh client per selected lane.
let proxy = pool.next_proxy()?;
let client = proxy.reqwest_client()?;
let response = client.get("https://api.ipify.org").send().await?;
let status = response.status();
let exit_ip = response.text().await?;
println!(
    "lane={} epoch={} status={} exit_ip={}",
    proxy.lane().0,
    proxy.epoch(),
    status,
    exit_ip.trim(),
);

// Sticky session with a caller-supplied builder.
let sticky = pool.proxy_for("customer-42")?;
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
  `Proxy`; proxy selection itself still happens through `next_proxy()` or
  `proxy_for()`.

The adapter uses the `socks5h` scheme, so hostnames are resolved by Tor, not
locally, and it passes the lane's username/password as SOCKS5 credentials
(not HTTP `Proxy-Authorization`).

Every built `reqwest::Client` is bound to the `Proxy` snapshot it came from:
rotation (TTL, assignment limit, `Pool::retire()`) only affects lanes handed
out by later `next_proxy()`/`proxy_for()` calls, an already built client keeps
using its old lane credentials and open connections, and building a client
does not itself count as an assignment. Reuse one client for the HTTP session
that should share a lane identity, and get a new `Proxy`/client when the
application is ready to accept a new epoch.

`reqwest::Proxy`'s own `Debug` output prints the lane password in clear text,
unlike `torlane`'s types. Keep the value returned by `reqwest_proxy()` out of
logs; log `Proxy::lane()` and `Proxy::epoch()` instead.

A runnable example is included:

```text
cargo run --example reqwest --features reqwest
```

## Current scope

The project intentionally implements a basic pool. It does not currently
include:

- automatic process supervision and restart backoff;
- STREAM/CIRC observability;
- active circuit warmup.

Applications can use `Proxy::addr()` and `Proxy::auth()` to configure any
SOCKS5 client that supports username/password authentication and remote DNS.

## Development

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

The integration tests use local mock Control Port and SOCKS servers. Some
Tor-instance tests use `python3` to run a lightweight fake Tor executable; the
production library has no Python dependency.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option.
