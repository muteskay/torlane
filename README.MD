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
    println!("proxy URL: {}", proxy.socks5h_url());

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
through Tor instead of using local DNS.

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
secrets.

## Proxy selection

`Pool::next_proxy()` selects the next ready lane using round-robin order. It
does not perform network I/O.

`Pool::proxy_for(session)` hashes the session key to a stable logical
`LaneId`. If that lane is temporarily unavailable, the method returns
`PoolError::LaneUnavailable` instead of silently moving the session to a
different identity.

## Lane rotation

A lane is rotated when any configured condition is met:

- `Pool::retire(lane)` is called;
- its `lane_ttl` expires;
- it reaches `lane_max_assignments` proxy selections.

Rotation increments the lane epoch and creates new SOCKS credentials. Existing
`Proxy` values remain immutable, but their old credentials are no longer
returned by subsequent pool selections.

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

## Configuration delivery

The generated Tor configuration is sent through stdin by default, so no
physical `torrc` is required. File mode can be enabled explicitly:

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

Low-level Tor policy types are available for network, circuit, bridge, node
selection, padding, logging, and related settings.

## Reqwest integration

An opt-in `reqwest` feature adds inherent methods on `Proxy` that turn an
already selected lane into `reqwest` configuration:

```toml
[dependencies]
torlane = { version = "0.1", features = ["reqwest"] }
```

```rust,no_run
# #[cfg(feature = "reqwest")]
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
use torlane::Pool;

let pool = Pool::builder().work_dir("./.torlane").lanes(4).build().await?;

// Round-robin: a fresh client per selected lane.
let proxy = pool.next_proxy()?;
let client = proxy.reqwest_client()?;
let response = client.get("https://check.torproject.org/api/ip").send().await?;
println!("lane={} epoch={} status={}", proxy.lane().0, proxy.epoch(), response.status());

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
- `Proxy::reqwest_client()` is the round-robin/sticky shorthand for the two
  calls above.

The adapter uses the `socks5h` scheme, so hostnames are resolved by Tor, not
locally, and it passes the lane's username/password as SOCKS5 credentials
(not HTTP `Proxy-Authorization`).

Every built `reqwest::Client` is bound to the `Proxy` snapshot it came from:
rotation (TTL, assignment limit, `Pool::retire()`) only affects lanes handed
out by later `next_proxy()`/`proxy_for()` calls, an already built client keeps
using its old lane credentials and open connections, and building a client
does not itself count as an assignment. Reuse one client for the HTTP session
that should share a lane identity, and get a new `Proxy`/client when the
application is ready to accept a new epoch. See the `torlane::Proxy`
module-level docs (built with `--features reqwest`) for the full contract.

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
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The integration tests use local mock Control Port and SOCKS servers. Some
Tor-instance tests use `python3` to run a lightweight fake Tor executable; the
production library has no Python dependency.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option.
