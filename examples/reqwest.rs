//! Round-robin and sticky HTTP requests through `torlane` lanes via `reqwest`.
//!
//! Requires the `reqwest` feature:
//!
//! ```text
//! cargo run --example reqwest --features reqwest
//! ```
//!
//! By default it runs `tor` from `PATH` and stores instance data in
//! `.torlane-example`. Both paths can be overridden:
//!
//! ```text
//! TOR_BINARY=/usr/bin/tor \
//! TORLANE_WORK_DIR=/tmp/torlane-example \
//! cargo run --example reqwest --features reqwest
//! ```
//!
//! Like `examples/basic_pool.rs`, this example intentionally never prints a
//! SOCKS password or a `socks5h://` URL: only `lane`, `epoch` and the SOCKS
//! address are safe to log. See the `torlane::Proxy` module-level docs
//! (built with `--features reqwest`) for the full client lifecycle contract.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use torlane::Pool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tor_binary = env::var_os("TOR_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tor"));
    let work_dir = env::var_os("TORLANE_WORK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".torlane-example"));

    let pool = Pool::builder()
        .tor_binary(tor_binary)
        .work_dir(work_dir)
        .lanes(4)
        .lane_ttl(Duration::from_secs(10 * 60))
        .lane_max_assignments(100)
        .bootstrap_timeout(Duration::from_secs(90))
        .build()
        .await?;

    println!("Round-robin requests, one client per lane:");
    for _ in 0..4 {
        // `next_proxy()` counts the assignment; building and using the client
        // afterwards does not touch the pool again.
        let proxy = pool.next_proxy()?;
        let client = proxy.reqwest_client()?;

        let response = client
            .get("https://check.torproject.org/api/ip")
            .send()
            .await?;
        println!(
            "  lane={} epoch={} SOCKS={} status={}",
            proxy.lane().0,
            proxy.epoch(),
            proxy.addr(),
            response.status(),
        );
    }

    println!("Sticky session, caller-supplied builder:");
    let sticky = pool.proxy_for("customer-42")?;
    let builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    let sticky_client = sticky.configure_reqwest(builder)?.build()?;
    let response = sticky_client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await?;
    println!(
        "  session=customer-42 lane={} epoch={} status={}",
        sticky.lane().0,
        sticky.epoch(),
        response.status(),
    );

    // Rotating the lane does not affect the clients already built above: they
    // keep using their pre-rotation credentials and connections.
    pool.retire(sticky.lane())?;
    println!(
        "Retired lane={}; a new Proxy/client for it would carry a new epoch.",
        sticky.lane().0
    );

    let snapshot = pool.snapshot();
    println!(
        "Tor PID: {:?}, ready lanes: {}",
        snapshot.instance.pid, snapshot.ready_lane_count,
    );

    pool.shutdown().await?;
    Ok(())
}
