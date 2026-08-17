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

    println!("Round-robin selection:");
    for _ in 0..4 {
        let proxy = pool.next_proxy()?;
        println!(
            "  lane={} epoch={} SOCKS={}",
            proxy.lane().0,
            proxy.epoch(),
            proxy.addr(),
        );
    }

    let first = pool.proxy_for("customer-42")?;
    let second = pool.proxy_for("customer-42")?;
    assert_eq!(first.lane(), second.lane());
    println!("Sticky session customer-42 -> lane={}", first.lane().0);

    let snapshot = pool.snapshot();
    println!(
        "Tor PID={:?}, SOCKS={}, ready lanes={}",
        snapshot.instance.pid, snapshot.instance.socks_addr, snapshot.ready_lane_count,
    );

    pool.retire(first.lane())?;
    println!("Queued rotation for lane={}", first.lane().0);

    pool.shutdown().await?;
    Ok(())
}
