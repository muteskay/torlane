use std::env;
use std::path::PathBuf;
use std::time::Duration;

use torlane::{Pool, RotationPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tor_binary = env::var_os("TOR_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tor"));
    let work_dir = env::var_os("TORLANE_WORK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".torlane-example"));

    let pool = Pool::builder(work_dir)
        .tor_binary(tor_binary)
        .lanes(4)
        .rotation(
            RotationPolicy::new()
                .after(Duration::from_secs(10 * 60))
                .after_assignments(100),
        )
        .bootstrap_timeout(Duration::from_secs(90))
        .start()
        .await?;

    println!("Round-robin selection:");
    for _ in 0..4 {
        let proxy = pool.next()?;
        println!(
            "  lane={} epoch={} SOCKS={}",
            proxy.lane_id().0,
            proxy.epoch(),
            proxy.addr(),
        );
    }

    let first = pool.for_key("customer-42")?;
    let second = pool.for_key("customer-42")?;
    assert_eq!(first.lane_id(), second.lane_id());
    println!("Sticky session customer-42 -> lane={}", first.lane_id().0);

    pool.rotate(first.lane_id()).await?;
    println!("Rotated lane={}", first.lane_id().0);

    pool.shutdown().await?;
    Ok(())
}
