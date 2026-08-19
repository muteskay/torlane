use std::env;
use std::path::PathBuf;
use std::time::Duration;

use torlane::{Pool, RotationPolicy};

const IP_CHECK_URL: &str = "https://api.ipify.org";

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

    println!("Round-robin requests, one client per lane:");
    for _ in 0..4 {
        let proxy = pool.next()?;
        let client = proxy.reqwest_client()?;

        let response = client.get(IP_CHECK_URL).send().await?;
        let status = response.status();
        let exit_ip = response.text().await?;
        println!(
            "  lane={} epoch={} SOCKS={} status={} exit_ip={}",
            proxy.lane_id().0,
            proxy.epoch(),
            proxy.addr(),
            status,
            exit_ip.trim(),
        );
    }

    println!("Sticky session, caller-supplied builder:");
    let sticky = pool.for_key("customer-42")?;
    let builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    let sticky_client = sticky.configure_reqwest(builder)?.build()?;
    let response = sticky_client.get(IP_CHECK_URL).send().await?;
    let status = response.status();
    let exit_ip = response.text().await?;
    println!(
        "  session=customer-42 lane={} epoch={} status={} exit_ip={}",
        sticky.lane_id().0,
        sticky.epoch(),
        status,
        exit_ip.trim(),
    );

    // Rotating the lane does not affect the clients already built above: they
    // keep using their pre-rotation credentials and connections.
    pool.rotate(sticky.lane_id()).await?;
    println!(
        "Rotated lane={}; a new Proxy/client for it now carries a new epoch.",
        sticky.lane_id().0
    );

    pool.shutdown().await?;
    Ok(())
}
