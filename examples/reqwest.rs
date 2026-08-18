use std::env;
use std::path::PathBuf;
use std::time::Duration;

use torlane::Pool;

const IP_CHECK_URL: &str = "https://api.ipify.org";

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
        let proxy = pool.next_proxy()?;
        let client = proxy.reqwest_client()?;

        let response = client.get(IP_CHECK_URL).send().await?;
        let status = response.status();
        let exit_ip = response.text().await?;
        println!(
            "  lane={} epoch={} SOCKS={} status={} exit_ip={}",
            proxy.lane().0,
            proxy.epoch(),
            proxy.addr(),
            status,
            exit_ip.trim(),
        );
    }

    println!("Sticky session, caller-supplied builder:");
    let sticky = pool.proxy_for("customer-42")?;
    let builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    let sticky_client = sticky.configure_reqwest(builder)?.build()?;
    let response = sticky_client.get(IP_CHECK_URL).send().await?;
    let status = response.status();
    let exit_ip = response.text().await?;
    println!(
        "  session=customer-42 lane={} epoch={} status={} exit_ip={}",
        sticky.lane().0,
        sticky.epoch(),
        status,
        exit_ip.trim(),
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
