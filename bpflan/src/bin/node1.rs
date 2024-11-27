use std::{thread, time};

use bpflan::Network;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let n1 = Network::create("test").await?;
    // n1.add_peer();

    thread::sleep(time::Duration::from_millis(3000));

    n1.destroy().await?;

    Ok(())
}
