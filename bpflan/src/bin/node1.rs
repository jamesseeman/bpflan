use std::{thread, time};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut handle = bpflan::connect()?;
    let n1 = handle.create_network("test").await?;
    println!("{:?}", n1);

    // n1.add_peer();

    thread::sleep(time::Duration::from_secs(30));

    n1.destroy().await?;

    Ok(())
}
