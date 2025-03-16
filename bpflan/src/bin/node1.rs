use tokio::signal;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut handle = bpflan::connect()?;
    let mut n1 = handle.create_network("test").await?;
    println!("{:?}", n1);

    let p1 = n1.add_port(None).await?;
    println!("{:?}", p1);

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    n1.destroy().await?;

    Ok(())
}
