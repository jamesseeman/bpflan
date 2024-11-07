use aya::{
    maps::Array,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpflan"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;

    let _ = tc::qdisc_add_clsact(&iface);

    let program_in: &mut SchedClassifier = ebpf.program_mut("bpflan_out").unwrap().try_into()?;
    program_in.load()?;
    program_in.attach(&iface, TcAttachType::Egress)?;

    let program_out: &mut SchedClassifier = ebpf.program_mut("bpflan_in").unwrap().try_into()?;
    program_out.load()?;
    program_out.attach(&iface, TcAttachType::Ingress)?;

    let mut hit_count = Array::try_from(ebpf.map_mut("HIT_COUNT").unwrap())?;
    hit_count.set(0, 0, 0)?;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        println!("{}", hit_count.get(&0, 0)?);
    }

    // let ctrl_c = signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // ctrl_c.await?;
    // println!("Exiting...");

    Ok(())
}
