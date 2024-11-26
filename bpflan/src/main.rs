use std::{fs::OpenOptions, io::Write};

use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
use fd_lock::RwLock;
#[rustfmt::skip]
use log::{debug, warn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Attempt to acquire file lock
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/var/run/bpflan.lock")?;
    let mut lock = RwLock::new(file);
    let mut lock_file = lock
        .try_write()
        .expect("Failed to acquire /var/run/bpflan.lock");
    lock_file.set_len(0)?;
    writeln!(lock_file, "{}", std::process::id())?;

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

    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("HIT_COUNT").unwrap())?;
    loop {
        while let Some(e) = ring_buf.next() {
            println!("Received: {:?}", e);
        }
    }

    Ok(())
}
