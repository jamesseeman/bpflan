mod network;
use aya::Ebpf;
use fd_lock::RwLock;
use log::{debug, warn};
pub use network::Network;
use std::{fs::OpenOptions, io::Write, sync::Arc};
use tokio::sync::Mutex;

mod error;
pub use error::Error;

#[derive(Clone)]
pub struct Handle {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl Handle {
    fn new() -> anyhow::Result<Self> {
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

        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
        })
    }

    pub async fn create_network(&mut self, name: &str) -> Result<Network, crate::Error> {
        Network::create(self.ebpf.clone(), name, 0).await
    }

    pub async fn create_network_with_vni(
        &mut self,
        name: &str,
        vni: u32,
    ) -> Result<Network, crate::Error> {
        Network::create(self.ebpf.clone(), name, vni).await
    }
}

pub fn connect() -> anyhow::Result<Handle> {
    Handle::new()
}
