use aya::{
    maps::HashMap as EbpfHashMap,
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use futures::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use rand::{distributions::Alphanumeric, Rng};
use std::{ffi::CString, net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Port {
    name: String,
    if_index: u32,
    hw_addr: [u8; 6],
}

impl Port {
    pub fn get_name(self) -> String {
        self.name
    }

    pub fn get_if_index(self) -> u32 {
        self.if_index
    }

    pub fn get_hw_addr(self) -> [u8; 6] {
        self.hw_addr
    }

    // TODO
    //pub async fn delete(self)
}

const TUNSETIFF: u64 = 0x400454ca;
const IFF_TAP: i16 = 0x0002; // TAP device
const IFF_NO_PI: i16 = 0x1000; // No packet information

#[derive(Debug)]
struct BridgeInterface {
    name: String,
    if_index: u32,
    ip_addr: Ipv4Addr,
    mac_addr: [u8; 6],
}

#[derive(Debug)]
pub struct Network {
    name: String,
    if_index: u32,
    vni: u32, // Technically this is u24
    hw_addr: [u8; 6],
    ebpf: Arc<Mutex<Ebpf>>,
    ports: Vec<Port>,
    parent_if: Option<BridgeInterface>,
}

impl Network {
    async fn get_interface_by_name(
        handle: &rtnetlink::Handle,
        name: String,
    ) -> Option<(u32, [u8; 6])> {
        let mut links = handle.link().get().match_name(name.clone()).execute();
        match links.try_next().await {
            Ok(result) => match result {
                Some(link) => {
                    if let Some(LinkAttribute::Address(addr)) = link
                        .attributes
                        .iter()
                        .find(|attr| matches!(attr, LinkAttribute::Address(_)))
                    {
                        // TODO: check that the returned hw_addr is accurate
                        // Testing shows that this value returned after an instance is created
                        // is different than that shown by 'ip link show'
                        if let Ok(hw_addr) = addr.as_slice().try_into() {
                            return Some((link.header.index, hw_addr));
                        }
                    }

                    None
                }
                None => None,
            },

            // For some reason, try_next() returns an Error when no interface is found rather than a None
            Err(_) => None,
        }
    }

    // Todo: VNI is actually u24, we need to verify that value isn't greater than max valid VNI
    pub async fn create(
        ebpf: Arc<Mutex<Ebpf>>,
        name: &str,
        vni: u32,
    ) -> Result<Self, crate::Error> {
        // Connect to rtnetlink
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let iface = format!("bpf-{}", name);
        // Check if interface already exists
        let (if_index, hw_addr) = match Network::get_interface_by_name(&handle, iface.clone()).await
        {
            Some((index, addr)) => (index, addr),
            None => {
                // Attempt to create interface
                handle.link().add().bridge(iface.clone()).execute().await?;
                if let Some((index, addr)) =
                    Network::get_interface_by_name(&handle, iface.clone()).await
                {
                    (index, addr)
                } else {
                    return Err(crate::Error::InterfaceCreateFailed);
                }
            }
        };

        // Set interface up
        handle.link().set(if_index).up().execute().await?;

        // Load ebpf programs
        let _ = tc::qdisc_add_clsact(&iface);

        let mut ebpf_mut = ebpf.lock().await;

        // TODO: check if TC's are already attached for previously existing interfaces
        let program_in: &mut SchedClassifier =
            ebpf_mut.program_mut("bpflan_out").unwrap().try_into()?;
        program_in.load()?;
        program_in.attach(&iface, TcAttachType::Egress)?;

        let program_out: &mut SchedClassifier =
            ebpf_mut.program_mut("bpflan_in").unwrap().try_into()?;
        program_out.load()?;
        program_out.attach(&iface, TcAttachType::Ingress)?;

        let mut vni_map: EbpfHashMap<_, u32, u32> =
            EbpfHashMap::try_from(ebpf_mut.map_mut("VNI").unwrap())?;
        let _ = vni_map.insert(if_index, vni, 0);

        /*
        // TODO: move following block to separate function
        let ebpf_clone = ebpf.clone();
        tokio::spawn(async move {
            loop {
                let mut ebpf_mut = ebpf_clone.lock().await;
                let arp_cache: EbpfHashMap<_, [u8; 6], u32> =
                    EbpfHashMap::try_from(ebpf_mut.map_mut("ARP_CACHE").unwrap()).unwrap();

                std::thread::sleep(Duration::from_secs(1));

                for entry in arp_cache.iter() {
                    let (key, value) = entry.unwrap();
                    println!("Entry: {:?}: {}", key, value);
                }
            }
        });
        */

        Ok(Self {
            name: name.into(),
            vni,
            if_index,
            hw_addr,
            ebpf: ebpf.clone(),
            ports: vec![],
            parent_if: None,
        })
    }

    pub fn get_if_index(&self) -> u32 {
        self.if_index
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub async fn set_parent(
        &mut self,
        parent: &str,
        ip_addr: Ipv4Addr,
    ) -> Result<u32, crate::Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        if let Some((if_index, hw_addr)) =
            Network::get_interface_by_name(&handle, parent.into()).await
        {
            self.parent_if = Some(BridgeInterface {
                name: parent.into(),
                if_index,
                ip_addr,
                mac_addr: hw_addr,
            });

            let mut ebpf_mut = self.ebpf.lock().await;
            let mut if_map: EbpfHashMap<_, u32, u32> =
                EbpfHashMap::try_from(ebpf_mut.map_mut("PARENT_IF").unwrap())?;
            let _ = if_map.insert(self.if_index, if_index, 0);
            let mut ip_map: EbpfHashMap<_, u32, u32> =
                EbpfHashMap::try_from(ebpf_mut.map_mut("PARENT_IP").unwrap())?;
            let _ = ip_map.insert(self.if_index, ip_addr.to_bits(), 0);
            let mut hwaddr_map: EbpfHashMap<_, u32, [u8; 6]> =
                EbpfHashMap::try_from(ebpf_mut.map_mut("PARENT_MAC").unwrap())?;
            let _ = hwaddr_map.insert(self.if_index, hw_addr, 0);

            Ok(if_index)
        } else {
            Err(crate::Error::InterfaceNotFound)
        }
    }

    pub async fn add_peer(&mut self, peer: Ipv4Addr) -> Result<(), crate::Error> {
        let mut ebpf_mut = self.ebpf.lock().await;
        let mut peers: EbpfHashMap<_, u32, u32> =
            EbpfHashMap::try_from(ebpf_mut.map_mut("PEERS").unwrap())?;
        let peer_int: u32 = peer.into();

        // PEERS is structured as a linked list
        let mut prev_peer = 0;
        while let Ok(value) = peers.get(&prev_peer, 0) {
            if value == 0 {
                break;
            } else {
                prev_peer = value;
            }
        }

        // Point previous peer to new peer
        let _ = peers.insert(prev_peer, peer_int, 0);

        // New peer is the end of the list
        let _ = peers.insert(peer_int, 0, 0);

        Ok(())
    }

    pub async fn drop_peer(&mut self, peer: Ipv4Addr) -> Result<(), crate::Error> {
        let mut ebpf_mut = self.ebpf.lock().await;
        let mut peers: EbpfHashMap<_, u32, u32> =
            EbpfHashMap::try_from(ebpf_mut.map_mut("PEERS").unwrap())?;
        let peer_int: u32 = peer.into();

        let prev_peer = 0;
        let next_peer = peers.get(&peer_int, 0)?;
        while let Ok(value) = peers.get(&prev_peer, 0) {
            if value == peer_int {
                break;
            }
            // If we've reached the end of the list without finding the peer...
            else if value == 0 {
                return Ok(());
            }
        }

        let _ = peers.insert(prev_peer, next_peer, 0);
        let _ = peers.remove(&peer_int);

        Ok(())
    }

    pub async fn delete(self) -> Result<(), crate::Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        handle.link().del(self.if_index).execute().await?;
        Ok(())
    }

    fn create_tap_interface(name: &str) -> Result<(), crate::Error> {
        // Open /dev/net/tun
        let tun_fd = open("/dev/net/tun", OFlag::O_RDWR, Mode::empty())?;

        // Create an ifreq struct to pass to the ioctl
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let tap_name_cstr = CString::new(name).unwrap();
        unsafe {
            std::ptr::copy_nonoverlapping(
                tap_name_cstr.as_ptr(),
                ifr.ifr_name.as_mut_ptr(),
                tap_name_cstr.to_bytes().len(),
            );
        }
        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

        // Call ioctl to create tap interface
        let result = unsafe { libc::ioctl(tun_fd, TUNSETIFF, &ifr) };
        if result == 0 {
            Ok(())
        } else {
            Err(crate::Error::IoctlError)
        }
    }

    pub async fn add_port(&mut self, name: Option<String>) -> Result<Port, crate::Error> {
        // Connect to rtnetlink
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // If a name wasn't provided, generate a random alphanumeric string
        let if_name = name.unwrap_or(
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect(),
        );

        let iface = format!("bpf-{}", if_name);

        // Check if interface already exists
        let (if_index, hw_addr) = match Network::get_interface_by_name(&handle, iface.clone()).await
        {
            Some((index, addr)) => (index, addr),
            None => {
                // Attempt to create interface
                Network::create_tap_interface(&iface)?;

                if let Some((index, addr)) =
                    Network::get_interface_by_name(&handle, iface.clone()).await
                {
                    (index, addr)
                } else {
                    return Err(crate::Error::InterfaceCreateFailed);
                }
            }
        };

        // Add port to the bridge
        handle
            .link()
            .set(if_index)
            .controller(self.if_index)
            .execute()
            .await?;

        // Set interface up
        handle.link().set(if_index).up().execute().await?;

        let new_port = Port {
            name: if_name,
            hw_addr,
            if_index,
        };
        self.ports.push(new_port.clone());

        Ok(new_port)
    }
}
