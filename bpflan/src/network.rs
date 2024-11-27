use aya::{
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use futures::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use std::{collections::HashMap, net::SocketAddrV4};

#[derive(Debug)]
pub struct Network {
    name: String,
    if_index: u32,
    vni: u16, // Technically this is u24, but leaving as u16 for now
    hw_addr: [u8; 6],
    peers: HashMap<SocketAddrV4, Option<[u8; 6]>>,
}

impl Network {
    pub async fn create(ebpf: &mut Ebpf, name: &str, vni: u16) -> Result<Self, crate::Error> {
        // Connect to rtnetlink
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // Create interface
        let iface = format!("bpf-{}", name);
        handle.link().add().bridge(iface.clone()).execute().await?;

        // Get if_index
        let mut links = handle.link().get().match_name(iface.clone()).execute();

        let (if_index, hw_addr) = match links.try_next().await? {
            Some(link) => {
                // Todo: fix, refactor
                if let Some(LinkAttribute::Address(addr)) = link
                    .attributes
                    .iter()
                    .find(|attr| matches!(attr, LinkAttribute::Address(_)))
                {
                    if let Ok(hw_addr) = addr.as_slice().try_into() {
                        (link.header.index, hw_addr)
                    } else {
                        return Err(crate::Error::InterfaceCreateFailed);
                    }
                } else {
                    return Err(crate::Error::InterfaceCreateFailed);
                }
            }
            None => return Err(crate::Error::InterfaceCreateFailed),
        };

        // Set interface up
        handle.link().set(if_index).up().execute().await?;

        // Load ebpf programs
        let _ = tc::qdisc_add_clsact(&iface);

        let program_in: &mut SchedClassifier =
            ebpf.program_mut("bpflan_out").unwrap().try_into()?;
        program_in.load()?;
        program_in.attach(&iface, TcAttachType::Egress)?;

        let program_out: &mut SchedClassifier =
            ebpf.program_mut("bpflan_in").unwrap().try_into()?;
        program_out.load()?;
        program_out.attach(&iface, TcAttachType::Ingress)?;

        Ok(Self {
            name: name.into(),
            vni,
            if_index,
            hw_addr,
            peers: HashMap::new(),
        })
    }

    pub fn add_peer(&mut self, peer: SocketAddrV4) {
        self.peers.insert(peer, None);
    }

    pub fn drop_peer(&mut self, peer: SocketAddrV4) -> Option<Option<[u8; 6]>> {
        self.peers.remove(&peer)
    }

    pub async fn destroy(self) -> Result<(), crate::Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        handle.link().del(self.if_index).execute().await?;
        Ok(())
    }
}
