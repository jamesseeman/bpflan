use futures::TryStreamExt;
use rand::Rng;
use std::{collections::HashMap, net::SocketAddrV4};

pub struct Network {
    name: String,
    if_index: u32,
    id: u16, // Technically this is u24, but leaving as u16 for now
    peers: HashMap<SocketAddrV4, Option<[u8; 6]>>,
}

impl Network {
    pub async fn create(name: &str) -> Result<Self, crate::Error> {
        // Connect to rtnetlink
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // Create interface
        handle
            .link()
            .add()
            .bridge(format!("bpf-{}", name))
            .execute()
            .await?;

        // Get if_index
        let mut links = handle
            .link()
            .get()
            .match_name(format!("bpf-{}", name))
            .execute();
        let if_index = match links.try_next().await? {
            Some(link) => link.header.index,
            None => return Err(crate::Error::InterfaceCreateFailed),
        };

        // Set interface up
        handle.link().set(if_index).up().execute().await?;

        Ok(Self {
            name: name.into(),
            id: rand::thread_rng().gen_range(1..u16::MAX),
            if_index,
            peers: HashMap::new(),
        })
    }

    pub async fn create_with_id(name: &str, id: u16) -> Result<Self, crate::Error> {
        // Connect to rtnetlink
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // Create interface
        handle
            .link()
            .add()
            .bridge(format!("bpf-{}", name))
            .execute()
            .await?;

        // Get if_idnex
        let mut links = handle
            .link()
            .get()
            .match_name(format!("bpf-{}", name))
            .execute();
        let if_index = match links.try_next().await? {
            Some(link) => link.header.index,
            None => return Err(crate::Error::InterfaceCreateFailed),
        };

        // Set interface up
        handle.link().set(if_index).up().execute().await?;

        Ok(Self {
            name: name.into(),
            id,
            if_index,
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
