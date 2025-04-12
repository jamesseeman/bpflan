#![no_std]
#![no_main]

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{
        bpf_adj_room_mode::{BPF_ADJ_ROOM_MAC, BPF_ADJ_ROOM_NET},
        bpf_tunnel_key, xdp_action, TC_ACT_PIPE, TC_ACT_SHOT,
    },
    cty::c_void,
    helpers::{
        bpf_map_update_elem, bpf_skb_adjust_room, bpf_skb_change_head, bpf_skb_change_type,
        gen::{
            bpf_clone_redirect, bpf_get_hash_recalc, bpf_skb_change_tail, bpf_skb_load_bytes,
            bpf_skb_store_bytes, bpf_xdp_adjust_head,
        },
        r#gen::{bpf_set_hash_invalid, bpf_skb_set_tunnel_key},
    },
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, PerCpuArray, RingBuf, Stack},
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::{self, VxlanHdr},
};

const BROADCAST: [u8; 6] = [255, 255, 255, 255, 255, 255];
const BUFFER_LEN: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + VxlanHdr::LEN;

#[map]
static VNI_TO_BRIDGE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static BRIDGE_TO_VNI: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static PARENT_IF: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PARENT_IP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PARENT_MAC: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1024, 0);

// The ARP_CACHE map is structured based on the way bpflan handles traffic:
// When processing traffic, we need to know whether the packet's destination
// is on the local machine, or if it needs to be encapsulated in VXLAN and sent
// to a peer.
// For local traffic, ARP_CACHE[hw addr] is the VNI, which we can
// verify by comparing ARP_CACHE[hw addr] < 0xFFFFFF
// For remote traffic, ARP_CACHE[dst hw addr] == IPv4 address of the peer,
// which we can verify by comparing ARP_CACHE > 0xFFFFFF

// TODO:
// - TTL, clean up old arp entries
// - dynamically allocate arp cache?
// - evaluate memory usage for hash maps of different sizes
// note: this supports at most a full /16 network
#[map]
static ARP_CACHE: HashMap<[u8; 6], u32> = HashMap::with_max_entries(65536, 0);

// PEERS is a dynamic array i.e. vector of IPv4 address
// No vector map exists, so the solution is to use the HashMap as a linked list
// Each index in PEERS points to the next peer.
// Ex. [192.168.0.1, 192.168.0.2, 192.168.0.3] maps to:
// PEERS[0] = 3232235521
// PEERS[3232235521] = 3232235522
// PEERS[3232235522] = 3232235523
// PEERS[3232235523] = 0
#[map]
static PEERS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Used to map peer IPs to their L2 addresses
#[map]
static PEER_ARP_CACHE: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1024, 0);

#[derive(PartialEq)]
enum Direction {
    Ingress,
    Egress,
}

#[classifier]
pub fn parent_out(ctx: TcContext) -> i32 {
    //info!(&ctx, "Egress");
    match bpflan_parent(ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn parent_in(ctx: TcContext) -> i32 {
    //info!(&ctx, "Ingress");
    match bpflan_parent(ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn bpflan_out(ctx: TcContext) -> i32 {
    // info!(&ctx, "Egress packet");
    match bpflan_bridge(ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn bpflan_in(ctx: TcContext) -> i32 {
    // info!(&ctx, "Ingress packet");
    match bpflan_bridge(ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn vxlan_wrap(ctx: &mut TcContext, peer_addr: u32) -> Result<(), ()> {
    let len = ctx.len();
    let if_index = unsafe { *ctx.skb.skb }.ifindex;

    let original_eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    let vni = unsafe { ARP_CACHE.get(&original_eth_hdr.src_addr) }.unwrap_or(&0);

    // Add a buffer to the beginning of the packet
    unsafe {
        bpf_skb_change_head(ctx.skb.skb, BUFFER_LEN as u32, 0);
    }

    let mut eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    // TODO: determine dst_addr
    // eth_hdr.dst_addr = [0, 1, 2, 3, 4, 5];
    if let Some(hw_addr) = unsafe { PARENT_MAC.get(&if_index) } {
        eth_hdr.src_addr = *hw_addr;
    }
    if let Some(hw_addr) = unsafe { PEER_ARP_CACHE.get(&peer_addr.into()) } {
        eth_hdr.dst_addr = *hw_addr;
    }

    eth_hdr.ether_type = EtherType::Ipv4;
    ctx.store(0, &eth_hdr, 0).map_err(|_| ())?;

    let mut ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    ip_hdr.set_version(4);
    // TODO: fix this awkward if statement. Simply using unwrap() results in ebpf code failing to load
    if let Some(parent_ip) = unsafe { PARENT_IP.get(&if_index) } {
        ip_hdr.set_src_addr(Ipv4Addr::from_bits(*parent_ip));
    }
    ip_hdr.set_dst_addr(peer_addr.into());
    ip_hdr.proto = IpProto::Udp;
    ip_hdr.ttl = 64;
    ip_hdr.set_ihl(5);
    ctx.store(EthHdr::LEN, &ip_hdr, 0).map_err(|_| ())?;

    let mut udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    // For now using arbitrary source port
    // TODO: randomize source port, probably?
    udp_hdr.source = (60000 as u16).to_be();
    udp_hdr.dest = (4789 as u16).to_be();
    let payload_len = len + (VxlanHdr::LEN + UdpHdr::LEN) as u32;
    udp_hdr.len = (payload_len as u16).to_be();
    ctx.store(EthHdr::LEN + Ipv4Hdr::LEN, &udp_hdr, 0)
        .map_err(|_| ())?;

    let mut vxlan_hdr: VxlanHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
        .map_err(|_| ())?;

    // set_vni_valid doesn't seem to work?
    vxlan_hdr.flags.set_bit(3, true);
    vxlan_hdr.vni = ((*vni << 8) as u32).to_be();
    ctx.store(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN, &vxlan_hdr, 0)
        .map_err(|_| ())?;

    Ok(())
}

fn vxlan_unwrap(ctx: &mut TcContext) -> Result<u32, ()> {
    // TODO: determine if this call is needed
    if let Err(res) = ctx.pull_data(0) {
        info!(ctx, "Pull error");
        return Err(());
    }

    let vxlan_hdr: VxlanHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
        .map_err(|_| ())?;
    let vni = vxlan_hdr.vni.to_be() >> 8;

    let inner_hdr: EthHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + VxlanHdr::LEN)
        .map_err(|_| ())?;
    let _ = ctx.store(0, &inner_hdr, 0);

    let adjust_result =
        unsafe { bpf_skb_adjust_room(ctx.skb.skb, -(BUFFER_LEN as i32), BPF_ADJ_ROOM_MAC, 0) };
    info!(ctx, "adjust result: {}", adjust_result);

    Ok(vni)
}

fn bpflan_parent(mut ctx: TcContext, direction: Direction) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match direction {
        Direction::Egress => {
            if let Some(peer_ipv4) = unsafe { ARP_CACHE.get(&eth_hdr.src_addr) } {
                if eth_hdr.dst_addr == BROADCAST {
                    // ebpf calls this block an infinite loop unless we bound it, but
                    // this isn't an issue as long as the linked list doesn't loop
                    let mut next_index = 0;
                    let mut x = 0;
                    let mut vxlan_wrapped = false;
                    while let Some(peer) = unsafe { PEERS.get(&next_index) } {
                        if x >= 1024 {
                            break;
                        }

                        if *peer == 0 {
                            // Once we've cloned to each peer, drop the packet
                            // TODO: this is a bit inefficient, since we're cloning the packet one more time than necessary
                            // Also returning an error on expected behavior is sloppy
                            break;
                        }

                        // Wrap in VXLAN
                        if !vxlan_wrapped {
                            vxlan_wrap(&mut ctx, *peer)?;
                            vxlan_wrapped = true;
                        }
                        // If the packet has already been wrapped:
                        else {
                            // Modify destination address
                            let mut ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
                            ip_hdr.set_dst_addr(Ipv4Addr::from_bits(*peer));
                            ctx.store(EthHdr::LEN, &ip_hdr, 0).map_err(|_| ())?;
                        }

                        // Duplicate and redirect to each peer
                        let if_index = unsafe { *ctx.skb.skb }.ifindex;
                        let _ = ctx.clone_redirect(if_index, 0);

                        next_index = *peer;
                        x += 1;
                    }
                } else {
                    vxlan_wrap(&mut ctx, *peer_ipv4)?;
                    // Duplicate and redirect to each peer
                    let if_index = unsafe { *ctx.skb.skb }.ifindex;
                    let _ = ctx.clone_redirect(if_index, 0);
                }
            }
        }
        Direction::Ingress => {
            match eth_hdr.ether_type {
                EtherType::Ipv4 => {
                    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

                    // Todo: use something like PEER_STACK queue to prevent need to run this block on for every packet
                    if let Some(_) = unsafe { PEERS.get(&ip_hdr.src_addr) } {
                        let _ = PEER_ARP_CACHE.insert(&ip_hdr.src_addr, &eth_hdr.src_addr, 0);
                    }

                    match ip_hdr.proto {
                        IpProto::Udp => {
                            let udp_hdr: UdpHdr =
                                ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
                            info!(&ctx, "UDP: {}", udp_hdr.dest.to_le());
                            if udp_hdr.dest == (4789 as u16).to_le() {
                                vxlan_unwrap(&mut ctx)?;
                                let if_index = unsafe { *ctx.skb.skb }.ifindex;
                                let _ = ctx.clone_redirect(if_index, 0);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    Ok(TC_ACT_PIPE)
}

fn bpflan_bridge(mut ctx: TcContext, direction: Direction) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // For ARP requests and responses, update ARP_CACHE[hw addr] = 0 since we know the given hw addr is local
    // Note: this match is required because of this error: "reference to packed field is unaligned" when using if block
    match eth_hdr.ether_type {
        EtherType::Arp => {
            let arp_header: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            info!(&ctx, "ARP! {:mac}", arp_header.sha);
            // Todo: only do for locally originated traffic
            let _ = ARP_CACHE.insert(&arp_header.sha, &0, 0);
        }
        _ => {}
    }

    // If broadcasting or sending directly to peer:
    // Todo: support multicast
    let l3_dest = unsafe { ARP_CACHE.get(&eth_hdr.dst_addr) }.unwrap_or(&0xFFFFFF);
    if l3_dest >= &0xFFFFFF || eth_hdr.dst_addr == BROADCAST {
        info!(&ctx, "Broadcast!");

        // Clone to parent interface
        let if_index = unsafe { *ctx.skb.skb }.ifindex;
        if let Some(parent_if) = unsafe { PARENT_IF.get(&if_index) } {
            let vni = unsafe { BRIDGE_TO_VNI.get(&if_index) }.unwrap_or(&0);
            let _ = ARP_CACHE.insert(&eth_hdr.src_addr, vni, 0);
            let _ = ctx.clone_redirect(*parent_if, 0);
        }
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
