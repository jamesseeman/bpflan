#![no_std]
#![no_main]

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::{
        bpf_map_update_elem, bpf_skb_adjust_room, bpf_skb_change_head, bpf_skb_change_type,
        gen::bpf_clone_redirect,
    },
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, RingBuf},
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
static VNI: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PARENT_IF: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PARENT_IP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PARENT_MAC: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1024, 0);

// The ARP_CACHE map is structured based on the way bpflan handles traffic:
// When processing traffic, we need to know whether the packet's destination
// is on the local machine, or if it needs to be encapsulated in VXLAN and sent
// to a peer. If ARP_CACHE[dst hw addr] == 0, then the destination is local.
// If ARP_CACHE[dst hw addr] == IP4, then the destination is on the peer {IP4}

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

#[derive(PartialEq)]
enum Direction {
    Ingress,
    Egress,
}

#[classifier]
pub fn bpflan_out(ctx: TcContext) -> i32 {
    // info!(&ctx, "Egress packet");
    match try_bpflan(ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn bpflan_in(ctx: TcContext) -> i32 {
    // info!(&ctx, "Ingress packet");
    match try_bpflan(ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn vxlan_wrap(ctx: &mut TcContext, peer_addr: u32) -> Result<(), ()> {
    let len = ctx.len();
    let if_index = unsafe { *ctx.skb.skb }.ifindex;

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
    if let Some(vni) = unsafe { VNI.get(&if_index) } {
        vxlan_hdr.vni = ((*vni << 8) as u32).to_be();
    }
    ctx.store(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN, &vxlan_hdr, 0)
        .map_err(|_| ())?;

    Ok(())
}

fn vxlan_unwrap(ctx: &mut TcContext) {
    // unsafe {
    //     bpf_skb_change_head(ctx.skb.skb, -BUFFER_LEN as u32, 0);
    // }
}

fn try_bpflan(mut ctx: TcContext, direction: Direction) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // For ARP requests and responses, update ARP_CACHE[hw addr] = 0 since we know the given hw addr is local
    // Note: this match is required because of this error: "reference to packed field is unaligned" when using if block
    match eth_hdr.ether_type {
        EtherType::Arp => {
            let mut arp_header: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            info!(&ctx, "ARP! {:mac}", arp_header.sha);
            let _ = ARP_CACHE.insert(&arp_header.sha, &0, 0);
        }
        _ => {}
    }

    // Broadcast
    if eth_hdr.dst_addr == BROADCAST {
        info!(&ctx, "Broadcast!");
        // let ifindex = unsafe { *ctx.skb.skb }.ifindex;
        // let ingress = unsafe { *ctx.skb.skb }.ingress_ifindex;
        // let tcindex = unsafe {*ctx.skb.skb}.tc_index;
        // info!(&ctx, "{} - {} - {}", ifindex, ingress, tcindex);

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
            if let Some(parent_if) = unsafe { PARENT_IF.get(&if_index) } {
                let _ = ctx.clone_redirect(*parent_if, 0);
            }

            next_index = *peer;
            x += 1;
        }

        if vxlan_wrapped {
            vxlan_unwrap(&mut ctx);
        }

        return Ok(TC_ACT_PIPE);
    }
    // Check if packet will be sent to peer
    else if let Some(peer_ipv4) = unsafe { ARP_CACHE.get(&eth_hdr.dst_addr) } {
        // Wrap in VXLAN
        vxlan_wrap(&mut ctx, *peer_ipv4)?;
        // Forward packet
        return Ok(TC_ACT_PIPE);
    }

    // TODO: multicast

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
