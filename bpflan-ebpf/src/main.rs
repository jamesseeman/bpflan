#![no_std]
#![no_main]

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::{bpf_map_update_elem, bpf_skb_adjust_room, bpf_skb_change_head, bpf_skb_change_type},
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, RingBuf},
    programs::{TcContext, XdpContext},
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
static HIT_COUNT: RingBuf = RingBuf::with_byte_size(4, 0);

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

fn try_bpflan(mut ctx: TcContext, direction: Direction) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // For ARP requests and responses, update ARP_CACHE[hw addr] = None since we know the given hw addr is local
    // Note: this match is required because of this error: "reference to packed field is unaligned" when using if block
    match eth_hdr.ether_type {
        EtherType::Arp => {
            let mut arp_header: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            info!(&ctx, "ARP! {:mac}", arp_header.sha);
            let _ = ARP_CACHE.insert(&arp_header.sha, &0, 0);
        }
        _ => {}
    }

    info!(&ctx, "Dst addr: {:mac}", eth_hdr.dst_addr);

    // Broadcast
    if eth_hdr.dst_addr == BROADCAST {
        info!(&ctx, "Broadcast!");
        //let keys = PEERS.keys();
        //for (key, _) in PEERS.keys {
        //
        //}
        // Wrap in VXLAN

        // Duplicate and redirect to each peer

        // Unwrap VXLAN
    }
    // Check if packet will be sent to peer
    else if let Some(peer_ipv4) = unsafe { ARP_CACHE.get(&eth_hdr.dst_addr) } {
        // Wrap in VXLAN

        // Forward packet
        return Ok(TC_ACT_PIPE);
    }

    // TODO: multicast

    Ok(TC_ACT_PIPE)

    /*
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let mut ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

            match ipv4_hdr.proto {
                IpProto::Udp => {
                    let mut udp_hdr: UdpHdr =
                        ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
                    if udp_hdr.dest == 4789 {
                        // TODO: unwrap VXLAN headers
                        // TODO: account for potential user VXLAN traffic (not coming from bpflan) i.e. don't unwrap VXLAN
                    }

                    Ok(TC_ACT_PIPE)
                }
                IpProto::Icmp => {
                    //if Direction::Egress == direction {
                    let eth_src = eth_hdr.src_addr;
                    let eth_dst = eth_hdr.dst_addr;
                    info!(&ctx, "Eth src: {:mac}", eth_src);
                    info!(&ctx, "Eth dst: {:mac}", eth_dst);

                    let ip_src = u32::from_be(ipv4_hdr.src_addr);
                    let ip_dst = u32::from_be(ipv4_hdr.dst_addr);
                    info!(&ctx, "IP src: {:i}", ip_src);
                    info!(&ctx, "IP dst: {:i}", ip_dst);

                    // unsafe {
                    //     bpf_skb_adjust_room(ctx.skb.skb, -(BUFFER_LEN as i32), 0, 0);
                    // }

                    // ipv4_hdr.set_dst_addr(Ipv4Addr::new(8, 8, 8, 8));
                    // ctx.store(EthHdr::LEN, &ipv4_hdr, 0).map_err(|_| ())?;

                    let _ = HIT_COUNT.output(&1, 0);

                    let len = ctx.len();

                    /*
                    unsafe {
                        bpf_skb_change_head(ctx.skb.skb, BUFFER_LEN as u32, 0);
                    }

                    let mut eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
                    eth_hdr.dst_addr = [0, 1, 2, 3, 4, 5];
                    eth_hdr.src_addr = [6, 7, 8, 9, 10, 11];
                    eth_hdr.ether_type = EtherType::Ipv4;
                    ctx.store(0, &eth_hdr, 0).map_err(|_| ())?;

                    let mut ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
                    ip_hdr.set_version(4);
                    ip_hdr.set_src_addr(Ipv4Addr::new(1, 2, 3, 4));
                    ip_hdr.set_dst_addr(Ipv4Addr::new(5, 6, 7, 8));
                    ip_hdr.proto = IpProto::Udp;
                    ip_hdr.set_ihl(5);
                    ctx.store(EthHdr::LEN, &ip_hdr, 0).map_err(|_| ())?;

                    let mut udp_hdr: UdpHdr =
                        ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
                    // For now using arbitrary source port
                    udp_hdr.source = (60000 as u16).to_be();
                    udp_hdr.dest = (4789 as u16).to_be();
                    let payload_len = len + (VxlanHdr::LEN + UdpHdr::LEN) as u32;
                    info!(&ctx, "Payload len: {}", payload_len);
                    udp_hdr.len = (payload_len as u16).to_be();
                    ctx.store(EthHdr::LEN + Ipv4Hdr::LEN, &udp_hdr, 0)
                        .map_err(|_| ())?;

                    let mut vxlan_hdr: VxlanHdr = ctx
                        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
                        .map_err(|_| ())?;

                    // set_vni_valid doesn't seem to work?
                    vxlan_hdr.flags.set_bit(3, true);
                    vxlan_hdr.vni = ((200 << 8) as u32).to_be();
                    ctx.store(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN, &vxlan_hdr, 0)
                        .map_err(|_| ())?;

                    */
                    //}

                    Ok(TC_ACT_PIPE)
                }
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }

    */
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
