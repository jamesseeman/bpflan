#![no_std]
#![no_main]

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_map_update_elem,
    macros::{classifier, map, xdp},
    maps::{Array, HashMap},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static HIT_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
pub fn bpflan_out(ctx: TcContext) -> i32 {
    info!(&ctx, "Egress packet");

    match try_bpflan(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn bpflan_in(ctx: TcContext) -> i32 {
    info!(&ctx, "Ingress packet");
    match try_bpflan(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_bpflan(mut ctx: TcContext) -> Result<i32, ()> {
    // info!(&ctx, "received a packet");
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let mut ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

            match ipv4_hdr.proto {
                IpProto::Icmp => {
                    let eth_src = eth_hdr.src_addr;
                    let eth_dst = eth_hdr.dst_addr;
                    info!(&ctx, "Eth src: {:mac}", eth_src);
                    info!(&ctx, "Eth dst: {:mac}", eth_dst);

                    let ip_src = u32::from_be(ipv4_hdr.src_addr);
                    let ip_dst = u32::from_be(ipv4_hdr.dst_addr);
                    info!(&ctx, "IP src: {:i}", ip_src);
                    info!(&ctx, "IP dst: {:i}", ip_dst);

                    ipv4_hdr.set_dst_addr(Ipv4Addr::new(8, 8, 8, 8));
                    ctx.store(EthHdr::LEN, &ipv4_hdr, 0).map_err(|_| ())?;

                    if let Some(count) = HIT_COUNT.get_ptr_mut(0) {
                        unsafe {
                            *count += 1;
                        }
                    }

                    Ok(TC_ACT_PIPE)
                }
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
