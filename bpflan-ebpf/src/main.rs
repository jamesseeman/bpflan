#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn bpflan(ctx: XdpContext) -> u32 {
    match try_bpflan(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_bpflan(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { *eth_hdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

            match unsafe { *ipv4_hdr }.proto {
                IpProto::Icmp => {
                    let eth_src = unsafe { *eth_hdr }.src_addr;
                    let eth_dst = unsafe { *eth_hdr }.dst_addr;
                    info!(&ctx, "Eth src: {:mac}", eth_src);
                    info!(&ctx, "Eth dst: {:mac}", eth_dst);

                    let ip_src = u32::from_be(unsafe { *ipv4_hdr }.src_addr);
                    let ip_dst = u32::from_be(unsafe { *ipv4_hdr }.dst_addr);
                    info!(&ctx, "IP src: {:i}", ip_src);
                    info!(&ctx, "IP dst: {:i}", ip_dst);

                    Ok(xdp_action::XDP_PASS)
                }
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
