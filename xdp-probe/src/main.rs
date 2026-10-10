//! LuxShield XDP probe.
//!
//! Runs inside the NIC driver hook: parses Ethernet / IPv4 / IPv6 / TCP / UDP,
//! consults `blocklist_map`, and returns `XDP_DROP` (zero-copy drop before the
//! kernel allocates an `sk_buff`) or `XDP_PASS`. Every inspected packet emits a
//! `PacketEvent` on `metrics_ringbuf` for the user-space manager.
//!
//! Builds against the `bpfel-unknown-none` target (see `.cargo/config.toml`):
//!   cargo +nightly build --release -Z build-std=core
//! Requires `bpf-linker` on PATH and a Linux host for load/attach via `aya`.
//! API surface tracks `aya-ebpf` 0.1 (neé `aya-bpf`); bump the pin and re-check when upgrading.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use core::mem;
use lux_common::{
    BlockRule, PacketEvent, LUX_ACTION_DROP, LUX_ACTION_PASS, LUX_FAMILY_V4, LUX_FAMILY_V6,
};

const ETH_HDR_LEN: usize = 14;
const IHL_TO_BYTES: usize = 4;

// IPv4 protocol numbers (TCP/UDP drive port extraction).
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Blocked sources. Key is the IPv4 address in network byte order; the value
/// carries prefix/expiry so the manager can add temporary bans. `HashMap`
/// (not LPM trie) keeps the first cut dependency-light; swap for
/// `LpmTrie` if subnet matching is needed. Max entries is power-of-two.
#[map]
static BLOCKLIST: HashMap<u32, BlockRule> = HashMap::with_max_entries(4096, 0);

/// Per-packet metadata fan-out to user space (256 KiB ≈ 6.5k events).
#[map]
static METRICS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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

#[inline(always)]
fn emit(event: &PacketEvent) {
    // Best-effort: a full ring buffer must never change the forwarding verdict.
    let _ = METRICS.output(event, 0);
}

#[xdp]
pub fn xdp_prog(ctx: XdpContext) -> u32 {
    match inspect(&ctx) {
        Ok(action) => action,
        // Malformed/truncated frames are the common case for hostile traffic:
        // drop instead of passing garbage up the stack.
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn inspect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_proto = u16::from_be(unsafe { *ptr_at::<u16>(ctx, 12)? });
    let base = ETH_HDR_LEN;

    let (family, proto, src_u32, l4_off) = match eth_proto {
        0x0800 => {
            // IPv4
            let ip = ptr_at::<[u8; 20]>(ctx, base)?;
            let hdr = unsafe { *ip };
            let ihl = (hdr[0] & 0x0f) as usize;
            let proto = hdr[9];
            let src = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
            (LUX_FAMILY_V4, proto, src, base + ihl * IHL_TO_BYTES)
        }
        0x86dd => {
            // IPv6 — first 40 bytes; extension headers are not walked.
            let ip = ptr_at::<[u8; 40]>(ctx, base)?;
            let hdr = unsafe { *ip };
            let proto = hdr[6];
            // Fold the low 32 bits into the v4 map key for a shared blocklist.
            let src = u32::from_be_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]);
            (LUX_FAMILY_V6, proto, src, base + 40)
        }
        _ => {
            emit(&PacketEvent {
                ts_ns: unsafe { bpf_ktime_get_ns() },
                src_ip: [0; 16],
                packet_size: 0,
                dst_port: 0,
                family: 0,
                protocol: 0,
                action: LUX_ACTION_PASS,
                blocked: 0,
                _pad: [0; 2],
            });
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let dst_port = read_dst_port(ctx, l4_off, proto).unwrap_or(0);
    let size = (ctx.data_end() - ctx.data()) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let mut blocked = false;
    if let Some(rule) = unsafe { BLOCKLIST.get(&src_u32) } {
        let expired = rule.expires_at_ns != 0 && now > rule.expires_at_ns;
        if !expired && rule.action == LUX_ACTION_DROP {
            blocked = true;
        }
    }

    let event = PacketEvent {
        ts_ns: now,
        src_ip: v4_mapped(src_u32),
        packet_size: size,
        dst_port,
        family,
        protocol: proto,
        action: if blocked { LUX_ACTION_DROP } else { LUX_ACTION_PASS },
        blocked: if blocked { 1 } else { 0 },
        _pad: [0; 2],
    };
    emit(&event);

    Ok(if blocked { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS })
}

#[inline(always)]
fn read_dst_port(ctx: &XdpContext, l4_off: usize, proto: u8) -> Option<u16> {
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    // dst port is the second 16-bit field of both TCP and UDP headers.
    let p = ptr_at::<u16>(ctx, l4_off + 2).ok()?;
    Some(u16::from_be(unsafe { *p }))
}

/// Store IPv4 as an IPv4-mapped IPv6 address so one 16-byte field serves both
/// families end to end.
#[inline(always)]
fn v4_mapped(addr: u32) -> [u8; 16] {
    let o = addr.to_be_bytes();
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12] = o[0];
    a[13] = o[1];
    a[14] = o[2];
    a[15] = o[3];
    a
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
