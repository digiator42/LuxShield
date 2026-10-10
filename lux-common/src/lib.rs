//! Wire ABI shared between the aya-bpf probe (kernel, no_std) and the
//! GritShield user-space manager. Every struct is `#[repr(C)]` so both sides
//! agree on byte layout without an allocator or serde in the kernel path.
//!
//! Byte layout is versioned by [`ABI_VERSION`]; bump it whenever a field
//! changes so mismatched probe/manager pairs are detected on attach.
#![no_std]

pub const ABI_VERSION: u32 = 1;

// --- XDP actions surfaced through the metrics ring buffer ---
pub const LUX_ACTION_PASS: u8 = 0;
pub const LUX_ACTION_DROP: u8 = 1;
pub const LUX_ACTION_REDIRECT: u8 = 2;

pub const LUX_FAMILY_V4: u8 = 4;
pub const LUX_FAMILY_V6: u8 = 6;

/// One packet metadata record written by the XDP program into
/// `metrics_ringbuf` and read by the user-space manager.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketEvent {
    /// `bpf_ktime_get_ns()` timestamp.
    pub ts_ns: u64,
    /// Source address, 16 bytes so both families fit; v4 stored as
    /// IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
    pub src_ip: [u8; 16],
    /// L3 payload bytes seen at the NIC.
    pub packet_size: u32,
    /// Destination port in host byte order (0 for non-TCP/UDP).
    pub dst_port: u16,
    pub family: u8,   // LUX_FAMILY_V4 | LUX_FAMILY_V6
    pub protocol: u8, // IPPROTO: 1 icmp, 6 tcp, 17 udp
    pub action: u8,   // LUX_ACTION_*
    pub blocked: u8,  // 1 = matched blocklist_map
    /// Zero padding so the struct is a stable 40 bytes.
    pub _pad: [u8; 2],
}

impl PacketEvent {
    pub const SIZE: usize = core::mem::size_of::<PacketEvent>();

    /// Decode from raw ring-buffer bytes without allocating.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let mut ev = PacketEvent {
            ts_ns: u64::from_le_bytes(buf[0..8].try_into().ok()?),
            src_ip: [0; 16],
            packet_size: u32::from_le_bytes(buf[24..28].try_into().ok()?),
            dst_port: u16::from_le_bytes(buf[28..30].try_into().ok()?),
            family: buf[30],
            protocol: buf[31],
            action: buf[32],
            blocked: buf[33],
            _pad: [0; 2],
        };
        ev.src_ip.copy_from_slice(&buf[8..24]);
        Some(ev)
    }
}

/// Value stored in `blocklist_map`, keyed by IPv4 (`u32`, network order).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlockRule {
    /// Prefix length (0-32). The probe matches `key & mask == entry & mask`.
    pub prefix_len: u8,
    pub action: u8, // LUX_ACTION_DROP
    /// Expiry: `bpf_ktime_get_ns()` deadline. `0` = never expires.
    pub expires_at_ns: u64,
    /// Free-form reason bytes (ASCII), NUL-padded.
    pub reason: [u8; 32],
    pub _pad: [u8; 7],
}

impl BlockRule {
    pub const SIZE: usize = core::mem::size_of::<BlockRule>();
}