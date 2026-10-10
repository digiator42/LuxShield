//! Linux-only kernel bridge (compiled with `--features ebpf` on Linux).
//!
//! Loads the XDP probe (`LUX_XDP_OBJ`, a raw `.o` built from `../xdp-probe`),
//! attaches it to `LUX_XDP_IFACE`, exposes `BLOCKLIST` mutations to the
//! [`Firewall`], and pumps `METRICS` records into the [`NetStore`].
//!
//! Note: this module is only exercised on Linux hosts; it targets aya 0.13.
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, Pod};
use lux_common::{BlockRule, PacketEvent, LUX_ACTION_DROP};

use crate::firewall::{Firewall, KernelBridge};
use crate::netstore::NetStore;
use crate::types::NetEvent;

/// `BlockRule` is defined in `lux-common` and `Pod` in `aya`, so the impl must
/// live on a local type. `repr(transparent)` keeps the exact kernel byte
/// layout while satisfying the orphan rule.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodBlockRule(BlockRule);

unsafe impl Pod for PodBlockRule {}

struct AyaInner {
    bpf: Ebpf,
}

pub struct AyaBridge {
    inner: Mutex<AyaInner>,
}

impl KernelBridge for AyaBridge {
    fn attached(&self) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        "xdp"
    }
    fn upsert(&self, key: u32, rule: &BlockRule) -> Result<bool, String> {
        let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
        let mut map: AyaHashMap<&mut MapData, u32, PodBlockRule> = AyaHashMap::try_from(
            inner
                .bpf
                .map_mut("BLOCKLIST")
                .ok_or("BLOCKLIST map missing")
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        map.insert(key, PodBlockRule(*rule), 0)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn remove(&self, key: u32) -> Result<bool, String> {
        let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
        let mut map: AyaHashMap<&mut MapData, u32, PodBlockRule> = AyaHashMap::try_from(
            inner
                .bpf
                .map_mut("BLOCKLIST")
                .ok_or("BLOCKLIST map missing")
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        map.remove(&key).map_err(|e| e.to_string())?;
        Ok(true)
    }
}

/// Load + attach the probe, wire the bridge into the firewall, and start the
/// ring-buffer pump. Returns an error the caller can log before falling back
/// to the simulator.
pub async fn run_pump(store: Arc<NetStore>, firewall: Arc<Firewall>) -> Result<(), String> {
    let iface = std::env::var("LUX_XDP_IFACE").map_err(|_| "LUX_XDP_IFACE is not set")?;
    let obj = std::env::var("LUX_XDP_OBJ").unwrap_or_else(|_| "target/xdp-probe.o".to_string());

    let mut bpf = Ebpf::load_file(&obj).map_err(|e| format!("load {obj}: {e}"))?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_prog")
        .ok_or("xdp_prog not found in object")
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| e.to_string())?;
    program.load().map_err(|e| e.to_string())?;
    program
        .attach(&iface, XdpFlags::default())
        .map_err(|e| e.to_string())?;

    let mut ring = RingBuf::try_from(
        bpf.take_map("METRICS")
            .ok_or("METRICS map missing")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    firewall.set_bridge(Arc::new(AyaBridge {
        inner: Mutex::new(AyaInner { bpf }),
    }));
    println!("[luxshield] xdp probe attached to {iface} (object {obj})");

    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || loop {
        while let Some(item) = ring.next() {
            let Some(ev) = PacketEvent::from_bytes(&item[..]) else {
                continue;
            };
            let blocked = ev.action == LUX_ACTION_DROP;
            let ip = crate::types::format_ip(&ev.src_ip);
            let reason = if blocked {
                firewall.reason(&ip)
            } else {
                None
            };
            let event = NetEvent::from_packet(&ev, "xdp", reason.as_deref());
            handle.block_on(store.ingest(&event));
        }
    });

    Ok(())
}