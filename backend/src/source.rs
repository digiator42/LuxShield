//! Packet-event producer.
//!
//! `run` bridges a source of [`PacketEvent`] records into the [`NetStore`]:
//!
//! * **sim** (default, cross-platform) — a synthetic traffic generator that
//!   mimics the XDP probe: passes ordinary flows, drops anything that hits the
//!   firewall, and periodically emits `bandwidth` spike records. It is the
//!   pair-of-dials demo used on non-Linux hosts.
//! * **ebpf** (Linux + feature `ebpf`) — reads the live `metrics_ringbuf`
//!   via aya and decodes [`PacketEvent::from_bytes`]; see `kernel.rs`.
//!
//! Priority: `LUX_RING=ebpf` when the feature is compiled in, else never.
use std::sync::Arc;
use std::time::Duration;

use lux_common::{PacketEvent, LUX_ACTION_DROP, LUX_ACTION_PASS, LUX_FAMILY_V4};

use crate::firewall::Firewall;
use crate::netstore::NetStore;
use crate::types::NetEvent;

pub async fn run(store: Arc<NetStore>, firewall: Arc<Firewall>) {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    if std::env::var("LUX_RING").as_deref() == Ok("ebpf") {
        println!("[luxshield] ring buffer source: xdp (aya)");
        if let Err(e) = crate::kernel::run_pump(store.clone(), firewall.clone()).await {
            eprintln!("[luxshield] xdp pump failed: {e}; falling back to simulator");
            sim::run(store, firewall).await;
        }
        return;
    }

    println!("[luxshield] ring buffer source: simulator (LUX_SIM_PPS={})", sim::sim_pps());
    sim::run(store, firewall).await;
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------

pub mod sim {
    use super::*;
    use std::time::Instant;

    const TICK: Duration = Duration::from_millis(50);

    /// Base sources in the normal flow mix.
    const POOL: [&str; 6] = [
        "10.0.0.12",
        "10.0.0.44",
        "192.168.1.7",
        "198.51.100.23",
        "203.0.113.50",
        "172.16.4.9",
    ];
    const ATTACKER: &str = "203.0.113.66";
    const PORTS: [u16; 6] = [443, 80, 22, 53, 8080, 3389];

    pub fn sim_pps() -> u64 {
        std::env::var("LUX_SIM_PPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20)
            .clamp(1, 5000)
    }

    fn spike_threshold() -> u64 {
        std::env::var("LUX_SPIKE_BPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(250_000)
    }

    /// xorshift64 — deterministic, dependency-free on purpose.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() as usize) % n
        }
    }

    pub async fn run(store: Arc<NetStore>, firewall: Arc<Firewall>) {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let burst_threshold = spike_threshold();

        let mut tick = tokio::time::interval(TICK);
        // window accumulation
        let mut window_bytes: u64 = 0;
        let mut window_pkts: u64 = 0;
        let mut window_until = Instant::now() + Duration::from_secs(1);
        // burst state
        let mut burst_until = Instant::now();
        let mut in_burst = false;

        loop {
            tick.tick().await;

            // (Re)enter bursts every 8-16 s for ~1.5 s to exercise spikes.
            if !in_burst && rng.below(160) == 0 {
                in_burst = true;
                burst_until = Instant::now() + Duration::from_millis(1500);
            }
            if in_burst && Instant::now() >= burst_until {
                in_burst = false;
            }

            let pps: f64 = if in_burst { 60.0 } else { sim_pps() as f64 };
            // Discrete packets per 50 ms tick (>= 1 so the demo never stalls).
            let baseline = (pps * TICK.as_secs_f64()).max(1.0) as usize;

            for _ in 0..baseline {
                let src = if in_burst && rng.below(100) < 60 {
                    ATTACKER
                } else {
                    POOL[rng.below(POOL.len())]
                };
                let proto = match rng.below(20) {
                    0..=13 => 6u8,  // tcp
                    14..=18 => 17u8, // udp
                    _ => 1u8,        // icmp
                };
                let port = if proto == 1 { 0 } else { PORTS[rng.below(PORTS.len())] };
                let size = if in_burst {
                    1200 + rng.below(300) as u32
                } else {
                    60 + rng.below(900) as u32
                };

                let blocked = firewall.contains(src);
                let ev = PacketEvent {
                    ts_ns: 0,
                    src_ip: v4_mapped(src),
                    packet_size: size,
                    dst_port: port,
                    family: LUX_FAMILY_V4,
                    protocol: proto,
                    action: if blocked { LUX_ACTION_DROP } else { LUX_ACTION_PASS },
                    blocked: u8::from(blocked),
                    _pad: [0; 2],
                };

                let reason = if blocked { firewall.reason(src) } else { None };
                let event = NetEvent::from_packet(&ev, "sim", reason.as_deref());
                window_bytes += size as u64;
                window_pkts += 1;
                store.ingest(&event).await;
            }

            // Once per second: bandwidth spike detection.
            if Instant::now() >= window_until {
                let bps = window_bytes * 8;
                let pps_now = window_pkts;
                if bps >= burst_threshold {
                    store.ingest(&NetEvent::spike(bps, pps_now, true)).await;
                }
                window_bytes = 0;
                window_pkts = 0;
                window_until = Instant::now() + Duration::from_secs(1);
            }
        }
    }

    pub fn v4_mapped(ip: &str) -> [u8; 16] {
        let a: Vec<u8> = ip
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .collect();
        let mut raw = [0u8; 16];
        if a.len() == 4 {
            raw[10] = 0xff;
            raw[11] = 0xff;
            raw[12..16].copy_from_slice(&a);
        }
        raw
    }
}