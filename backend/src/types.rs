use std::time::{SystemTime, UNIX_EPOCH};

use lux_common::{PacketEvent, LUX_ACTION_DROP};

/// Wall-clock milliseconds as a float (matches the logs-soc SSE convention so
/// frontends can compare timestamps without an integer overflow worry).
pub fn now_ms_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

/// One record broadcast over the SSE stream. `kind` doubles as the SSE event
/// name: `packet` | `drop` | `spike` | `block`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NetEvent {
    pub ts_ms: f64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u32>,
    /// XDP verdict: `pass` | `drop`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Bandwidth spike fields (kind = `spike`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pps: Option<u64>,
    /// Pipeline the record came from: `xdp` | `sim` | `waf` | `api`.
    pub source: String,
}

impl NetEvent {
    pub fn from_packet(ev: &PacketEvent, source: &str, reason: Option<&str>) -> Self {
        let blocked = ev.action == LUX_ACTION_DROP;
        Self {
            ts_ms: now_ms_f64(),
            kind: if blocked { "drop" } else { "packet" }.to_string(),
            ip: Some(format_ip(&ev.src_ip)),
            port: (ev.dst_port > 0).then_some(ev.dst_port),
            protocol: Some(protocol_name(ev.protocol)),
            bytes: Some(ev.packet_size),
            action: Some(if blocked { "drop" } else { "pass" }.to_string()),
            reason: reason.map(ToOwned::to_owned),
            bps: None,
            pps: None,
            source: source.to_string(),
        }
    }

    pub fn spike(bps: u64, pps: u64, peak: bool) -> Self {
        Self {
            ts_ms: now_ms_f64(),
            kind: "spike".to_string(),
            ip: None,
            port: None,
            protocol: None,
            bytes: None,
            action: None,
            reason: Some(if peak {
                "bandwidth threshold exceeded".to_string()
            } else {
                "bandwidth back to normal".to_string()
            }),
            bps: Some(bps),
            pps: Some(pps),
            source: "pipeline".to_string(),
        }
    }

    pub fn block(ip: &str, reason: &str, added_by: &str) -> Self {
        Self {
            ts_ms: now_ms_f64(),
            kind: "block".to_string(),
            ip: Some(ip.to_string()),
            port: None,
            protocol: None,
            bytes: None,
            action: Some("drop".to_string()),
            reason: Some(reason.to_string()),
            bps: None,
            pps: None,
            source: added_by.to_string(),
        }
    }
}

fn protocol_name(p: u8) -> String {
    match p {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        other => other.to_string(),
    }
}

/// Format a 16-byte address; IPv4 arrives IPv4-mapped (`::ffff:a.b.c.d`).
pub fn format_ip(raw: &[u8; 16]) -> String {
    if raw[10] == 0xff && raw[11] == 0xff {
        format!("{}.{}.{}.{}", raw[12], raw[13], raw[14], raw[15])
    } else {
        let hex: Vec<String> = raw.iter().map(|b| format!("{:02x}", b)).collect();
        hex.chunks(2).map(|c| c.join("")).collect::<Vec<_>>().join(":")
    }
}