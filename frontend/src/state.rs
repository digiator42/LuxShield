//! Reactive application state for the LuxShield console.
//!
//! One [`AppState`] value holds every signal the dashboard reads or writes.
//! It is provided once via `provide!` in `run_app` and pulled out of context
//! with `use_context::<AppState>()` inside components.
//!
//! Packet records arrive over SSE (`packet` | `drop` | `spike` | `block` named
//! events, see [`crate::net`]), flow through [`crate::ingest`], and land in
//! `packets`. The worker thread ([`crate::worker`]) maintains per-IP
//! aggregates for the traffic map; the firewall panel talks REST to the
//! backend ([`crate::api`]).

use std::cell::Cell;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use veloasm::prelude::*;

// ---------------------------------------------------------------------------
// Buffer sizing
// ---------------------------------------------------------------------------

/// Packet rows retained in memory (the filter's source of truth).
pub const RAW_KEEP: usize = 800;
/// Raw buffer grows to this before being trimmed back to [`RAW_KEEP`].
pub const RAW_TRIM_AT: usize = 1000;

/// Rows kept in the terminal viewport after a trim.
pub const VISIBLE_KEEP: usize = 300;
/// Trim the terminal back to [`VISIBLE_KEEP`] only when it grows past this.
pub const VISIBLE_TRIM_AT: usize = 360;

/// Map nodes rendered on the traffic canvas.
pub const MAP_KEEP: usize = 48;
/// Flash alerts visible at once.
pub const TOAST_KEEP: usize = 5;
/// Milliseconds before a flash alert auto-dismisses.
pub const TOAST_TTL_MS: u32 = 6_000;

// ---------------------------------------------------------------------------
// Wire format — NetEvent as delivered by GET /api/v1/network/stream
// ---------------------------------------------------------------------------

/// One record broadcast over the SSE stream. `kind` doubles as the SSE event
/// name: `packet` | `drop` | `spike` | `block`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetEvent {
    pub ts_ms: f64,
    pub kind: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub bytes: Option<u32>,
    pub action: Option<String>,
    pub reason: Option<String>,
    pub bps: Option<u64>,
    pub pps: Option<u64>,
    pub source: String,
}

// ---------------------------------------------------------------------------
// Display enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PktKind {
    Packet,
    Drop,
    Spike,
    Block,
}

impl PktKind {
    pub fn parse(s: &str) -> PktKind {
        match s.trim().to_ascii_lowercase().as_str() {
            "drop" => PktKind::Drop,
            "spike" => PktKind::Spike,
            "block" => PktKind::Block,
            _ => PktKind::Packet,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PktKind::Packet => "PACKET",
            PktKind::Drop => "DROP",
            PktKind::Spike => "SPIKE",
            PktKind::Block => "BLOCK",
        }
    }

    /// CSS modifier shared by rows, chips and toasts.
    pub fn css(&self) -> &'static str {
        match self {
            PktKind::Packet => "packet",
            PktKind::Drop => "drop",
            PktKind::Spike => "spike",
            PktKind::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnStatus {
    Connecting,
    Open,
    Reconnecting,
    Closed,
}

impl ConnStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "CONNECTING",
            ConnStatus::Open => "STREAMING",
            ConnStatus::Reconnecting => "RECONNECTING",
            ConnStatus::Closed => "OFFLINE",
        }
    }

    /// CSS modifier for the status dot.
    pub fn css(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "connecting",
            ConnStatus::Open => "open",
            ConnStatus::Reconnecting => "reconnecting",
            ConnStatus::Closed => "closed",
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal row
// ---------------------------------------------------------------------------

/// One rendered packet row. Built eagerly on ingest so the keyed `for` body
/// can hand owned values to `<PacketRow>` without borrowing.
#[derive(Clone, Debug)]
pub struct PacketRow {
    pub id: u64,
    pub ts_ms: f64,
    pub kind: PktKind,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub bytes: u32,
    pub action: String,
    pub reason: String,
    pub source: String,
    /// Pre-lowercased search haystack so filtering never allocates per keystroke.
    pub haystack: String,
}

// ---------------------------------------------------------------------------
// Traffic map + firewall
// ---------------------------------------------------------------------------

/// Per-IP aggregate maintained by the worker thread and rendered on canvas.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MapNode {
    pub ip: String,
    pub packets: u64,
    pub drops: u64,
    pub bytes: u64,
    pub burst: bool,
    pub last_ts_ms: f64,
}

/// One firewall rule as returned by `GET /api/v1/firewall/rules`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub ip: String,
    pub prefix_len: u8,
    pub reason: String,
    pub added_by: String,
    pub added_at_ms: f64,
    pub expires_at_ms: Option<f64>,
    /// True once the rule actually reached `blocklist_map` in the kernel.
    pub kernel_synced: bool,
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Metrics {
    /// Packets seen in the last full second.
    pub packets_per_sec: RwSignal<u32>,
    /// Bytes seen in the last full second.
    pub bytes_per_sec: RwSignal<u32>,
    /// Drops seen in the last full second.
    pub drops_per_sec: RwSignal<u32>,
    /// Session totals.
    pub pass_total: RwSignal<u32>,
    pub drop_total: RwSignal<u32>,
    pub spike_total: RwSignal<u32>,
    pub block_total: RwSignal<u32>,
    pub bytes_total: RwSignal<u64>,
    /// Rolling `packets/sec` samples (newest last) feeding the sparkline.
    pub rate_history: RwSignal<Vec<f32>>,

    // Unsignalized counters, drained once per metrics tick.
    pub window_packets: Rc<Cell<u32>>,
    pub window_bytes: Rc<Cell<u64>>,
    pub window_drops: Rc<Cell<u32>>,
    /// Monotonic id source for packet rows.
    pub next_id: Rc<Cell<u64>>,
}

impl Metrics {
    /// Next unique id for a packet row.
    pub fn next_row_id(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }
}

#[derive(Clone)]
pub struct KernelInfo {
    pub bridge: RwSignal<String>,
    pub attached: RwSignal<bool>,
}

#[derive(Clone)]
pub struct AppState {
    pub conn: RwSignal<ConnStatus>,

    /// Raw ingested records (capped at [`RAW_KEEP`]).
    pub packets: SignalVec<PacketRow>,
    /// Filtered tail of `packets` actually rendered by the terminal.
    pub visible: SignalVec<PacketRow>,
    /// `None` = show every kind.
    pub filter_kind: RwSignal<Option<PktKind>>,
    pub filter_query: RwSignal<String>,
    pub auto_scroll: RwSignal<bool>,
    pub selected: RwSignal<Option<PacketRow>>,

    /// Per-IP aggregates for the traffic map (worker-maintained).
    pub map_nodes: SignalVec<MapNode>,
    /// Firewall rules (REST-polled).
    pub rules: SignalVec<Rule>,
    pub fw_error: RwSignal<String>,
    /// True when the backend answers 401/403: bad key or this viewer is
    /// WAF/firewall-banned (which blocks *every* endpoint, stream included).
    pub banned: RwSignal<bool>,

    /// Ephemeral flash alerts (auto-dismissed after [`TOAST_TTL_MS`]).
    pub toasts: SignalVec<PacketRow>,

    pub metrics: Metrics,
    pub kernel: KernelInfo,
}

impl AppState {
    pub fn new() -> Self {
        let metrics = Metrics {
            packets_per_sec: signal!(0u32),
            bytes_per_sec: signal!(0u32),
            drops_per_sec: signal!(0u32),
            pass_total: signal!(0u32),
            drop_total: signal!(0u32),
            spike_total: signal!(0u32),
            block_total: signal!(0u32),
            bytes_total: signal!(0u64),
            rate_history: signal!(Vec::<f32>::new()),
            window_packets: Rc::new(Cell::new(0)),
            window_bytes: Rc::new(Cell::new(0)),
            window_drops: Rc::new(Cell::new(0)),
            next_id: Rc::new(Cell::new(1)),
        };

        let app = Self {
            conn: signal!(ConnStatus::Connecting),
            packets: signal_vec(Vec::new()),
            visible: signal_vec(Vec::new()),
            filter_kind: signal!(Option::<PktKind>::None),
            filter_query: signal!(String::new()),
            auto_scroll: signal!(true),
            selected: signal!(None),
            map_nodes: signal_vec(Vec::new()),
            rules: signal_vec(Vec::new()),
            fw_error: signal!(String::new()),
            banned: signal!(false),
            toasts: signal_vec(Vec::new()),
            metrics,
            kernel: KernelInfo {
                bridge: signal!("sim".to_string()),
                attached: signal!(false),
            },
        };

        app.install_filter();
        app.install_metrics_tick();
        app
    }

    /// Derive `visible` from `packets` + the active filters.
    fn install_filter(&self) {
        let packets = self.packets.clone();
        let visible = self.visible.clone();
        let kind = self.filter_kind;
        let query = self.filter_query;

        effect!(move || {
            let want_kind = kind.get();
            let q = query.get().to_ascii_lowercase();
            let source = packets.get();

            let mut out: Vec<PacketRow> = source
                .into_iter()
                .filter(|e| want_kind.map_or(true, |k| e.kind == k))
                .filter(|e| q.is_empty() || e.haystack.contains(&q))
                .collect();

            if out.len() > VISIBLE_TRIM_AT {
                let excess = out.len() - VISIBLE_KEEP;
                out.drain(..excess);
            }

            visible.with_mut(|v| *v = out);
        });
    }

    /// 1 Hz metrics tick: drain the hot-path counters into display signals
    /// and push a sparkline sample.
    fn install_metrics_tick(&self) {
        let app = self.clone();

        let _interval = gloo_timers::callback::Interval::new(1_000, move || {
            let packets = app.metrics.window_packets.replace(0);
            let bytes = app.metrics.window_bytes.replace(0);
            let drops = app.metrics.window_drops.replace(0);

            app.metrics.packets_per_sec.set(packets);
            app.metrics.drops_per_sec.set(drops);
            app.metrics
                .bytes_per_sec
                .set(bytes.min(u32::MAX as u64) as u32);
            app.metrics
                .bytes_total
                .update(|t| *t = t.saturating_add(bytes));
            app.metrics.rate_history.update(|h| {
                h.push(packets as f32);
                if h.len() > 60 {
                    h.remove(0);
                }
            });
        });
        // Retained for the app lifetime (dropping would cancel the timer).
        std::mem::forget(_interval);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `HH:MM:SS.mmm` in the browser's local timezone.
pub fn format_time(ts_ms: f64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ts_ms));
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds(),
        d.get_milliseconds()
    )
}


