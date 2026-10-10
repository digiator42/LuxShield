//! Web Worker offload for packet aggregation.
//!
//! The UI thread parses SSE records and renders rows directly (cheap at
//! stream rates), but per-IP aggregation for the traffic map — counting,
//! burst scoring, pruning — runs in a dedicated worker over the *same* wasm
//! module. The main thread posts compact scored rows; the worker posts back
//! throttled map snapshots (≤1/sec) so the canvas never drowns in messages.
//!
//! The worker is bootstrapped by `webworker.js` (copied to the dist root by
//! Trunk), which imports the same wasm module and calls the `#[wasm_bindgen]`
//! entry points below. `main()` in [`crate::lib`] detects the worker context
//! via a missing `window` and skips mounting the app there.

use std::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::state::{AppState, MapNode, PacketRow, MAP_KEEP};

// ---------------------------------------------------------------------------
// Worker-side engine (runs off the UI thread)
// ---------------------------------------------------------------------------

/// Rows crossing into the worker: only the fields aggregation needs.
#[derive(Deserialize)]
struct ScoreRow {
    ip: String,
    kind: String,
    bytes: u32,
    ts_ms: f64,
}

#[derive(Default)]
struct Agg {
    packets: u64,
    drops: u64,
    bytes: u64,
    last_ts_ms: f64,
    /// Timestamps (ms) of recent packets for burst scoring.
    window: Vec<f64>,
}

/// Packets in the trailing window that flag a bursty source.
const BURST_WINDOW_MS: f64 = 5_000.0;
const BURST_THRESHOLD: usize = 50;
/// Idle IPs are pruned after this long.
const PRUNE_AFTER_MS: f64 = 60_000.0;
/// Hard cap on tracked IPs (evict stalest first).
const IP_CAP: usize = 500;
/// Minimum gap between snapshots posted to the main thread.
const SNAPSHOT_GAP_MS: f64 = 1_000.0;

thread_local! {
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::new());
}

struct Engine {
    table: HashMap<String, Agg>,
    last_snapshot_ms: f64,
}

impl Engine {
    fn new() -> Self {
        Self {
            table: HashMap::new(),
            last_snapshot_ms: 0.0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Score rows; returns true when a snapshot is due. Snapshotting is done
    /// by the caller so the engine borrow is released first.
    fn score(&mut self, rows: &[ScoreRow], now_ms: f64) -> bool {
        for row in rows {
            if row.ip.is_empty() {
                continue;
            }
            let agg = self.table.entry(row.ip.clone()).or_default();
            agg.packets += 1;
            agg.bytes += row.bytes as u64;
            agg.last_ts_ms = row.ts_ms;
            if row.kind == "drop" || row.kind == "block" {
                agg.drops += 1;
            }
            agg.window.push(row.ts_ms);
        }

        // Prune + cap.
        if self.table.len() > IP_CAP {
            let mut ips: Vec<(String, f64)> = self
                .table
                .iter()
                .map(|(ip, a)| (ip.clone(), a.last_ts_ms))
                .collect();
            ips.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            let excess = self.table.len() - IP_CAP;
            for (ip, _) in ips.into_iter().take(excess) {
                self.table.remove(&ip);
            }
        }
        self.table
            .retain(|_, a| now_ms - a.last_ts_ms < PRUNE_AFTER_MS);

        // Throttled snapshot.
        if now_ms - self.last_snapshot_ms >= SNAPSHOT_GAP_MS {
            self.last_snapshot_ms = now_ms;
            return true;
        }
        false
    }
}

fn burst(agg: &mut Agg, now_ms: f64) -> bool {
    agg.window
        .retain(|ts| now_ms - *ts <= BURST_WINDOW_MS);
    agg.window.len() >= BURST_THRESHOLD
}

/// A snapshot crossing the worker boundary, tagged for the dispatcher.
#[derive(Serialize)]
struct Snapshot<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    nodes: &'a [MapNode],
}

fn post_snapshot(now_ms: f64) {
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        let mut nodes: Vec<MapNode> = Vec::with_capacity(e.table.len());
        for (ip, agg) in e.table.iter_mut() {
            nodes.push(MapNode {
                ip: ip.clone(),
                packets: agg.packets,
                drops: agg.drops,
                bytes: agg.bytes,
                burst: burst(agg, now_ms),
                last_ts_ms: agg.last_ts_ms,
            });
        }
        // Heaviest talkers first; the map renders the head.
        nodes.sort_by(|a, b| {
            (b.packets + b.drops * 10)
                .cmp(&(a.packets + a.drops * 10))
        });
        nodes.truncate(MAP_KEEP);
        let msg = serde_json::to_string(&Snapshot {
            kind: "snapshot",
            nodes: &nodes,
        })
        .unwrap_or_default();
        if !msg.is_empty() {
            js_sys::global()
                .dyn_ref::<web_sys::DedicatedWorkerGlobalScope>()
                .map(|scope| scope.post_message(&JsValue::from_str(&msg)));
        }
    });
}

/// Score one JSON batch of rows; called by `webworker.js` for every
/// `{type:"score"}` control message.
#[wasm_bindgen]
pub fn worker_score(json: &str) {
    #[derive(Deserialize)]
    struct ScoreBatch {
        rows: Vec<ScoreRow>,
    }
    let Ok(batch) = serde_json::from_str::<ScoreBatch>(json) else {
        return;
    };
    if batch.rows.is_empty() {
        return;
    }
    let now_ms = js_sys::Date::now();
    let due = ENGINE.with(|e| e.borrow_mut().score(&batch.rows, now_ms));
    if due {
        post_snapshot(now_ms);
    }
}

/// Initialize (or re-initialize) the worker engine. Called once by
/// `webworker.js` immediately after the wasm module boots.
#[wasm_bindgen]
pub fn worker_start() {
    ENGINE.with(|e| e.borrow_mut().reset());
}

/// Drop all buffered aggregation state.
#[wasm_bindgen]
pub fn worker_reset() {
    ENGINE.with(|e| e.borrow_mut().reset());
}

// ---------------------------------------------------------------------------
// Main-thread orchestration
// ---------------------------------------------------------------------------

thread_local! {
    /// The single long-lived aggregation worker (created on connect).
    static WORKER: RefCell<Option<web_sys::Worker>> = const { RefCell::new(None) };
}

/// Messages the worker posts back to the main thread.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WorkerMsg {
    Ready,
    Snapshot { nodes: Vec<MapNode> },
}

/// Compact row encoding posted to the worker.
#[derive(Serialize)]
struct OutRow<'a> {
    ip: &'a str,
    kind: &'a str,
    bytes: u32,
    ts_ms: f64,
}

/// Forward freshly ingested rows to the worker for aggregation.
pub fn score_rows(rows: &[PacketRow]) {
    let compact: Vec<OutRow> = rows
        .iter()
        .filter(|r| !r.ip.is_empty())
        .map(|r| OutRow {
            ip: &r.ip,
            kind: r.kind.css(),
            bytes: r.bytes,
            ts_ms: r.ts_ms,
        })
        .collect();
    if compact.is_empty() {
        return;
    }
    let msg = serde_json::json!({ "type": "score", "rows": compact }).to_string();
    WORKER.with(|slot| {
        if let Some(worker) = slot.borrow().as_ref() {
            let _ = worker.post_message(&JsValue::from_str(&msg));
        }
    });
}

/// Lazily create the worker and wire its message handler.
pub fn ensure_worker(app: &AppState) {
    WORKER.with(|slot| {
        if slot.borrow().is_some() {
            return;
        }
        let Some(worker) = create_worker(app) else {
            web_sys::console::error_1(&"cannot start aggregation worker".into());
            return;
        };
        *slot.borrow_mut() = Some(worker);
    });
}

fn create_worker(app: &AppState) -> Option<web_sys::Worker> {
    let document = web_sys::window()?.document()?;

    // Trunk emits `<link rel="modulepreload" href=".../<hash>.js">`; the worker
    // imports that same module so the hashed filename never needs hardcoding.
    let js_url = document
        .query_selector("link[rel=modulepreload]")
        .ok()
        .flatten()
        .and_then(|el| el.get_attribute("href"))?;

    let options = web_sys::WorkerOptions::new();
    options.set_type(web_sys::WorkerType::Module);
    let worker = web_sys::Worker::new_with_options("webworker.js", &options).ok()?;

    let app = app.clone();
    let on_message = wasm_bindgen::closure::Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        let Some(raw) = ev.data().as_string() else {
            return;
        };
        match serde_json::from_str::<WorkerMsg>(&raw) {
            Ok(WorkerMsg::Snapshot { nodes }) => {
                app.map_nodes.with_mut(|v| *v = nodes);
            }
            Ok(WorkerMsg::Ready) => {
                web_sys::console::debug_1(&"aggregation worker ready".into());
            }
            Err(err) => {
                web_sys::console::warn_1(&format!("bad worker message: {err}").into())
            }
        }
    }) as Box<dyn FnMut(web_sys::MessageEvent)>);
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    // Hand the worker the module + wasm URLs it should import. The wasm URL is
    // explicit because Trunk hashes the filename, which wasm-bindgen's default
    // `import.meta.url`-relative path would miss.
    let wasm_url = wasm_url(&document, &js_url);
    let init = format!(
        "{{\"type\":\"init\",\"jsUrl\":{},\"wasmUrl\":{}}}",
        json_string(&js_url),
        json_string(&wasm_url)
    );
    let _ = worker.post_message(&JsValue::from_str(&init));

    Some(worker)
}

/// Resolve the hashed `_bg.wasm` URL, preferring Trunk's `<link rel="preload">`.
fn wasm_url(document: &web_sys::Document, js_url: &str) -> String {
    if let Ok(Some(el)) = document.query_selector("link[rel=preload][as=fetch]") {
        if let Some(href) = el.get_attribute("href") {
            return href;
        }
    }
    js_url
        .strip_suffix(".js")
        .map(|base| format!("{base}_bg.wasm"))
        .unwrap_or_else(|| js_url.to_string())
}

/// Minimal JSON string encoder for the one value we hand to the worker.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
