//! Ingestion pipeline — the single funnel every packet record flows through.
//!
//! SSE batches arrive as parsed [`NetEvent`]s, get stamped, converted to
//! capped terminal rows, counted into metrics, and promoted (drops, spikes,
//! blocks) to flash toasts. Raw JSON strings are additionally forwarded to
//! the worker thread for per-IP aggregation ([`crate::worker`]).

use gloo_timers::future::TimeoutFuture;

use crate::state::{
    AppState, NetEvent, PacketRow, PktKind, RAW_KEEP, RAW_TRIM_AT, TOAST_KEEP, TOAST_TTL_MS,
};
use crate::worker;

/// Run one batch of network events through state on the main thread.
pub fn ingest_events(app: &AppState, events: Vec<NetEvent>) {
    if events.is_empty() {
        return;
    }

    let mut rows: Vec<PacketRow> = Vec::with_capacity(events.len());
    let mut toast_ids: Vec<u64> = Vec::new();

    for mut ev in events {
        if ev.ts_ms <= 0.0 {
            ev.ts_ms = js_sys::Date::now();
        }
        let kind = PktKind::parse(&ev.kind);
        let id = app.metrics.next_row_id();

        let ip = ev.ip.clone().unwrap_or_default();
        let protocol = ev.protocol.clone().unwrap_or_default();
        let reason = ev.reason.clone().unwrap_or_default();
        let action = ev
            .action
            .clone()
            .unwrap_or_else(|| match kind {
                PktKind::Drop | PktKind::Block => "drop".to_string(),
                _ => "pass".to_string(),
            });
        let haystack = format!(
            "{} {} {} {} {}",
            ip.to_ascii_lowercase(),
            protocol.to_ascii_lowercase(),
            reason.to_ascii_lowercase(),
            action.to_ascii_lowercase(),
            ev.source.to_ascii_lowercase()
        );

        // Hot-path counters (drained once per metrics tick).
        let bytes = ev.bytes.unwrap_or(0);
        app.metrics
            .window_packets
            .set(app.metrics.window_packets.get().saturating_add(1));
        app.metrics
            .window_bytes
            .set(app.metrics.window_bytes.get().saturating_add(bytes as u64));
        match kind {
            PktKind::Drop => {
                app.metrics
                    .window_drops
                    .set(app.metrics.window_drops.get().saturating_add(1));
                app.metrics.drop_total.update(|t| *t += 1);
                toast_ids.push(id);
            }
            PktKind::Spike => {
                app.metrics.spike_total.update(|t| *t += 1);
                toast_ids.push(id);
            }
            PktKind::Block => {
                app.metrics.block_total.update(|t| *t += 1);
                toast_ids.push(id);
            }
            PktKind::Packet => {
                app.metrics.pass_total.update(|t| *t += 1);
            }
        }

        rows.push(PacketRow {
            id,
            ts_ms: ev.ts_ms,
            kind,
            ip,
            port: ev.port.unwrap_or(0),
            protocol,
            bytes,
            action,
            reason,
            source: std::mem::take(&mut ev.source),
            haystack,
        });
    }

    // Sorted insert — one notification for the whole batch.
    //
    // The stream replays `history` newest-first, then live records (see
    // `docs/api.md`), so blind appends would scramble chronology on every
    // (re)connect. Rows are inserted in `ts_ms` order; the buffer stays
    // oldest-first and eviction drops the oldest from the front.
    app.packets.with_mut(|v| {
        for row in rows.iter() {
            let pos = v.partition_point(|r: &PacketRow| r.ts_ms <= row.ts_ms);
            v.insert(pos, row.clone());
        }
        if v.len() > RAW_TRIM_AT {
            let excess = v.len() - RAW_KEEP;
            v.drain(..excess);
        }
    });

    // Flash toasts for drops / spikes / blocks, auto-dismissed.
    for row in rows.iter().filter(|r| toast_ids.contains(&r.id)) {
        push_toast(app, row.clone());
    }

    // Forward raw events to the worker for map aggregation.
    worker::score_rows(&rows);
}

/// Push a toast row, cap the stack, and schedule its dismissal.
fn push_toast(app: &AppState, row: PacketRow) {
    let id = row.id;
    app.toasts.with_mut(|v| {
        v.push(row);
        while v.len() > TOAST_KEEP {
            v.remove(0);
        }
    });

    let toasts = app.toasts.clone();
    wasm_bindgen_futures::spawn_local(async move {
        TimeoutFuture::new(TOAST_TTL_MS).await;
        toasts.with_mut(|v| {
            if let Some(pos) = v.iter().position(|t| t.id == id) {
                v.remove(pos);
            }
        });
    });
}
