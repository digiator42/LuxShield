//! LuxShield console — XDP/eBPF network shield dashboard.
//!
//! One codebase exercising Velo features end-to-end:
//!
//! - SSE packet feed (`EventSource` bridge in [`net`]) with named events
//!   (`packet` | `drop` | `spike` | `block`) feeding a keyed packet terminal
//! - [`worker`] — Web Worker aggregation (per-IP counts, burst scoring) for
//!   the traffic map, keeping scoring off the UI thread
//! - Canvas attack-vector map rendered at display refresh rate
//! - Firewall panel driving `POST/DELETE /api/v1/firewall/rules`
//! - `<Show>`, `class:` toggles, `bind:value` / `bind:checked` — filters,
//!   stream switch, auto-scroll

use velo::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

mod api;
mod components;
mod ingest;
mod net;
mod state;
mod worker;

use crate::components::*;
use crate::state::AppState;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    // The same wasm module is instantiated inside the aggregation Web Worker.
    // There is no `window` there, so skip mounting the dashboard; the worker
    // is driven by the `worker::worker_*` entry points instead.
    if web_sys::window().is_none() {
        return;
    }
    run_app();
}

pub fn run_app() {
    // Seed global context before mounting so every component can pull the
    // shared state with `use_context::<AppState>()`.
    let app = AppState::new();
    provide!(app.clone());

    // Spin up the aggregation worker, open the SSE stream, and sync the
    // kernel/health status once (then on an interval).
    worker::ensure_worker(&app);
    net::connect(&app);
    poll_health(&app);

    let shell = view! {
        <div class="app-shell">
            <TopBar />
            <BanBanner />
            <MetricsBar />
            <ControlPanel />

            <main class="layout">
                <div class="col-main">
                    <TrafficMap />
                    <PacketTerminal />
                </div>
                <aside class="col-side">
                    <FirewallPanel />
                </aside>
            </main>

            <ToastStack />
            <PacketDetail />
        </div>
    };
    mount(shell);
}

/// Poll `/health` + `/stats` for kernel bridge state and session totals.
fn poll_health(app: &AppState) {
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(async move {
        match api::get_health().await {
            Ok((ring, bridge, attached)) => {
                app.banned.set(false);
                app.kernel.bridge.set(if bridge.is_empty() {
                    ring.clone()
                } else {
                    bridge
                });
                app.kernel.attached.set(attached);
            }
            Err(e) => {
                if e.is_forbidden() {
                    app.banned.set(true);
                }
                web_sys::console::warn_1(&format!("health poll: {e}").into());
            }
        }
        match api::get_stats().await {
            Ok(s) => {
                app.metrics.pass_total.set(s.pass_total);
                app.metrics.drop_total.set(s.drop_total);
                app.metrics.spike_total.set(s.spike_total);
                app.metrics.block_total.set(s.block_total);
                app.metrics.bytes_total.set(s.bytes_total);
            }
            Err(e) => {
                web_sys::console::warn_1(&format!("stats poll: {e}").into());
            }
        }
    });

    let tick = app.clone();
    let _interval = gloo_timers::callback::Interval::new(10_000, move || {
        let tick = tick.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok((ring, bridge, attached)) = api::get_health().await {
                tick.kernel.bridge.set(if bridge.is_empty() {
                    ring.clone()
                } else {
                    bridge
                });
                tick.kernel.attached.set(attached);
            }
        });
    });
    std::mem::forget(_interval);
}
