//! Real-time metrics strip: packet rate, drops, bandwidth, and a rolling
//! packets/sec sparkline chart.

use veloasm::prelude::*;

use crate::state::AppState;

/// Map a history window onto SVG polyline coordinates (120×36 viewBox).
fn sparkline_points(history: &[f32]) -> String {
    if history.is_empty() {
        return String::new();
    }
    let max = history.iter().copied().fold(1.0f32, f32::max);
    let n = history.len();
    history
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = if n == 1 {
                120.0
            } else {
                i as f32 * 120.0 / (n - 1) as f32
            };
            // Invert: SVG y grows downward, chart bars grow upward.
            let y = 34.0 - (v / max) * 32.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[component]
pub fn MetricsBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let pps = app.metrics.packets_per_sec;
    let drops = app.metrics.drop_total;
    let drops_sec = app.metrics.drops_per_sec;
    let blocks = app.metrics.block_total;

    let bandwidth = memo!(move || {
        let bps = app.metrics.bytes_per_sec.get();
        if bps >= 1_000_000 {
            format!("{:.2} MB/s", bps as f64 / 1_000_000.0)
        } else {
            format!("{:.1} KB/s", bps as f64 / 1024.0)
        }
    });
    let total_bytes = memo!(move || {
        let b = app.metrics.bytes_total.get();
        if b >= 1_000_000_000 {
            format!("{:.2} GB", b as f64 / 1_000_000_000.0)
        } else if b >= 1_000_000 {
            format!("{:.1} MB", b as f64 / 1_000_000.0)
        } else {
            format!("{:.0} KB", b as f64 / 1024.0)
        }
    });

    let history = app.metrics.rate_history;
    let points = memo!(move || sparkline_points(&history.get()));

    view! {
        <section class="metrics">
            <div class="metric-tile">
                <span class="metric-label">"PACKETS / SEC"</span>
                <span class="metric-value">{ pps }</span>
                <span class="metric-sub">"drops/sec " { drops_sec }</span>
            </div>

            <div class="metric-tile">
                <span class="metric-label">"XDP DROPS"</span>
                <span class="metric-value metric-danger">{ drops }</span>
                <span class="metric-sub">"blocked " { blocks }</span>
            </div>

            <div class="metric-tile">
                <span class="metric-label">"BANDWIDTH"</span>
                <span class="metric-value metric-small">{ bandwidth }</span>
                <span class="metric-sub">"session " { total_bytes }</span>
            </div>

            <div class="metric-tile metric-spark">
                <span class="metric-label">"TRAFFIC · 60s"</span>
                <svg class="sparkline" viewBox="0 0 120 36" preserveAspectRatio="none">
                    <polyline class="sparkline-line" points={ points } fill="none" />
                </svg>
            </div>
        </section>
    }
}

