//! Top status bar: brand, kernel bridge state, and stream health.

use velo::prelude::*;

use crate::state::AppState;

#[component]
pub fn TopBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let conn = app.conn;
    let conn_css = memo!(move || format!("conn-dot {}", conn.get().css()));
    let conn_label = memo!(move || conn.get().label().to_string());
    let endpoint = crate::api::STREAM_PATH;

    let bridge = app.kernel.bridge;
    let attached = app.kernel.attached;
    let kernel_label =
        memo!(move || format!("KERNEL:{} {}", bridge.get(), if attached.get() { "XDP" } else { "SIM" }));

    view! {
        <header class="topbar">
            <div class="brand">
                <span class="brand-mark">"⬢"</span>
                <span class="brand-name">"LUXSHIELD"</span>
                <span class="brand-sub">"XDP NETWORK SHIELD"</span>
            </div>
            <div class="topbar-status">
                <span class="mode-badge">{ kernel_label }</span>
                <span class="conn">
                    <span class={ conn_css }></span>
                    <span class="conn-text">{ conn_label }</span>
                </span>
                <code class="stream-endpoint">{ endpoint }</code>
            </div>
        </header>
    }
}

/// Ban banner: shown when the backend answers 401/403 — bad API key or this
/// viewer is WAF/firewall-banned (which blocks every endpoint, stream
/// included). Unban via `DELETE /api/v1/firewall/rules?ip=…` (or MCP).
#[component]
pub fn BanBanner() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let banned = app.banned;

    view! {
        <div
            class="ban-banner"
            style:display={ move || if banned.get() { "block".to_string() } else { "none".to_string() } }
        >
            "⛔ 403 — bad API key or this viewer is banned. The stream and all endpoints stay blocked until unbanned: "
            <code>"DELETE /api/v1/firewall/rules?ip=…"</code>
        </div>
    }
}
