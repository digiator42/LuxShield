//! Stream controls: connect/disconnect, kind filters, and viewport controls.

use veloasm::prelude::*;

use crate::net;
use crate::state::{AppState, PktKind};

#[component]
pub fn ControlPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let conn = app.conn;
    let streaming = memo!(move || conn.get() == crate::state::ConnStatus::Open
        || conn.get() == crate::state::ConnStatus::Connecting
        || conn.get() == crate::state::ConnStatus::Reconnecting);

    let filter_kind = app.filter_kind;
    let auto_scroll = app.auto_scroll;
    let query = app.filter_query.clone();

    let app_conn = app.clone();
    let packets_for_clear = app.packets.clone();

    let packets_count = app.packets.clone();
    let visible_count = app.visible.clone();
    let raw_label = memo!(move || format!("{}", packets_count.len()));
    let shown_label = memo!(move || format!("{}", visible_count.len()));

    view! {
        <section class="controls">
            <div class="controls-group mode-toggle">
                <button
                    class="mode-btn"
                    class:active={ move || streaming.get() }
                    on:click={ move |_| {
                        net::connect(&app_conn);
                    }}>
                    "◉ " "LIVE PACKETS"
                </button>
                <button
                    class="mode-btn"
                    on:click={ move |_| {
                        net::disconnect();
                    }}>
                    "■ " "DISCONNECT"
                </button>
            </div>

            <div class="controls-group chips">
                <button
                    class="chip"
                    class:active={ move || filter_kind.get().is_none() }
                    on:click={ move |_| filter_kind.set(None) }>
                    "ALL"
                </button>
                <button
                    class="chip chip-pass"
                    class:active={ move || filter_kind.get() == Some(PktKind::Packet) }
                    on:click={ move |_| filter_kind.set(Some(PktKind::Packet)) }>
                    "PASS"
                </button>
                <button
                    class="chip chip-drop"
                    class:active={ move || filter_kind.get() == Some(PktKind::Drop) }
                    on:click={ move |_| filter_kind.set(Some(PktKind::Drop)) }>
                    "DROP"
                </button>
                <button
                    class="chip chip-spike"
                    class:active={ move || filter_kind.get() == Some(PktKind::Spike) }
                    on:click={ move |_| filter_kind.set(Some(PktKind::Spike)) }>
                    "SPIKE"
                </button>
                <button
                    class="chip chip-block"
                    class:active={ move || filter_kind.get() == Some(PktKind::Block) }
                    on:click={ move |_| filter_kind.set(Some(PktKind::Block)) }>
                    "BLOCK"
                </button>
            </div>

            <div class="controls-group controls-search">
                <input
                    type="text"
                    class="filter-input"
                    placeholder="filter by IP, protocol, or reason…"
                    bind:value={ query }
                />
                <span class="filter-count">{ shown_label } " / " { raw_label }</span>
            </div>

            <div class="controls-group controls-view">
                <label class="auto-scroll">
                    <input type="checkbox" bind:checked={ auto_scroll } />
                    "Auto-scroll"
                </label>
                <button
                    class="btn-ghost"
                    on:click={ move |_| packets_for_clear.clear() }>
                    "Clear"
                </button>
            </div>
        </section>
    }
}

