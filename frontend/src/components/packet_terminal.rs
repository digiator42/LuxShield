//! Live packet terminal: keyed, fine-grained rows over the filtered stream.
//!
//! Rows are appended by the keyed reconciler (only new nodes are created) and
//! trimmed in batches (see `VISIBLE_TRIM_AT`). Clicking a row opens
//! [`PacketDetail`] with the full record.

use velo::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::Event;

use crate::state::{format_time, AppState, PacketRow};

/// One terminal line. Takes the whole row as an owned prop so the keyed
/// `for` body can pass `row.clone()` — `view!` expression slots are `move`
/// closures and must not borrow the loop variable.
#[component]
pub fn PktRow(row: PacketRow) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let row_clone = row.clone();
    let selected = app.selected;
    let row_id = row.id;

    let row_class = class_names!("pkt-row", row.kind.css());
    let time = format_time(row.ts_ms);
    let kind_class = class_names!("pkt-kind", format!("kind-{}", row.kind.css()));
    let kind_text = row.kind.as_str().to_string();
    let meta = if row.port > 0 {
        format!("{}:{} {}", row.ip, row.port, row.protocol)
    } else {
        format!("{} {}", row.ip, row.protocol)
    };
    let msg = if row.reason.is_empty() {
        format!("{} · {} B · {}", row.action, row.bytes, row.source)
    } else {
        format!("{} · {}", row.action, row.reason)
    };
    let title = format!("{}:{}", row.ip, row.port);

    view! {
        <div
            class={ row_class }
            class:pkt-row-selected={ move || selected.get().as_ref().map(|r| r.id) == Some(row_id) }
            title={ title }
            on:click={ move |_| {
                selected.set(Some(row_clone.clone()));
            } }
        >
            <span class="pkt-time">{ time }</span>
            <span class={ kind_class }>{ kind_text }</span>
            <span class="pkt-meta">{ meta }</span>
            <span class="pkt-msg">{ msg }</span>
        </div>
    }
}

/// Packet detail modal showing the full record for the selected row.
#[component]
pub fn PacketDetail() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let selected = app.selected;

    view! {
        <div
            class="pkt-detail-overlay"
            style:display={ move || if selected.get().is_some() { "flex".to_string() } else { "none".to_string() } }
            on:click={ move |_| selected.set(None) }
        >
            <div class="pkt-detail-panel" on:click={ move |ev| {
                let ev = ev.dyn_ref::<web_sys::Event>().unwrap();
                ev.stop_propagation();
            }}>
                {
                    move || {
                        if let Some(row) = selected.get() {
                            let time = format_time(row.ts_ms);
                            let kind_text = row.kind.as_str().to_string();
                            let kind_css = format!("pkt-detail-value pkt-kind kind-{}", row.kind.css());
                            view! {
                                <div class="pkt-detail-content">
                                    <div class="pkt-detail-header">
                                        <h3 class="pkt-detail-title">"Packet Details"</h3>
                                        <button
                                            class="pkt-detail-close"
                                            on:click={ move |_| selected.set(None) }
                                        >"×"</button>
                                    </div>
                                    <div class="pkt-detail-body">
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Timestamp:"</span>
                                            <span class="pkt-detail-value">{ time }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Kind:"</span>
                                            <span class={ kind_css }>{ kind_text }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Source IP:"</span>
                                            <span class="pkt-detail-value">{ row.ip.clone() }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Port / Proto:"</span>
                                            <span class="pkt-detail-value">{ format!("{} / {}", row.port, row.protocol.clone()) }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Action:"</span>
                                            <span class="pkt-detail-value">{ row.action.clone() }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Bytes:"</span>
                                            <span class="pkt-detail-value">{ format!("{}", row.bytes) }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Reason:"</span>
                                            <span class="pkt-detail-value">{ if row.reason.is_empty() { "-".to_string() } else { row.reason.clone() } }</span>
                                        </div>
                                        <div class="pkt-detail-row">
                                            <span class="pkt-detail-label">"Source:"</span>
                                            <span class="pkt-detail-value">{ row.source.clone() }</span>
                                        </div>
                                    </div>
                                </div>
                            }
                        } else {
                            view! { <div></div> }
                        }
                    }
                }
            </div>
        </div>
    }
}

#[component]
pub fn PacketTerminal() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    // `SignalVec` is cheap (Rc-backed) but not `Copy` — give each `move`
    // closure below its own handle.
    let for_list = app.visible.clone();
    let count_list = app.visible.clone();
    let empty_list = app.visible.clone();
    let scroll_list = app.visible.clone();
    let auto_scroll = app.auto_scroll;

    let shown = memo!(move || format!("{}", count_list.len()));
    let is_empty = memo!(move || empty_list.len() == 0);
    let stick = app.auto_scroll;

    let node = view! {
        <section class="panel terminal">
            <div class="panel-head">
                <h2 class="panel-title">"Packet Terminal"</h2>
                <span class="panel-meta">{ shown } " records in view"</span>
                <button
                    class="btn-ghost"
                    style:display={ move || if stick.get() { "none".to_string() } else { "inline-block".to_string() } }
                    on:click={ move |_| {
                        stick.set(true);
                        scroll_to_bottom();
                    }}>
                    "↓ latest"
                </button>
            </div>

            <div
                class="term-body"
                id="packet-terminal"
                on:scroll={ move |ev: Event| {
                    // Stick-to-bottom: scrolling up pauses auto-scroll so old
                    // traces stay put; scrolling back to the bottom resumes it.
                    let Some(target) = ev.target() else { return; };
                    let Ok(el) = target.dyn_into::<web_sys::HtmlElement>() else { return; };
                    let gap = el.scroll_height() - el.scroll_top() - el.client_height();
                    stick.set(gap < 32);
                } }
            >
                {
                    move || if is_empty.get() {
                        view! { <div class="term-empty">"No packets yet. The live stream connects on load."</div> }
                    } else {
                        DomNode::empty()
                    }
                }
                {
                    for r in for_list key = |r: &PacketRow| r.id {
                        <PktRow row={ r.clone() } />
                    }
                }
            </div>
        </section>
    };

    // Auto-scroll effect. Created *after* `view!` — and therefore after the
    // keyed reconciler's effect — so on every list change the DOM is already
    // updated when we measure scrollHeight. Reading `len()` subscribes it.
    effect!(move || {
        let _rows = scroll_list.len();
        if auto_scroll.get() {
            scroll_to_bottom();
        }
    });

    node
}

/// Jump the terminal viewport to the newest row (no-op before mount).
fn scroll_to_bottom() {
    if let Some(el) = document().get_element_by_id("packet-terminal") {
        el.set_scroll_top(el.scroll_height());
    }
}
