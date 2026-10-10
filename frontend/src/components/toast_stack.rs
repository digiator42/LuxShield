//! Flash alerts for drops, spikes and blocks (auto-dismissed).

use velo::prelude::*;

use crate::state::{AppState, PacketRow};

#[component]
pub fn ToastCard(row: PacketRow) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let id = row.id;
    let toasts = app.toasts.clone();

    let card_class = class_names!("toast", format!("sev-{}", row.kind.css()));
    let title = match row.kind {
        crate::state::PktKind::Drop => format!("XDP DROP {}", row.ip),
        crate::state::PktKind::Spike => "Bandwidth spike".to_string(),
        crate::state::PktKind::Block => format!("Blocked {}", row.ip),
        crate::state::PktKind::Packet => format!("Packet {}", row.ip),
    };
    let detail = if row.reason.is_empty() {
        row.source.clone()
    } else {
        row.reason.clone()
    };

    view! {
        <div class={ card_class }>
            <div>
                <div class="toast-title">{ title }</div>
                <div class="toast-detail">{ detail }</div>
            </div>
            <button
                class="toast-close"
                on:click={ move |_| {
                    toasts.with_mut(|v| {
                        if let Some(pos) = v.iter().position(|t| t.id == id) {
                            v.remove(pos);
                        }
                    });
                }}>
                "×"
            </button>
        </div>
    }
}

#[component]
pub fn ToastStack() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let list = app.toasts.clone();

    view! {
        <div class="toasts">
            {
                for t in list key = |t: &PacketRow| t.id {
                    <ToastCard row={ t.clone() } />
                }
            }
        </div>
    }
}
