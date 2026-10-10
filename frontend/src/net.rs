//! SSE client: bridges LuxShield's live packet stream into reactive state.
//!
//! Wraps `web_sys::EventSource` — the browser handles automatic reconnection
//! backoff natively, so this module only tracks connection status and forwards
//! decoded events into [`ingest`](crate::ingest). The backend emits one named
//! event per record kind: `packet` | `drop` | `spike` | `block`.

use std::cell::RefCell;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::EventSource;

use crate::api;
use crate::ingest;
use crate::state::{AppState, ConnStatus, NetEvent};

thread_local! {
    /// The active stream, if any. `EventSource` is not `Clone`, so it lives
    /// behind a `RefCell` rather than inside `AppState`.
    static SOURCE: RefCell<Option<EventSource>> = const { RefCell::new(None) };
}

/// Named SSE events the backend emits (one per record kind).
const KINDS: [&str; 4] = ["packet", "drop", "spike", "block"];

/// Open the stream (closing any previous one first). Idempotent.
pub fn connect(app: &AppState) {
    disconnect();
    app.conn.set(ConnStatus::Connecting);

    let url = api::stream_url();
    let source = match EventSource::new(&url) {
        Ok(s) => s,
        Err(err) => {
            web_sys::console::error_1(&format!("SSE open failed: {err:?}").into());
            app.conn.set(ConnStatus::Closed);
            return;
        }
    };

    // --- onopen: mark the feed healthy -------------------------------------
    let on_open = {
        let conn = app.conn;
        Closure::wrap(Box::new(move || conn.set(ConnStatus::Open)) as Box<dyn FnMut()>)
    };
    source.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    on_open.forget();

    // --- onerror: EventSource retries on its own; surface the state --------
    let on_error = {
        let conn = app.conn;
        Closure::wrap(Box::new(move || conn.set(ConnStatus::Reconnecting)) as Box<dyn FnMut()>)
    };
    source.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    on_error.forget();

    // --- one listener per named event kind ---------------------------------
    for kind in KINDS {
        let on_event = {
            let app = app.clone();
            Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
                let Some(raw) = event.data().as_string() else {
                    return;
                };
                match serde_json::from_str::<NetEvent>(&raw) {
                    Ok(ev) => ingest::ingest_events(&app, vec![ev]),
                    Err(err) => {
                        web_sys::console::warn_1(
                            &format!("skipping malformed SSE event: {err}").into(),
                        )
                    }
                }
            }) as Box<dyn FnMut(web_sys::MessageEvent)>)
        };

        if let Err(err) =
            source.add_event_listener_with_callback(kind, on_event.as_ref().unchecked_ref())
        {
            web_sys::console::error_1(
                &format!("failed to register '{kind}' listener: {err:?}").into(),
            );
        }
        on_event.forget();
    }

    SOURCE.with(|slot| *slot.borrow_mut() = Some(source));
}

/// Close the stream (no-op when already closed).
pub fn disconnect() {
    SOURCE.with(|slot| {
        if let Some(source) = slot.borrow_mut().take() {
            source.close();
        }
    });
}
