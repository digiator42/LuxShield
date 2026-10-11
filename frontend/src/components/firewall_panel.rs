//! Firewall panel: active blocklist rules (REST-polled) plus an add-rule
//! form that pushes straight into the kernel map via the backend.

use veloasm::prelude::*;

use crate::api;
use crate::state::{format_time, AppState, Rule};

/// Poll the rules endpoint every few seconds; first paint happens on mount.
fn start_rules_poll(app: AppState) {
    let refresh = move || {
        let app = app.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match api::get_rules().await {
                Ok(rules) => {
                    app.fw_error.set(String::new());
                    app.banned.set(false);
                    app.rules.with_mut(|v| *v = rules);
                }
                Err(e) => {
                    // Surface connectivity problems without wiping last-good data.
                    if e.is_forbidden() {
                        app.banned.set(true);
                    }
                    app.fw_error.set(format!("rules sync: {e}"));
                }
            }
        });
    };

    refresh();
    let tick = refresh.clone();
    let _interval = gloo_timers::callback::Interval::new(5_000, move || tick());
    std::mem::forget(_interval);
}

#[component]
pub fn FirewallPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let rules_list = app.rules.clone();
    let rules_empty = app.rules.clone();
    let rules_count = app.rules.clone();
    let count_label = memo!(move || format!("{} active", rules_count.len()));
    let is_empty = memo!(move || rules_empty.len() == 0);

    let ip_input = signal!(String::new());
    let reason_input = signal!(String::new());
    let fw_error = app.fw_error;

    start_rules_poll(app.clone());

    let node = view! {
        <section class="panel firewall">
            <div class="panel-head">
                <h2 class="panel-title">"Firewall"</h2>
                <span class="panel-meta">{ count_label }</span>
            </div>

            <div class="fw-list">
                {
                    move || if is_empty.get() {
                        view! { <div class="fw-empty">"No active rules. Drops from the stream auto-appear here once the backend syncs them."</div> }
                    } else {
                        DomNode::empty()
                    }
                }
                {
                    for r in rules_list key = |r: &Rule| r.ip.clone() {
                        <RuleCard rule={ r.clone() } />
                    }
                }
            </div>

            <div class="fw-form">
                <input
                    type="text"
                    class="fw-input"
                    placeholder="IP to block…"
                    bind:value={ ip_input }
                />
                <input
                    type="text"
                    class="fw-input"
                    placeholder="reason…"
                    bind:value={ reason_input }
                />
                <button
                    class="btn-accent"
                    on:click={ move |_| {
                        let ip = ip_input.get().trim().to_string();
                        if ip.is_empty() {
                            return;
                        }
                        let reason = reason_input.get().trim().to_string();
                        let app = app.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            match api::post_rule(&ip, 0, &reason).await {
                                Ok(()) => {
                                    ip_input.set(String::new());
                                    reason_input.set(String::new());
                                    match api::get_rules().await {
                                        Ok(rules) => {
                                            app.fw_error.set(String::new()); app.banned.set(false);
                                            app.rules.with_mut(|v| *v = rules);
                                        }
                                        Err(e) => { if e.is_forbidden() { app.banned.set(true); } app.fw_error.set(e.to_string()) },
                                    }
                                }
                                Err(e) => { if e.is_forbidden() { app.banned.set(true); } app.fw_error.set(e.to_string()) },
                            }
                        });
                    }}>
                    "Block IP"
                </button>
            </div>
            <div class="fw-err">{ fw_error }</div>
        </section>
    };

    node
}

#[component]
pub fn RuleCard(rule: Rule) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let ip = rule.ip.clone();
    let reason = if rule.reason.is_empty() {
        "-".to_string()
    } else {
        rule.reason.clone()
    };
    let meta = format!(
        "/{} · by {} · {} · {}",
        rule.prefix_len,
        rule.added_by,
        format_time(rule.added_at_ms),
        if rule.kernel_synced {
            "kernel-synced"
        } else {
            "user-space only"
        }
    );

    view! {
        <div class="fw-card">
            <div class="fw-head">
                <span class="fw-ip">{ rule.ip }</span>
                <button
                    class="fw-del"
                    title="remove rule"
                    on:click={ move |_| {
                        let app = app.clone();
                        let ip = ip.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            match api::delete_rule(&ip).await {
                                Ok(_) => match api::get_rules().await {
                                    Ok(rules) => {
                                        app.fw_error.set(String::new()); app.banned.set(false);
                                        app.rules.with_mut(|v| *v = rules);
                                    }
                                    Err(e) => { if e.is_forbidden() { app.banned.set(true); } app.fw_error.set(e.to_string()) },
                                },
                                Err(e) => { if e.is_forbidden() { app.banned.set(true); } app.fw_error.set(e.to_string()) },
                            }
                        });
                    }}>
                    "×"
                </button>
            </div>
            <div class="fw-reason">{ reason }</div>
            <div class="fw-meta">{ meta }</div>
        </div>
    }
}



