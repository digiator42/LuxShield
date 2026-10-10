//! Real-time traffic node graph: a 2D canvas rendered at display refresh
//! rate from the worker-maintained [`MapNode`](crate::state::MapNode) table.
//!
//! Layout is deterministic (hash of IP → angle), so frames are cheap: no
//! force simulation, just ring placement. Red = kernel-dropped sources,
//! green = passed traffic, amber ring = bursty source.

use std::cell::RefCell;
use std::rc::Rc;

use velo::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::CanvasRenderingContext2d;

use crate::state::AppState;

const W: f64 = 900.0;
const H: f64 = 300.0;

/// FNV-1a hash of an IP string → stable angle.
fn hash_ip(ip: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in ip.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[component]
pub fn TrafficMap() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let nodes_count = app.map_nodes.clone();
    let count_label = memo!(move || format!("{} sources", nodes_count.len()));

    let node = view! {
        <section class="panel map">
            <div class="panel-head">
                <h2 class="panel-title">"Attack Vector Map"</h2>
                <span class="panel-meta">{ count_label }</span>
            </div>
            <div class="map-wrap">
                <canvas id="traffic-canvas" class="traffic-canvas" width="900" height="300"></canvas>
                <div class="map-legend">
                    <span><span class="legend-dot legend-pass"></span>"passed"</span>
                    <span><span class="legend-dot legend-drop"></span>"xdp drop"</span>
                    <span><span class="legend-dot legend-burst"></span>"burst"</span>
                </div>
            </div>
        </section>
    };

    // Render loop — retained for the app lifetime.
    start_render_loop(app.clone());

    node
}

fn canvas_ctx() -> Option<CanvasRenderingContext2d> {
    let el = document().get_element_by_id("traffic-canvas")?;
    let canvas: web_sys::HtmlCanvasElement = el.dyn_into().ok()?;
    canvas
        .get_context("2d")
        .ok()
        .flatten()
        .and_then(|c| c.dyn_into().ok())
}

fn start_render_loop(app: AppState) {
    let f: Rc<RefCell<Option<wasm_bindgen::closure::Closure<dyn FnMut()>>>> =
        Rc::new(RefCell::new(None));
    let g = f.clone();

    let mut tick: f64 = 0.0;
    *g.borrow_mut() = Some(wasm_bindgen::closure::Closure::wrap(Box::new(move || {
        tick += 1.0;
        draw_frame(&app, tick);

        if let Some(window) = web_sys::window() {
            let _ = window.request_animation_frame(
                f.borrow()
                    .as_ref()
                    .expect("render loop installed")
                    .as_ref()
                    .unchecked_ref(),
            );
        }
    }) as Box<dyn FnMut()>));

    if let Some(window) = web_sys::window() {
        let _ = window.request_animation_frame(
            g.borrow()
                .as_ref()
                .expect("render loop installed")
                .as_ref()
                .unchecked_ref(),
        );
    }
    // Retained for the app lifetime.
    std::mem::forget(g);
}

fn draw_frame(app: &AppState, tick: f64) {
    let Some(ctx) = canvas_ctx() else {
        return;
    };
    let nodes = app.map_nodes.get();

    let cx = W / 2.0;
    let cy = H / 2.0;

    ctx.set_fill_style_str("#0c1118");
    ctx.fill_rect(0.0, 0.0, W, H);

    // Gateway hub.
    ctx.set_fill_style_str("#1a212d");
    ctx.begin_path();
    ctx.arc(cx, cy, 22.0, 0.0, std::f64::consts::TAU)
        .unwrap_or(());
    ctx.fill();
    ctx.set_stroke_style_str("#3ddc97");
    ctx.set_line_width(2.0);
    ctx.stroke();
    ctx.set_fill_style_str("#3ddc97");
    ctx.set_font("11px monospace");
    ctx.set_text_align("center");
    ctx.fill_text("XDP", cx, cy + 4.0).unwrap_or(());

    if nodes.is_empty() {
        ctx.set_fill_style_str("#7d8ba1");
        ctx.fill_text("waiting for packets…", cx, cy + 44.0)
            .unwrap_or(());
        return;
    }

    for n in nodes.iter() {
        let h = hash_ip(&n.ip) as f64 / u64::MAX as f64;
        let angle = h * std::f64::consts::TAU;
        let dropped = n.drops > 0;
        let radius = if dropped { 118.0 } else { 74.0 };
        let x = cx + radius * angle.cos();
        let y = cy + radius * 0.78 * angle.sin();

        let total = n.packets + n.drops;
        let size = (3.0 + (total.min(500) as f64).sqrt() * 0.45).min(11.0);

        // Edge from hub.
        let edge_alpha = if n.burst { 0.85 } else { 0.30 };
        let edge_color = if dropped {
            format!("rgba(255,93,93,{edge_alpha:.2})")
        } else {
            format!("rgba(61,220,151,{edge_alpha:.2})")
        };
        ctx.set_stroke_style_str(&edge_color);
        ctx.set_line_width(if n.burst { 2.0 } else { 1.0 });
        ctx.begin_path();
        ctx.move_to(cx, cy);
        ctx.line_to(x, y);
        ctx.stroke();

        // Bursty halo pulse.
        if n.burst {
            let pulse = 4.0 + 3.0 * ((tick / 14.0).sin() * 0.5 + 0.5);
            ctx.set_stroke_style_str("rgba(255,176,32,0.8)");
            ctx.set_line_width(1.5);
            ctx.begin_path();
            ctx.arc(x, y, size + pulse, 0.0, std::f64::consts::TAU)
                .unwrap_or(());
            ctx.stroke();
        }

        // Node body.
        let fill = if dropped { "#ff5d5d" } else { "#3ddc97" };
        ctx.set_fill_style_str(fill);
        ctx.begin_path();
        ctx.arc(x, y, size, 0.0, std::f64::consts::TAU)
            .unwrap_or(());
        ctx.fill();

        // Label (shortened IP).
        ctx.set_fill_style_str("#7d8ba1");
        ctx.set_font("9px monospace");
        let short = short_ip(&n.ip);
        ctx.fill_text(&short, x, y + size + 10.0).unwrap_or(());
    }
}

fn short_ip(ip: &str) -> String {
    if ip.len() <= 15 {
        ip.to_string()
    } else {
        format!("{}…", &ip[..12])
    }
}
