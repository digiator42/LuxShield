use gritshield::http::SseStream;
use gritshield::prelude::{RequestContext, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state;
use crate::types::NetEvent;

/// `GET /health` — liveness plus a peek at the pipeline and firewall.
pub async fn health(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    let s = st.store.stats().await;
    let (kernel_name, kernel_attached) = st.firewall.kernel();

    Response::json_ok(&json!({
        "service": "luxshield-backend",
        "status": "ok",
        "ring_source": st.ring_source,
        "kernel": { "bridge": kernel_name, "attached": kernel_attached },
        "buffers": {
            "history_count": s.history_count,
            "history_capacity": crate::netstore::HISTORY_CAPACITY,
            "live_streams": s.live_streams,
            "attached_total": s.attached_total,
        },
        "firewall": {
            "entries": st.firewall.entry_count(),
            "map_ops": st.firewall.map_ops(),
        }
    }))
}

/// `GET /api/v1/network/stream` — Server-Sent Events live packet tail.
///
/// The most recent `history` records (default 50) are replayed first, then live
/// records follow under an event name equal to the record `kind`:
///
/// ```text
/// event: packet
/// data: {"ts_ms":1720524000000,"kind":"packet","ip":"10.0.0.12","port":443,
///        "protocol":"tcp","bytes":742,"action":"pass","source":"sim"}
///
/// event: drop
/// data: {"ts_ms":...,"kind":"drop","ip":"203.0.113.66","action":"drop","reason":"...","source":"xdp"}
///
/// event: spike
/// data: {"ts_ms":...,"kind":"spike","bps":672000,"pps":60,"reason":"bandwidth threshold exceeded"}
///
/// event: block
/// data: {"ts_ms":...,"kind":"block","ip":"203.0.113.66","reason":"waf: request burst","source":"waf"}
/// ```
///
/// Query params: `history` (default 50, max 1000), `since` (epoch-ms), `api_key`.
pub async fn stream(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let limit = ctx
        .query_param("history")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(1000);
    let since = ctx.query_param("since").and_then(|v| v.parse::<f64>().ok());

    let history = st.store.history(limit).await;

    let mut sse = SseStream::new();
    for ev in history {
        if let Some(min_ts) = since {
            if ev.ts_ms < min_ts {
                continue;
            }
        }
        if let Ok(payload) = serde_json::to_string(&ev) {
            sse.queue_initial(&ev.kind, &payload);
        }
    }

    st.store.attach(sse.clone()).await;
    Response::sse(sse)
}

/// `GET /api/v1/network/stats` — aggregate counters for the dashboard/agents.
pub async fn stats(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    let s = st.store.stats().await;
    let (kernel_name, kernel_attached) = st.firewall.kernel();

    Response::json_ok(&json!({
        "packets_total": s.pass_total + s.drop_total,
        "pass_total": s.pass_total,
        "drop_total": s.drop_total,
        "spike_total": s.spike_total,
        "block_total": s.block_total,
        "bytes_total": s.bytes_total,
        "dropped_bytes_total": s.dropped_bytes_total,
        "live_streams": s.live_streams,
        "history_count": s.history_count,
        "kernel": { "bridge": kernel_name, "attached": kernel_attached },
        "firewall": {
            "entries": st.firewall.entry_count(),
            "map_ops": st.firewall.map_ops(),
            "kernel_ops": st.firewall.bridge_ops(),
        }
    }))
}

/// `GET /api/v1/firewall/rules` — list active (non-expired) rules.
pub async fn list_rules(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    let rules = st.firewall.list();
    Response::json_ok(&json!({ "count": rules.len(), "rules": rules }))
}

#[derive(Debug, Deserialize)]
pub struct RuleInput {
    pub ip: String,
    /// 0 or omitted = permanent.
    #[serde(default)]
    pub duration_secs: u64,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_prefix")]
    pub prefix_len: u8,
}

fn default_prefix() -> u8 {
    32
}

/// `POST /api/v1/firewall/rules` — add a rule and push it into the kernel map.
///
/// ```json
/// { "ip": "203.0.113.66", "duration_secs": 120, "reason": "manual ban" }
/// ```
pub async fn post_rule(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({"error": "invalid_json"})),
    };
    let input: RuleInput = match serde_json::from_value(body) {
        Ok(i) => i,
        Err(e) => {
            return Response::json_bad_request(&json!({
                "error": "invalid_rule",
                "detail": e.to_string()
            }))
        }
    };

    let reason = if input.reason.is_empty() {
        "manual firewall rule".to_string()
    } else {
        input.reason.clone()
    };

    match st
        .firewall
        .add(&input.ip, input.prefix_len, input.duration_secs, &reason, "api")
    {
        Ok(rule) => {
            st.store
                .ingest(&NetEvent::block(&rule.ip, &rule.reason, "api"))
                .await;
            Response::json_created(&json!({ "rule": rule }))
        }
        Err(e) => Response::json_bad_request(&json!({ "error": "invalid_rule", "detail": e })),
    }
}

/// `DELETE /api/v1/firewall/rules?ip=...` — remove a rule.
pub async fn delete_rule(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let ip = match ctx.query_param("ip") {
        Some(ip) if !ip.is_empty() => ip.to_string(),
        _ => return Response::json_bad_request(&json!({"error": "missing_ip"})),
    };

    match st.firewall.remove(&ip) {
        Ok(removed) => Response::json_ok(&json!({ "removed": removed, "ip": ip })),
        Err(e) => Response::json_internal_error_msg(format!("remove_failed: {e}")),
    }
}