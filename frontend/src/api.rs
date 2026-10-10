//! LuxShield backend API contract.
//!
//! The backend is implemented by a sibling agent; this module is the **single
//! place** the frontend's assumptions about it live. If routes or shapes
//! change, only this file (plus possibly `NetEvent`/`Rule` in `state.rs`)
//! should need touching.
//!
//! Endpoints (see `docs/api.md`; port 8020 via `LUX_PORT`):
//! - `GET /api/v1/network/stream` — SSE, named events packet|drop|spike|block.
//!   `history` replay is **newest-first** (ingest re-sorts chronologically).
//! - `GET /api/v1/network/stats` — aggregate counters
//! - `GET /api/v1/firewall/rules` — `{ count, rules: [RuleInfo] }` where each
//!   rule carries `kernel_synced` (true once in the kernel `blocklist_map`)
//! - `POST /api/v1/firewall/rules` — `{ ip, duration_secs?, reason?, prefix_len? }`
//! - `DELETE /api/v1/firewall/rules?ip=...`
//! - `GET /health` — liveness + kernel bridge status

use serde::Deserialize;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit};

use crate::state::Rule;

/// Backend base URL (dev). When served from the same origin as the API, this
/// can stay empty. Port 8020 by default (`LUX_PORT`, see `docs/api.md`).
pub const BASE_URL: &str = "http://127.0.0.1:8020";

/// Server-Sent Events feed of live packet telemetry.
pub const STREAM_PATH: &str = "/api/v1/network/stream";
/// Aggregate counters for the dashboard.
pub const STATS_PATH: &str = "/api/v1/network/stats";
/// Firewall rules (list + add).
pub const RULES_PATH: &str = "/api/v1/firewall/rules";
/// Liveness + kernel bridge status.
pub const HEALTH_PATH: &str = "/health";

fn with_base(path: &str) -> String {
    if BASE_URL.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", BASE_URL.trim_end_matches('/'), path)
    }
}

/// API key expected by the auth layer (set when `LUX_API_KEY` is set).
///
/// Neither `EventSource` nor plain `fetch` calls here set request headers,
/// so the key travels as a query parameter instead — the backend accepts
/// `?api_key=` as an alternative to the `X-API-Key` header.
pub const API_KEY: &str = "";

/// Append `?api_key=` (or `&api_key=`) when a key is configured.
fn with_auth(url: &str) -> String {
    if API_KEY.is_empty() {
        return url.to_string();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}api_key={API_KEY}")
}

/// Fully-qualified SSE URL including the history replay + auth parameters.
pub fn stream_url() -> String {
    with_auth(&format!("{}?history=100", with_base(STREAM_PATH)))
}

/// Fetch failure with the HTTP status preserved so callers can tell a
/// 401/403 (bad key, or this viewer is WAF/firewall-banned — which the
/// backend returns on *every* endpoint, stream included) from a dead server.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn is_forbidden(&self) -> bool {
        self.status == 401 || self.status == 403
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn debug_js(v: &JsValue) -> String {
    v.as_string().unwrap_or_else(|| format!("{v:?}"))
}

async fn fetch_json(url: &str) -> Result<JsValue, ApiError> {
    let window = web_sys::window().ok_or(ApiError {
        status: 0,
        message: "no window object".to_string(),
    });
    let window = match window {
        Ok(w) => w,
        Err(e) => return Err(e),
    };
    let response = JsFuture::from(window.fetch_with_str(&with_auth(url))).await.map_err(|e| ApiError {
        status: 0,
        message: debug_js(&e),
    })?;
    let response: web_sys::Response = response.dyn_into().map_err(|_| ApiError {
        status: 0,
        message: "fetch resolved to a non-Response".to_string(),
    })?;
    if !response.ok() {
        let status = response.status();
        return Err(ApiError {
            status,
            message: if status == 401 || status == 403 {
                format!("forbidden ({status}): bad key or this viewer is banned — unban via DELETE {RULES_PATH}?ip=…")
            } else {
                format!("GET {url} -> {status}")
            },
        });
    }
    JsFuture::from(response.json().map_err(|e| ApiError {
        status: 0,
        message: debug_js(&e),
    })?)
    .await
    .map_err(|e| ApiError {
        status: 0,
        message: debug_js(&e),
    })
}

/// Backend `/stats` payload (subset we display).
#[derive(Debug, Deserialize)]
pub struct StatsReply {
    #[serde(default)]
    pub pass_total: u32,
    #[serde(default)]
    pub drop_total: u32,
    #[serde(default)]
    pub spike_total: u32,
    #[serde(default)]
    pub block_total: u32,
    #[serde(default)]
    pub bytes_total: u64,
}

/// Backend `/firewall/rules` payload.
#[derive(Debug, Deserialize)]
struct RulesReply {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Backend `/health` payload (subset we display).
#[derive(Debug, Deserialize)]
struct HealthReply {
    #[serde(default)]
    pub ring_source: String,
    #[serde(default)]
    pub kernel: KernelReply,
}

#[derive(Debug, Default, Deserialize)]
struct KernelReply {
    #[serde(default)]
    pub bridge: String,
    #[serde(default)]
    pub attached: bool,
}

pub async fn get_stats() -> Result<StatsReply, ApiError> {
    let v = fetch_json(&with_base(STATS_PATH)).await?;
    serde_wasm_bindgen::from_value(v).map_err(|e| ApiError {
        status: 0,
        message: e.to_string(),
    })
}

pub async fn get_rules() -> Result<Vec<Rule>, ApiError> {
    let v = fetch_json(&with_base(RULES_PATH)).await?;
    let reply: RulesReply = serde_wasm_bindgen::from_value(v).map_err(|e| ApiError {
        status: 0,
        message: e.to_string(),
    })?;
    Ok(reply.rules)
}

pub async fn get_health() -> Result<(String, String, bool), ApiError> {
    let v = fetch_json(&with_base(HEALTH_PATH)).await?;
    let reply: HealthReply = serde_wasm_bindgen::from_value(v).map_err(|e| ApiError {
        status: 0,
        message: e.to_string(),
    })?;
    Ok((reply.ring_source, reply.kernel.bridge, reply.kernel.attached))
}

fn api_err(status: u16, message: String) -> ApiError {
    ApiError { status, message }
}

/// Add a firewall rule. `duration_secs = 0` means permanent.
pub async fn post_rule(ip: &str, duration_secs: u64, reason: &str) -> Result<(), ApiError> {
    let body = serde_json::json!({
        "ip": ip,
        "duration_secs": duration_secs,
        "reason": reason,
        "prefix_len": 32,
    })
    .to_string();

    let headers = web_sys::Headers::new().map_err(|e| api_err(0, debug_js(&e)))?;
    headers
        .append("content-type", "application/json")
        .map_err(|e| api_err(0, debug_js(&e)))?;

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&body));

    let request = Request::new_with_str_and_init(&with_auth(&with_base(RULES_PATH)), &init)
        .map_err(|e| api_err(0, debug_js(&e)))?;

    let window = web_sys::window().ok_or(api_err(0, "no window object".to_string()))?;
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| api_err(0, debug_js(&e)))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| api_err(0, "rule POST resolved to a non-Response".to_string()))?;

    if response.ok() {
        Ok(())
    } else {
        let status = response.status();
        let detail = JsFuture::from(
            response
                .text()
                .map_err(|e| api_err(0, debug_js(&e)))?,
        )
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        Err(api_err(
            status,
            if status == 401 || status == 403 {
                format!("forbidden ({status}): bad key or this viewer is banned")
            } else {
                format!("rule POST failed: {detail}")
            },
        ))
    }
}

/// Remove a firewall rule by IP.
pub async fn delete_rule(ip: &str) -> Result<bool, ApiError> {
    let window = web_sys::window().ok_or(api_err(0, "no window object".to_string()))?;
    let url = with_auth(&format!("{}?ip={}", with_base(RULES_PATH), ip));
    let init = RequestInit::new();
    init.set_method("DELETE");
    let request =
        Request::new_with_str_and_init(&url, &init).map_err(|e| api_err(0, debug_js(&e)))?;
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| api_err(0, debug_js(&e)))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| api_err(0, "rule DELETE resolved to a non-Response".to_string()))?;
    if response.ok() {
        Ok(true)
    } else {
        Err(api_err(
            response.status(),
            format!("rule DELETE failed: {}", response.status()),
        ))
    }
}
