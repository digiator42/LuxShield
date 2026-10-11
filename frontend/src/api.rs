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
//!
//! Transport is veloasm's `request()` builder throughout — no hand-rolled
//! `RequestInit` here.

use serde::Deserialize;

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

/// Base builder for this backend: absolute URL plus the auth query param.
fn authenticated(url: String) -> veloasm::RequestBuilder {
    let req = veloasm::request(&url);
    if API_KEY.is_empty() {
        req
    } else {
        req.query("api_key", API_KEY)
    }
}

/// Fully-qualified SSE URL including the history replay + auth parameters.
pub fn stream_url() -> String {
    authenticated(with_base(STREAM_PATH))
        .query("history", "100")
        .url()
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

impl From<veloasm::FetchError> for ApiError {
    fn from(e: veloasm::FetchError) -> Self {
        match e {
            veloasm::FetchError::Status { code, .. } if code == 401 || code == 403 => ApiError {
                status: code,
                message: format!("forbidden ({code}): bad key or this viewer is banned — unban via DELETE {RULES_PATH}?ip=…"),
            },
            veloasm::FetchError::Status { code, reason } => ApiError {
                status: code,
                message: format!("request failed ({code} {reason})"),
            },
            veloasm::FetchError::Network(msg) => ApiError {
                status: 0,
                message: msg,
            },
            veloasm::FetchError::Decode(msg) => ApiError {
                status: 0,
                message: msg,
            },
        }
    }
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
    Ok(veloasm::fetch_json(&authenticated(with_base(STATS_PATH)).url()).await?)
}

pub async fn get_rules() -> Result<Vec<Rule>, ApiError> {
    let reply: RulesReply =
        veloasm::fetch_json(&authenticated(with_base(RULES_PATH)).url()).await?;
    Ok(reply.rules)
}

pub async fn get_health() -> Result<(String, String, bool), ApiError> {
    let reply: HealthReply =
        veloasm::fetch_json(&authenticated(with_base(HEALTH_PATH)).url()).await?;
    Ok((reply.ring_source, reply.kernel.bridge, reply.kernel.attached))
}

/// Add a firewall rule. `duration_secs = 0` means permanent.
pub async fn post_rule(ip: &str, duration_secs: u64, reason: &str) -> Result<(), ApiError> {
    let body = serde_json::json!({
        "ip": ip,
        "duration_secs": duration_secs,
        "reason": reason,
        "prefix_len": 32,
    });
    authenticated(with_base(RULES_PATH))
        .method("POST")
        .json_body(&body)?
        .send()
        .await?;
    Ok(())
}

/// Remove a firewall rule by IP.
pub async fn delete_rule(ip: &str) -> Result<bool, ApiError> {
    authenticated(format!("{}?ip={}", with_base(RULES_PATH), ip))
        .method("DELETE")
        .send()
        .await?;
    Ok(true)
}

