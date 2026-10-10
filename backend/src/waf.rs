use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use gritshield::http::response::Response;
use gritshield::middleware::{Middleware, MiddlewareResult};
use gritshield::prelude::RequestContext;
use serde_json::json;

use crate::firewall::Firewall;
use crate::netstore::NetStore;
use crate::state::AppState;
use crate::types::NetEvent;

// ---------------------------------------------------------------------------
// API key
// ---------------------------------------------------------------------------

/// Require `X-API-Key` (or `?api_key=`) when `LUX_API_KEY` is configured.
/// `EventSource` cannot send headers, so the query variant must stay open.
pub struct ApiKeyMiddleware {
    expected: Option<String>,
}

impl ApiKeyMiddleware {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            expected: state.api_key.clone(),
        }
    }
}

#[async_trait]
impl Middleware for ApiKeyMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        if let Some(expected) = &self.expected {
            let provided = ctx
                .header("x-api-key")
                .map(ToOwned::to_owned)
                .or_else(|| ctx.query_param("api_key").map(ToOwned::to_owned))
                .unwrap_or_default();

            if provided.is_empty() || provided != *expected {
                return MiddlewareResult::Error(Response::json_unauthorized(&json!({
                    "error": "unauthorized",
                    "detail": "missing or invalid X-API-Key header (or ?api_key= query param)"
                })));
            }
        }
        MiddlewareResult::Next(None)
    }
}

// ---------------------------------------------------------------------------
// Firewall enforcement (HTTP mirror of the kernel drop)
// ---------------------------------------------------------------------------

/// Reject requests whose source IP currently sits in the firewall. In XDP mode
/// those packets are already being dropped at the NIC; this layer keeps HTTP
/// (e.g. proxied clients behind Nginx) consistent with the kernel verdict.
pub struct FirewallMiddleware {
    firewall: Arc<Firewall>,
}

impl FirewallMiddleware {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            firewall: state.firewall.clone(),
        }
    }
}

#[async_trait]
impl Middleware for FirewallMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        let ip = ctx.resolve_client_ip();
        if self.firewall.contains(&ip) {
            MiddlewareResult::Error(Response::json_forbidden(&json!({
                "error": "firewall_blocked",
                "ip": ip,
                "reason": self.firewall.reason(&ip),
                "detail": "source is blocked by the LuxShield firewall"
            })))
        } else {
            MiddlewareResult::Next(None)
        }
    }
}

// ---------------------------------------------------------------------------
// WAF: volumetric burst detector
// ---------------------------------------------------------------------------

type Window = (usize, std::time::Instant);

/// Counts requests per client and, when a burst exceeds the configured limit
/// within the window, writes the offender into the firewall — which, via the
/// kernel bridge, mutates `blocklist_map` so subsequent packets are dropped at
/// the NIC before they ever reach this listener.
pub struct WafMiddleware {
    store: Arc<NetStore>,
    firewall: Arc<Firewall>,
    limit: usize,
    window: Duration,
    ban_secs: u64,
    counters: Arc<Mutex<std::collections::HashMap<String, Window>>>,
}

impl WafMiddleware {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            store: state.store.clone(),
            firewall: state.firewall.clone(),
            limit: state.waf_burst,
            window: Duration::from_secs(1),
            ban_secs: state.waf_ban_secs,
            counters: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait]
impl Middleware for WafMiddleware {
    async fn on_request(&self, ctx: &mut RequestContext) -> MiddlewareResult {
        let ip = ctx.resolve_client_ip();

        let trip = {
            let Ok(mut counters) = self.counters.lock() else {
                return MiddlewareResult::Next(None);
            };
            if counters.len() > 4096 {
                counters.retain(|_, (_, at)| at.elapsed() <= self.window);
            }
            let entry = counters.entry(ip.clone()).or_insert_with(|| (0, std::time::Instant::now()));
            if entry.1.elapsed() > self.window {
                *entry = (0, std::time::Instant::now());
            }
            entry.0 += 1;
            entry.0 > self.limit
        };

        if trip {
            // Ban only on the transition, not on every subsequent request.
            if !self.firewall.contains(&ip) {
                let reason = format!("waf: request burst (>{} req/s)", self.limit);
                let _ = self
                    .firewall
                    .add(&ip, 32, self.ban_secs, &reason, "waf");
                self.store
                    .ingest(&NetEvent::block(&ip, &reason, "waf"))
                    .await;
            }
            let mut res = Response::json_forbidden(&json!({
                "error": "waf_blocked",
                "ip": ip,
                "detail": "momentum treated as volumetric attack; added to firewall"
            }));
            res.headers
                .push(("Retry-After".to_string(), "60".to_string()));
            MiddlewareResult::Error(res)
        } else {
            MiddlewareResult::Next(None)
        }
    }

    async fn on_response(&self, _ctx: &RequestContext, res: &mut Response) {
        if !res
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-LuxShield-Waf"))
        {
            res.headers.push(("X-LuxShield-Waf".to_string(), "pass".to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// Hardening headers
// ---------------------------------------------------------------------------

pub struct HttpSecurityMiddleware;

impl HttpSecurityMiddleware {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Middleware for HttpSecurityMiddleware {
    async fn on_request(&self, _ctx: &mut RequestContext) -> MiddlewareResult {
        MiddlewareResult::Next(None)
    }

    async fn on_response(&self, ctx: &RequestContext, res: &mut Response) {
        for (k, v) in [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store"),
            ("Server", "luxshield-backend"),
        ] {
            if !res.headers.iter().any(|(hk, _)| hk.eq_ignore_ascii_case(k)) {
                res.headers.push((k.to_string(), v.to_string()));
            }
        }
        res.headers.push((
            "X-LuxShield-Response-Time-Ms".to_string(),
            ctx.start_time.elapsed().as_millis().to_string(),
        ));
    }
}