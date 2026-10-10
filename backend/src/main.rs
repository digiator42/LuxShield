mod api;
mod firewall;
mod netstore;
mod state;
mod types;
mod waf;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod kernel;
#[cfg(feature = "mcp")]
mod mcp;
mod source;

use std::sync::Arc;

use gritshield::core::logger::LogLevel;
use gritshield::prelude::*;

use crate::firewall::{Firewall, NullBridge};
use crate::netstore::NetStore;
use crate::state::AppState;
use crate::waf::{ApiKeyMiddleware, FirewallMiddleware, HttpSecurityMiddleware, WafMiddleware};

#[tokio::main]
async fn main() {
    let ring_source = {
        let requested = std::env::var("LUX_RING").unwrap_or_else(|_| "sim".to_string());
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        if requested == "ebpf" {
            "ebpf"
        } else {
            "sim"
        }
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        if requested == "ebpf" {
            eprintln!("[luxshield] LUX_RING=ebpf needs `--features ebpf` on Linux; using simulator");
        }
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        {
            "sim"
        }
    };

    let store = Arc::new(NetStore::new());
    let firewall = Arc::new(Firewall::new(Arc::new(NullBridge)));

    let api_key = std::env::var("LUX_API_KEY").ok().filter(|k| !k.is_empty());
    let waf_burst: usize = env_or("LUX_WAF_BURST", 60);
    let waf_ban_secs: u64 = env_or("LUX_WAF_BAN_SECS", 60);

    let app_state = Arc::new(AppState {
        store: store.clone(),
        firewall: firewall.clone(),
        api_key,
        ring_source: ring_source.to_string(),
        waf_burst,
        waf_ban_secs,
    });
    gritshield::core::ioc::AutoWire::component((*app_state).clone());

    // Packet producer: XDP ring pump (Linux) or the simulator.
    tokio::spawn(source::run(store.clone(), firewall.clone()));

    // Request phase runs in mount order: CORS short-circuits OPTIONS first,
    // then auth, then firewall enforcement, then the WAF burst detector.
    let router = Router::new()
        .mount_logger(LogLevel::Debug)
        .add_middleware(gritshield::middleware::CorsMiddleware::new(vec![
            "*".to_string(),
        ]))
        .add_middleware(ApiKeyMiddleware::new(app_state.clone()))
        .add_middleware(FirewallMiddleware::new(app_state.clone()))
        .add_middleware(WafMiddleware::new(app_state.clone()))
        .add_middleware(HttpSecurityMiddleware::new())
        .route(("/health", HttpMethod::GET, api::health))
        .route(("/api/v1/network/stream", HttpMethod::GET, api::stream))
        .route(("/api/v1/network/stats", HttpMethod::GET, api::stats))
        .route(("/api/v1/firewall/rules", HttpMethod::GET, api::list_rules))
        .route(("/api/v1/firewall/rules", HttpMethod::POST, api::post_rule))
        .route(("/api/v1/firewall/rules", HttpMethod::DELETE, api::delete_rule));

    let host = std::env::var("LUX_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("LUX_PORT").unwrap_or_else(|_| "8020".to_string());

    println!("[luxshield] backend listening on http://{host}:{port}");
    println!("[luxshield] packet source: {ring_source}");
    println!("[luxshield] WAF: >{waf_burst} req/s bans the client for {waf_ban_secs}s");
    println!(
        "[luxshield] MCP surface mounted automatically at http://{host}:{port}/mcp (MCP_HTTP_PREFIX to relocate)"
    );

    ignite(&host, &port, router).await;
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}