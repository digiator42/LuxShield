use std::sync::Arc;

use crate::firewall::Firewall;
use crate::netstore::NetStore;

/// Application-wide shared state, registered once into the GritShield DI
/// container and resolved on demand by handlers, middlewares and MCP tools.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<NetStore>,
    pub firewall: Arc<Firewall>,
    /// When `Some`, requests must present `X-API-Key` (or `?api_key=`).
    pub api_key: Option<String>,
    /// Where packet records come from: `sim` or `xdp`.
    pub ring_source: String,
    /// Per-IP request burst that trips the WAF.
    pub waf_burst: usize,
    /// WAF ban duration in seconds (0 = permanent).
    pub waf_ban_secs: u64,
}

/// Resolve the registered application state from the global container.
pub fn resolve() -> Arc<AppState> {
    use gritshield::core::ioc::CONTEXT;
    CONTEXT
        .resolve::<AppState>()
        .expect("AppState was not registered; this must be the first boot step")
}